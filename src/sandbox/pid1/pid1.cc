#include "../communication/supervisor_pid1_tracee.hh"
#include "../tracee/tracee.hh"
#include "pid1.hh"

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <ctime>
#include <fcntl.h>
#include <optional>
#include <poll.h>
#include <sched.h>
#include <simlib/errmsg.hh>
#include <simlib/file_contents.hh>
#include <simlib/file_path.hh>
#include <simlib/noexcept_concat.hh>
#include <simlib/overloaded.hh>
#include <simlib/string_view.hh>
#include <simlib/syscalls.hh>
#include <simlib/timespec_arithmetic.hh>
#include <simlib/ubsan.hh>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <variant>

namespace sms = sandbox::communication::supervisor_pid1_tracee;

namespace {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
volatile sms::SharedMemState* shared_mem_state;

template <class... Args>
[[noreturn]] void die_with_msg(Args&&... msg) noexcept {
    sms::write_result_error(shared_mem_state, "pid1: ", std::forward<decltype(msg)>(msg)...);
    _exit(1);
}

template <class... Args>
[[noreturn]] void die_with_error(Args&&... msg) noexcept {
    die_with_msg(std::forward<decltype(msg)>(msg)..., errmsg());
}

void set_process_name() noexcept {
    if (prctl(PR_SET_NAME, "pid1", 0, 0, 0)) {
        die_with_error("prctl(SET_NAME)");
    }
}

void setup_kill_on_supervisor_death(int supervisor_pidfd) noexcept {
    // Make kernel send us SIGKILL when the parent process (= supervisor process) dies
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)) {
        die_with_error("prctl(PR_SET_PDEATHSIG)");
    }
    // Check if the supervisor is not already dead - it might happened just before prctl(). We
    // cannot use getppid() because it returns 0 as we are in a new PID namespace, so we use
    // poll() on supervisor's pidfd
    pollfd pfd = {
        .fd = supervisor_pidfd,
        .events = POLLIN,
        .revents = 0,
    };
    if (poll(&pfd, 1, 0) == 1) {
        die_with_msg("supervisor died");
    }
    // Close supervisor_pidfd to limit attack surface as it may be used to send signals to the
    // supervisor
    if (close(supervisor_pidfd)) {
        die_with_error("close()");
    }
}

void setup_session_and_process_group() noexcept {
    // Exclude pid1 process from the parent's process group and session
    if (setsid() < 0) {
        die_with_error("setsid()");
    }
}

void write_file(FilePath file_path, StringView data) noexcept {
    auto fd = open(file_path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd == -1) {
        die_with_error("open(", file_path, ")");
    }
    if (write_all(fd, data) != data.size()) {
        die_with_error("write(", file_path, ")");
    }
    if (close(fd)) {
        die_with_error("close()");
    }
}

void setup_user_namespace(const sandbox::pid1::Args::LinuxNamespaces::User::Pid1& user_ns
) noexcept {
    write_file(
        "/proc/self/uid_map",
        from_unsafe{noexcept_concat(user_ns.inside_uid, ' ', user_ns.outside_uid, " 1")}
    );
    write_file("/proc/self/setgroups", "deny");
    write_file(
        "/proc/self/gid_map",
        from_unsafe{noexcept_concat(user_ns.inside_gid, ' ', user_ns.outside_gid, " 1")}
    );
}

void setup_mount_namespace(const sandbox::pid1::Args::LinuxNamespaces::Mount& mount_ns) noexcept {
    if (chdir("/")) {
        die_with_error("chdir(\"/\")");
    }
    for (const auto& oper : mount_ns.operations) {
        using Mount = sandbox::pid1::Args::LinuxNamespaces::Mount;
        std::visit(
            overloaded{
                [&](const Mount::MountTmpfs& mount_tmpfs) {
                    auto flags = MS_NOSUID | MS_SILENT;
                    if (mount_tmpfs.read_only) {
                        flags |= MS_RDONLY;
                    }
                    if (mount_tmpfs.no_exec) {
                        flags |= MS_NOEXEC;
                    }
                    auto options_str = [&]() noexcept {
                        auto size = [&]() noexcept {
                            using T =
                                decltype(mount_tmpfs.max_total_size_of_files_in_bytes)::value_type;
                            if (!mount_tmpfs.max_total_size_of_files_in_bytes) {
                                return T{0}; // no limit
                            }
                            auto x = *mount_tmpfs.max_total_size_of_files_in_bytes;
                            return x > 0 ? x : T{1}; // 1 == lowest possible limit
                        }();
                        auto nr_inodes = [&]() noexcept {
                            using T =
                                decltype(mount_tmpfs.max_total_size_of_files_in_bytes)::value_type;
                            if (!mount_tmpfs.inode_limit) {
                                return T{0}; // no limit
                            }
                            // Adjust limit because root dir counts as an inode
                            return *mount_tmpfs.inode_limit +
                                1; // overflow is fine, as 0 == no limit
                        }();
                        uint8_t mode_user = (mount_tmpfs.root_dir_mode >> 6) & 7;
                        uint8_t mode_group = (mount_tmpfs.root_dir_mode >> 3) & 7;
                        uint8_t mode_other = mount_tmpfs.root_dir_mode & 7;
                        return noexcept_concat(
                            "size=",
                            size,
                            ",nr_inodes=",
                            nr_inodes,
                            ",mode=0",
                            mode_user,
                            mode_group,
                            mode_other
                        );
                    }();
                    if (mount(
                            nullptr, mount_tmpfs.path.c_str(), "tmpfs", flags, options_str.c_str()
                        )) {
                        die_with_error("mount(tmpfs at \"", mount_tmpfs.path, "\")");
                    }
                },
                [&](const Mount::MountProc& mount_proc) {
                    auto flags = MS_NOSUID | MS_SILENT;
                    if (mount_proc.read_only) {
                        flags |= MS_RDONLY;
                    }
                    if (mount_proc.no_exec) {
                        flags |= MS_NOEXEC;
                    }
                    if (mount(nullptr, mount_proc.path.c_str(), "proc", flags, nullptr)) {
                        die_with_error("mount(proc at \"", mount_proc.path, "\")");
                    }
                },
                [&](const Mount::BindMount& bind_mount) {
                    int mount_fd = open_tree(
                        AT_FDCWD,
                        bind_mount.source.c_str(),
                        OPEN_TREE_CLOEXEC | OPEN_TREE_CLONE |
                            (bind_mount.recursive ? AT_RECURSIVE : 0)
                    );
                    if (mount_fd < 0) {
                        die_with_error("open_tree(\"", bind_mount.source, "\")");
                    }

                    mount_attr mattr = {};
                    mattr.attr_set = MOUNT_ATTR_NOSUID;
                    if (bind_mount.read_only) {
                        mattr.attr_set |= MOUNT_ATTR_RDONLY;
                    }
                    if (bind_mount.no_exec) {
                        mattr.attr_set |= MOUNT_ATTR_NOEXEC;
                    }
                    if (mount_setattr(
                            mount_fd,
                            "",
                            AT_EMPTY_PATH | (bind_mount.recursive ? AT_RECURSIVE : 0),
                            &mattr,
                            sizeof(mattr)
                        ))
                    {
                        die_with_error("mount_setattr()");
                    }
                    if (move_mount(
                            mount_fd, "", AT_FDCWD, bind_mount.dest.c_str(), MOVE_MOUNT_F_EMPTY_PATH
                        ))
                    {
                        die_with_error("move_mount(dest: \"", bind_mount.dest, "\")");
                    }
                    if (close(mount_fd)) {
                        die_with_error("close()");
                    }
                },
                [&](const Mount::CreateDir& create_dir) {
                    if (mkdir(create_dir.path.c_str(), create_dir.mode)) {
                        die_with_error("mkdir(\"", create_dir.path, "\")");
                    }
                },
                [&](const Mount::CreateFile& create_file) {
                    int fd = open(
                        create_file.path.c_str(), O_CREAT | O_EXCL | O_CLOEXEC, create_file.mode
                    );
                    if (fd < 0) {
                        die_with_error("open(\"", create_file.path, "\", O_CREAT | O_EXCL)");
                    }
                    if (close(fd)) {
                        die_with_error("close()");
                    }
                },
            },
            oper
        );
    }

    if (mount_ns.new_root_mount_path) {
        if (chdir(mount_ns.new_root_mount_path->c_str())) {
            die_with_error("chdir(new_root_mount_path)");
        }
        // This has to be done within the same user namespace that performed the mount. After
        // the following clone3 with CLONE_NEWUSER | CLONE_NEWNS the whole mount tree becomes
        // locked in tracee and we really want it for security i.e. the user will not be able to
        // disintegrate part of the mount tree (but they may umount the entire mount tree).
        if (syscalls::pivot_root(".", ".")) {
            die_with_error(R"(pivot_root(".", "."))");
        }
        // Unmount the old root (also, it is needed for clone3 with CLONE_NEWUSER to succeed)
        if (umount2(".", MNT_DETACH)) {
            die_with_error(R"(umount2("."))");
        }
    }
}

void drop_all_capabilities_and_prevent_gaining_any_of_them() noexcept {
    cap_t caps = cap_init(); // all capabilities are cleared
    if (caps == nullptr) {
        die_with_error("caps_init()");
    }
    if (cap_set_proc(caps)) {
        die_with_error("cap_set_proc()");
    }
    if (cap_free(caps)) {
        die_with_error("cap_free()");
    }
}

struct SignalHandlersState {
    timer_t real_time_timer_id;
    timespec real_time_limit;
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
volatile const SignalHandlersState* signal_handlers_state_ptr = nullptr;

void sigusr1_handler_to_kill_the_tracee(int /*sig*/, siginfo_t* si, void* /*ucontext*/) noexcept {
    if (si->si_code == SI_TIMER) {
        int saved_errno = errno;
        // Kill the tracee
        int tracee_cgroup_kill_fd = si->si_int;
        if (write(tracee_cgroup_kill_fd, "1", 1) < 0) {
            die_with_error("write()");
        }
        // Restore errno
        errno = saved_errno;
    }
}

void sigusr2_handler_to_start_timer(int /*sig*/, siginfo_t* si, void* /*ucontext*/) noexcept {
    if (si->si_code == SI_USER && si->si_pid > 0) { // signal came from the tracee process
        int saved_errno = errno;
        // Start the timer
        itimerspec its = {
            .it_interval = {.tv_sec = 0, .tv_nsec = 0},
            .it_value =
                {
                    .tv_sec = signal_handlers_state_ptr->real_time_limit.tv_sec,
                    .tv_nsec = signal_handlers_state_ptr->real_time_limit.tv_nsec,
                },
        };
        if (its.it_value == timespec{.tv_sec = 0, .tv_nsec = 0}) {
            // it_value == 0 disables the timer, but the meaning of time limit == 0 is to provide
            // no time for tracee, so we use the minimal viable time limit value
            its.it_value = {.tv_sec = 0, .tv_nsec = 1};
        }
        if (timer_settime(signal_handlers_state_ptr->real_time_timer_id, 0, &its, nullptr)) {
            die_with_error("timer_settime()");
        }
        // Disable this signal handler
        struct sigaction sa = {};
        sa.sa_handler = SIG_IGN;
        sa.sa_flags = SA_RESTART;
        if (sigaction(SIGUSR2, &sa, nullptr)) {
            die_with_error("sigaction()");
        }
        // Restore errno
        errno = saved_errno;
    }
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
SignalHandlersState signal_handlers_state;

void install_signal_handlers_for_time_limit(
    int tracee_cgroup_kill_fd, std::optional<timespec> real_time_limit
) noexcept {
    if (!real_time_limit) {
        // SIGUSR2 from tracee will be ignored because this is the process with PID = 1 in the
        // current pid namespace
        return;
    }
    // Create the timer
    sigevent sev = {};
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGUSR1;
    sev.sigev_value.sival_int = tracee_cgroup_kill_fd;
    timer_t timer_id;
    if (timer_create(CLOCK_MONOTONIC, &sev, &timer_id)) {
        die_with_error("timer_create()");
    }

    signal_handlers_state = {
        .real_time_timer_id = timer_id,
        .real_time_limit = *real_time_limit,
    };
    signal_handlers_state_ptr = &signal_handlers_state;

    // Install signal handler for SIGUSR1
    struct sigaction sa = {};
    sa.sa_sigaction = &sigusr1_handler_to_kill_the_tracee;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    if (sigaction(SIGUSR1, &sa, nullptr)) {
        die_with_error("sigaction()");
    }
    // Install signal handler for SIGUSR2
    sa = {};
    sa.sa_sigaction = &sigusr2_handler_to_start_timer;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    if (sigaction(SIGUSR2, &sa, nullptr)) {
        die_with_error("sigaction()");
    }
}

template <size_t N>
void close_all_non_std_file_descriptors_except(int (&&surviving_fds)[N]) noexcept {
    static_assert(N > 0);
    std::sort(std::begin(surviving_fds), std::end(surviving_fds));
    auto prev_fd = STDERR_FILENO;
    for (auto fd : surviving_fds) {
        if (prev_fd + 1 < fd && close_range(prev_fd + 1, fd - 1, 0)) {
            die_with_error("close_range()");
        }
        prev_fd = fd;
    }
    // Close all remaining fds
    if (close_range(prev_fd + 1, ~0U, 0)) {
        die_with_error("close_range()");
    }
}

void harden_against_potential_compromise() noexcept {
    // Cut access to cgroups other than ours
    unshare(CLONE_NEWCGROUP);

    // TODO: install seccomp filters
}

timespec get_current_time() noexcept {
    timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts)) {
        die_with_error("clock_gettime()");
    }
    return ts;
}

} // namespace

namespace sandbox::pid1 {

[[noreturn]] void main(Args args) noexcept {
    shared_mem_state = args.shared_mem_state;

    set_process_name();
    setup_kill_on_supervisor_death(args.supervisor_pidfd);
    setup_session_and_process_group();
    setup_user_namespace(args.linux_namespaces.user.pid1);
    int proc_dirfd = open("/proc", O_RDONLY | O_CLOEXEC);
    setup_mount_namespace(args.linux_namespaces.mount);
    drop_all_capabilities_and_prevent_gaining_any_of_them();
    install_signal_handlers_for_time_limit(args.tracee_cgroup_kill_fd, args.time_limit);

    if (UNDEFINED_SANITIZER) {
        auto ignore_signal = [&](int sig) noexcept {
            struct sigaction sa = {};
            sa.sa_handler = SIG_IGN;
            if (sigemptyset(&sa.sa_mask)) {
                die_with_error("sigemptyset()");
            }
            sa.sa_flags = 0;
            if (sigaction(sig, &sa, nullptr)) {
                die_with_error("sigaction()");
            }
        };
        // Undefined sanitizer installs signal handlers for these signals and this leaves pid1
        // process prone to being killed by these signals
        ignore_signal(SIGBUS);
        ignore_signal(SIGFPE);
        ignore_signal(SIGSEGV);
    }

    clone_args cl_args = {};
    // CLONE_NEWUSER | CLONE_NEWNS are needed to lock the mount tree
    cl_args.flags = CLONE_NEWCGROUP | CLONE_INTO_CGROUP | CLONE_NEWUSER | CLONE_NEWNS;
    cl_args.exit_signal = SIGCHLD;
    cl_args.cgroup = static_cast<uint64_t>(args.tracee_cgroup_fd);

    auto tracee_pid = syscalls::clone3(&cl_args);
    if (tracee_pid == -1) {
        die_with_error("clone3()");
    }
    if (tracee_pid == 0) {
        tracee::main({
            .shared_mem_state = args.shared_mem_state,
            .executable_fd = args.executable_fd,
            .stdin_fd = args.stdin_fd,
            .stdout_fd = args.stdout_fd,
            .stderr_fd = args.stderr_fd,
            .argv = std::move(args.argv),
            .env = std::move(args.env),
            .proc_dirfd = proc_dirfd,
            .tracee_cgroup_cpu_stat_fd = args.tracee_cgroup_cpu_stat_fd,
            .linux_namespaces =
                {
                    .user =
                        {
                            .outside_uid = args.linux_namespaces.user.tracee.outside_uid,
                            .inside_uid = args.linux_namespaces.user.tracee.inside_uid,
                            .outside_gid = args.linux_namespaces.user.tracee.outside_gid,
                            .inside_gid = args.linux_namespaces.user.tracee.inside_gid,
                        },
                },
            .prlimit = args.prlimit,
        });
    }

    close_all_non_std_file_descriptors_except({args.tracee_cgroup_kill_fd});
    harden_against_potential_compromise();

    timespec waitid_time;
    siginfo_t si;
    for (;;) {
        if (syscalls::waitid(P_ALL, 0, &si, __WALL | WEXITED, nullptr)) {
            if (errno == ECHILD) {
                break;
            }
            die_with_error("waitid()");
        }
        waitid_time = get_current_time();
        if (si.si_pid == tracee_pid) {
            // Remaining processes will be killed on pid1's death
            break;
        }
    }

    // Check if tracee died prematurely with an error
    if (sms::is<sms::result::Error>(args.shared_mem_state)) {
        // Propagate error
        _exit(1); // error is already written by tracee
    }

    sms::write(args.shared_mem_state->tracee_waitid_time, waitid_time);
    sms::write_result_ok(
        args.shared_mem_state,
        {
            .code = si.si_code,
            .status = si.si_status,
        }
    );

    _exit(0);
}

} // namespace sandbox::pid1
