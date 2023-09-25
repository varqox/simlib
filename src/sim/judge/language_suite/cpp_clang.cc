#include <optional>
#include <simlib/file_path.hh>
#include <simlib/merge.hh>
#include <simlib/sandbox/sandbox.hh>
#include <simlib/sandbox/seccomp/bpf_builder.hh>
#include <simlib/sim/judge/language_suite/cpp_clang.hh>
#include <simlib/sim/judge/language_suite/fully_compiled_language.hh>
#include <simlib/slice.hh>
#include <string_view>
#include <sys/ioctl.h>
#include <vector>

using MountTmpfs = sandbox::RequestOptions::LinuxNamespaces::Mount::MountTmpfs;
using BindMount = sandbox::RequestOptions::LinuxNamespaces::Mount::BindMount;
using CreateDir = sandbox::RequestOptions::LinuxNamespaces::Mount::CreateDir;
using CreateFile = sandbox::RequestOptions::LinuxNamespaces::Mount::CreateFile;

namespace sim::judge::language_suite {

Cpp_Clang::Cpp_Clang(Standard standard)
: FullyCompiledLanguage{"/usr/bin/clang++", [] {
    auto bpf = sandbox::seccomp::BpfBuilder{};
    bpf.allow_syscall(SCMP_SYS(access));
    bpf.allow_syscall(SCMP_SYS(arch_prctl));
    bpf.allow_syscall(SCMP_SYS(brk));
    bpf.allow_syscall(SCMP_SYS(chmod));
    bpf.allow_syscall(SCMP_SYS(clone3));
    bpf.allow_syscall(SCMP_SYS(close));
    bpf.allow_syscall(SCMP_SYS(execve));
    bpf.allow_syscall(SCMP_SYS(execveat));
    bpf.allow_syscall(SCMP_SYS(exit_group));
    bpf.allow_syscall(SCMP_SYS(faccessat2));
    bpf.allow_syscall(SCMP_SYS(fcntl));
    bpf.allow_syscall(SCMP_SYS(futex));
    bpf.allow_syscall(SCMP_SYS(getcwd));
    bpf.allow_syscall(SCMP_SYS(getdents64));
    bpf.allow_syscall(SCMP_SYS(getrandom));
    bpf.allow_syscall(SCMP_SYS(ioctl), sandbox::seccomp::ARG1_EQ{TCGETS});
    bpf.allow_syscall(SCMP_SYS(kill));
    bpf.allow_syscall(SCMP_SYS(lseek));
    bpf.allow_syscall(SCMP_SYS(mmap));
    bpf.allow_syscall(SCMP_SYS(mprotect));
    bpf.allow_syscall(SCMP_SYS(mremap));
    bpf.allow_syscall(SCMP_SYS(munmap));
    bpf.allow_syscall(SCMP_SYS(newfstatat));
    bpf.allow_syscall(SCMP_SYS(openat));
    bpf.allow_syscall(SCMP_SYS(pread64));
    bpf.allow_syscall(SCMP_SYS(prlimit64));
    bpf.allow_syscall(SCMP_SYS(read));
    bpf.allow_syscall(SCMP_SYS(readlink));
    bpf.allow_syscall(SCMP_SYS(rename));
    bpf.allow_syscall(SCMP_SYS(rseq));
    bpf.allow_syscall(SCMP_SYS(rt_sigaction));
    bpf.allow_syscall(SCMP_SYS(rt_sigprocmask));
    bpf.allow_syscall(SCMP_SYS(sched_yield));
    bpf.allow_syscall(SCMP_SYS(set_robust_list));
    bpf.allow_syscall(SCMP_SYS(set_tid_address));
    bpf.allow_syscall(SCMP_SYS(sigaltstack));
    bpf.allow_syscall(SCMP_SYS(umask));
    bpf.allow_syscall(SCMP_SYS(unlink));
    bpf.allow_syscall(SCMP_SYS(wait4));
    bpf.allow_syscall(SCMP_SYS(write));
    bpf.err_syscall(EPERM, SCMP_SYS(getrusage));
    bpf.err_syscall(EPERM, SCMP_SYS(sysinfo));
    return bpf.export_to_fd();
}()}
, std_flag([&] {
    switch (standard) {
    case Standard::Cpp11: return "-std=c++11";
    case Standard::Cpp14: return "-std=c++14";
    case Standard::Cpp17: return "-std=c++17";
    case Standard::Cpp20: return "-std=c++20";
    case Standard::Cpp23: return "-std=c++23";
    case Standard::Gnupp11: return "-std=gnu++11";
    case Standard::Gnupp14: return "-std=gnu++14";
    case Standard::Gnupp17: return "-std=gnu++17";
    case Standard::Gnupp20: return "-std=gnu++20";
    case Standard::Gnupp23: return "-std=gnu++23";
    }
    __builtin_unreachable();
}()) {}

sandbox::Result Cpp_Clang::run_compiler(
    Slice<std::string_view> extra_args,
    std::optional<int> compilation_errors_fd,
    Slice<sandbox::RequestOptions::LinuxNamespaces::Mount::Operation> mount_ops,
    CompileOptions options
) {
    return sc.await_result(
        sc.send_request(
            compiler_executable_fd,
            merge(std::vector<std::string_view>{"clang++", std_flag, "-O2", "-static"}, extra_args),
            {
                .stdout_fd = compilation_errors_fd,
                .stderr_fd = compilation_errors_fd,
                .env = {{"PATH=/usr/bin"}},
                .linux_namespaces =
                    {
                        .user =
                            {
                                .inside_uid = 1000,
                                .inside_gid = 1000,
                            },
                        .mount =
                            {
                                .operations =
                                    merge(
                                        std::vector<sandbox::RequestOptions::LinuxNamespaces::
                                                        Mount::Operation>{
                                            MountTmpfs{
                                                .path = "/",
                                                .max_total_size_of_files_in_bytes =
                                                    options.max_file_size_in_bytes,
                                                .inode_limit = 32,
                                                .read_only = false,
                                            },
                                            CreateDir{.path = "/../lib"},
                                            CreateDir{.path = "/../lib64"},
                                            CreateDir{.path = "/../tmp"},
                                            CreateDir{.path = "/../usr"},
                                            CreateDir{.path = "/../usr/bin"},
                                            CreateDir{.path = "/../usr/include"},
                                            CreateDir{.path = "/../usr/lib"},
                                            CreateDir{.path = "/../usr/lib64"},
                                            BindMount{
                                                .source = "/lib",
                                                .dest = "/../lib",
                                                .no_exec = false,
                                            },
                                            BindMount{
                                                .source = "/lib64",
                                                .dest = "/../lib64",
                                                .no_exec = false,
                                            },
                                            BindMount{
                                                .source = "/usr/bin",
                                                .dest = "/../usr/bin",
                                                .no_exec = false,
                                            },
                                            BindMount{
                                                .source = "/usr/include",
                                                .dest = "/../usr/include",
                                            },
                                            BindMount{
                                                .source = "/usr/lib",
                                                .dest = "/../usr/lib",
                                                .no_exec = false,
                                            },
                                            BindMount{
                                                .source = "/usr/lib64",
                                                .dest = "/../usr/lib64",
                                                .no_exec = false,
                                            },
                                        },
                                        mount_ops
                                    ),
                                .new_root_mount_path = "/..",
                            },
                    },
                .cgroup =
                    {
                        .process_num_limit = 32,
                        .memory_limit_in_bytes = options.memory_limit_in_bytes,
                        .cpu_max_bandwidth =
                            sandbox::RequestOptions::Cgroup::CpuMaxBandwidth{
                                .max_usec = 10000,
                                .period_usec = 10000,
                            },
                    },
                .prlimit =
                    {
                        .max_core_file_size_in_bytes = 0,
                        .max_file_size_in_bytes = options.max_file_size_in_bytes,
                    },
                .time_limit = options.time_limit,
                .cpu_time_limit = options.cpu_time_limit,
                .seccomp_bpf_fd = compiler_seccomp_bpf_fd,
            }
        )
    );
}

sandbox::Result Cpp_Clang::is_supported_impl(CompileOptions options) {
    return run_compiler({{"--version"}}, std::nullopt, {}, std::move(options));
}

sandbox::Result Cpp_Clang::compile_impl(
    FilePath source, FilePath executable, int compilation_errors_fd, CompileOptions options
) {
    return run_compiler(
        {{"source.cc", "-o", "exe"}},
        compilation_errors_fd,
        {{
            CreateFile{.path = "/../exe"},
            CreateFile{.path = "/../source.cc"},
            BindMount{
                .source = std::string_view{executable},
                .dest = "/../exe",
                .read_only = false,
            },
            BindMount{
                .source = std::string_view{source},
                .dest = "/../source.cc",
            },
        }},
        std::move(options)
    );
}

} // namespace sim::judge::language_suite