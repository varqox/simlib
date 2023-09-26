#include <cerrno>
#include <fcntl.h>
#include <sched.h>
#include <simlib/file_contents.hh>
#include <simlib/file_path.hh>
#include <simlib/file_perms.hh>
#include <simlib/from_unsafe.hh>
#include <simlib/macros/throw.hh>
#include <simlib/random_bytes.hh>
#include <simlib/string_traits.hh>
#include <simlib/throw_assert.hh>
#include <string_view>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

void no_operations_no_new_root_mount_path() {
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    throw_assert(fd >= 0);
    throw_assert(close(fd) == 0);
}

void test_exec(FilePath path_for_executable, bool expect_execable) {
    char* empty[] = {nullptr};
    auto exe_contents = get_file_contents(expect_execable ? "/bin/true" : "/bin/false");
    put_file_contents(path_for_executable, exe_contents.data(), exe_contents.size(), S_0755);
    if (expect_execable) {
        pid_t pid = fork();
        throw_assert(pid != -1);
        if (pid == 0) {
            (void)execve(path_for_executable, empty, empty);
            _exit(1);
        }
        int status;
        throw_assert(waitpid(pid, &status, 0) == pid);
        throw_assert(status == 0);
    } else {
        throw_assert(execve(path_for_executable, empty, empty) == -1 && errno == EACCES);
    }
}

void mount_tmpfs() {
    // max_total_size_of_files = nullopt
    put_file_contents("/tmp/max_total_size_of_files_nullopt/ok", "");
    put_file_contents("/tmp/max_total_size_of_files_nullopt/x", from_unsafe{random_bytes(65536)});
    // max_total_size_of_files = 0
    put_file_contents("/tmp/max_total_size_of_files_0/ok", "xxx");
    try {
        put_file_contents("/tmp/max_total_size_of_files_0/too_much", "xxx");
        THROW("expected exception");
    } catch (const std::exception& e) {
        throw_assert(has_prefix(e.what(), "write() failed - No space left on device (os error 28)")
        );
    }
    // max_total_size_of_files = 1
    put_file_contents("/tmp/max_total_size_of_files_1/ok", "xxx");
    try {
        put_file_contents("/tmp/max_total_size_of_files_1/too_much", "xxx");
        THROW("expected exception");
    } catch (const std::exception& e) {
        throw_assert(has_prefix(e.what(), "write() failed - No space left on device (os error 28)")
        );
    }
    // max_total_size_of_files = 32768
    put_file_contents("/tmp/max_total_size_of_files_32768/ok", from_unsafe{random_bytes(32768)});
    try {
        put_file_contents(
            "/tmp/max_total_size_of_files_32768/too_much", from_unsafe{random_bytes(1)}
        );
        THROW("expected exception");
    } catch (const std::exception& e) {
        throw_assert(has_prefix(e.what(), "write() failed - No space left on device (os error 28)")
        );
    }

    // inode_limit = nullopt
    throw_assert(mkdir("/tmp/inode_limit_nullopt/a", S_0755) == 0);
    throw_assert(mkdir("/tmp/inode_limit_nullopt/b", S_0755) == 0);
    throw_assert(mkdir("/tmp/inode_limit_nullopt/c", S_0755) == 0);
    // inode_limit = 0
    throw_assert(mkdir("/tmp/inode_limit_0/a", S_0755) == -1 && errno == ENOSPC);
    // inode_limit = 1
    throw_assert(mkdir("/tmp/inode_limit_1/a", S_0755) == 0);
    throw_assert(mkdir("/tmp/inode_limit_1/b", S_0755) == -1 && errno == ENOSPC);
    // inode_limit = 2
    throw_assert(mkdir("/tmp/inode_limit_2/a", S_0755) == 0);
    throw_assert(mkdir("/tmp/inode_limit_2/b", S_0755) == 0);
    throw_assert(mkdir("/tmp/inode_limit_2/c", S_0755) == -1 && errno == ENOSPC);

    struct stat st;
    // root_dir_mode = 0000
    throw_assert(stat("/tmp/root_dir_mode_0000", &st) == 0);
    throw_assert((st.st_mode & ACCESSPERMS) == 0000);
    // root_dir_mode = 0123
    throw_assert(stat("/tmp/root_dir_mode_0123", &st) == 0);
    throw_assert((st.st_mode & ACCESSPERMS) == 0123);

    // read_only = true
    throw_assert(mkdir("/tmp/read_only_true/x", S_0755) == -1 && errno == EROFS);
    // read_only = false
    throw_assert(mkdir("/tmp/read_only_false/x", S_0755) == 0);

    // no_exec = true
    test_exec("/tmp/no_exec_true/exe", false);
    // no_exec = false
    test_exec("/tmp/no_exec_false/exe", true);
}

void mount_proc() {
    // read_only = true
    throw_assert(
        open("/tmp/read_only_true/self/comm", O_WRONLY | O_CLOEXEC) == -1 && errno == EROFS
    );
    // read_only = false
    put_file_contents("/tmp/read_only_false/self/comm", "test");

    // no_exec = true
    throw_assert(
        system( // NOLINT
            R"(grep --quiet -P '^\S+ \S+ \S+ / /tmp/no_exec_true .*\bnoexec\b.*' /proc/self/mountinfo)"
        ) == 0
    );
    // no_exec = false
    throw_assert(
        system( // NOLINT
            R"(grep -P '^\S+ \S+ \S+ / /tmp/no_exec_false ' /proc/self/mountinfo | grep --quiet -Pv '\bnoexec\b' -q)"
        ) == 0
    );
}

void bind_mount() {
    // recursive = true
    throw_assert(access("/tmp/recursive_true/file", F_OK) == 0);
    throw_assert(access("/tmp/recursive_true/dir/file", F_OK) == 0);
    throw_assert(access("/tmp/recursive_true/dir/dir", F_OK) == 0);
    // recursive = false
    throw_assert(access("/tmp/recursive_true/file", F_OK) == 0);
    throw_assert(access("/tmp/recursive_false/dir/file", F_OK) == -1 && errno == ENOENT);
    throw_assert(access("/tmp/recursive_false/dir/dir", F_OK) == -1 && errno == ENOENT);
    // read_only = true, recursive = true
    throw_assert(mkdir("/tmp/read_only_true_recursive_true/x", S_0755) == -1 && errno == EROFS);
    throw_assert(
        mkdir("/tmp/read_only_true_recursive_true/dir/dir/x", S_0755) == -1 && errno == EROFS
    );
    // read_only = true, recursive = false
    throw_assert(mkdir("/tmp/read_only_true_recursive_false/x", S_0755) == -1 && errno == EROFS);
    throw_assert(
        mkdir("/tmp/read_only_true_recursive_false/dir/dir/x", S_0755) == -1 && errno == ENOENT
    );
    // read_only = false, recursive = true
    throw_assert(mkdir("/tmp/read_only_false_recursive_true/x", S_0755) == 0);
    throw_assert(mkdir("/tmp/read_only_false_recursive_true/dir/dir/x", S_0755) == 0);
    // read_only = false, recursive = false
    throw_assert(mkdir("/tmp/read_only_false_recursive_false/y", S_0755) == 0);
    throw_assert(
        mkdir("/tmp/read_only_false_recursive_false/dir/dir/y", S_0755) == -1 && errno == ENOENT
    );
    // no_exec = true, recursive = true
    test_exec("/tmp/no_exec_true_recursive_true/exe", false);
    test_exec("/tmp/no_exec_true_recursive_true/dir/dir/exe", false);
    // no_exec = true, recursive = false
    test_exec("/tmp/no_exec_true_recursive_false/exe", false);
    throw_assert(
        access("/tmp/no_exec_true_recursive_false/dir/dir/", F_OK) == -1 && errno == ENOENT
    );
    // no_exec = false, recursive = true
    test_exec("/tmp/no_exec_false_recursive_true/exe", true);
    test_exec("/tmp/no_exec_false_recursive_true/dir/dir/exe", true);
    // // no_exec = false, recursive = false
    test_exec("/tmp/no_exec_false_recursive_false/exe", true);
    throw_assert(
        access("/tmp/no_exec_false_recursive_false/dir/dir/", F_OK) == -1 && errno == ENOENT
    );
}

void create_dir() {
    struct stat st;
    // mode = 0000
    throw_assert(stat("/tmp/dir_mode_0000", &st) == 0);
    throw_assert((st.st_mode & ACCESSPERMS) == 0000);
    // mode = 0314
    throw_assert(stat("/tmp/dir_mode_0314", &st) == 0);
    throw_assert((st.st_mode & ACCESSPERMS) == 0314);
}

void create_file() {
    struct stat st;
    // mode = 0000
    throw_assert(stat("/tmp/file_mode_0000", &st) == 0);
    throw_assert((st.st_mode & ACCESSPERMS) == 0000);
    // mode = 0314
    throw_assert(stat("/tmp/file_mode_0314", &st) == 0);
    throw_assert((st.st_mode & ACCESSPERMS) == 0314);
}

void tracee_cannot_umount_mounts() {
    throw_assert(umount2("/tmp/tmp", MNT_DETACH) == -1 && errno == EPERM);
    throw_assert(umount2("/tmp/proc", MNT_DETACH) == -1 && errno == EPERM);
    throw_assert(umount2("/tmp/bind", MNT_DETACH) == -1 && errno == EPERM);
    throw_assert(umount2("/tmp/bind_recursive", MNT_DETACH) == -1 && errno == EPERM);
    throw_assert(umount2("/tmp", MNT_DETACH) == -1 && errno == EPERM);
    // Tracee does not have permissions to unshare only mount namespace
    throw_assert(unshare(CLONE_NEWNS) == -1 && errno == EPERM);
    // Inside another user and mount namespace
    throw_assert(unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0);
    throw_assert(umount2("/tmp/tmp", MNT_DETACH) == -1 && errno == EINVAL);
    throw_assert(umount2("/tmp/proc", MNT_DETACH) == -1 && errno == EINVAL);
    throw_assert(umount2("/tmp/bind", MNT_DETACH) == -1 && errno == EINVAL);
    throw_assert(umount2("/tmp/bind_recursive", MNT_DETACH) == -1 && errno == EINVAL);
    throw_assert(umount2("/tmp", MNT_DETACH) == -1 && errno == EINVAL);
}

int main(int argc, char** argv) {
    throw_assert(argc == 2);
    std::string_view arg = argv[1];
    if (arg == "no_operations_no_new_root_mount_path") {
        no_operations_no_new_root_mount_path();
    } else if (arg == "mount_tmpfs") {
        mount_tmpfs();
    } else if (arg == "mount_proc") {
        mount_proc();
    } else if (arg == "bind_mount") {
        bind_mount();
    } else if (arg == "create_dir") {
        create_dir();
    } else if (arg == "create_file") {
        create_file();
    } else if (arg == "tracee_cannot_umount_mounts") {
        tracee_cannot_umount_mounts();
    } else {
        THROW("unexpected argument: ", arg);
    }
}
