#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <simlib/string_view.hh>
#include <sys/types.h>
#include <variant>
#include <vector>

namespace sandbox::supervisor::request {

struct Request {
    int result_fd;
    int kill_tracee_fd;
    std::variant<int, char*> executable;
    std::optional<int> stdin_fd;
    std::optional<int> stdout_fd;
    std::optional<int> stderr_fd;
    std::unique_ptr<std::byte[]> buff;
    std::vector<char*> argv; // with a trailing nullptr element
    std::vector<char*> env; // with a trailing nullptr element

    struct LinuxNamespaces {
        struct User {
            std::optional<uid_t> inside_uid;
            std::optional<gid_t> inside_gid;
        } user;

        struct Mount {
            struct MountTmpfs {
                CStringView path;
                std::optional<uint64_t>
                    max_total_size_of_files_in_bytes; // will be rounded up to page size multiple; 0
                                                      // rounds up to page size due to technical
                                                      // limitations of tmpfs.
                std::optional<uint64_t> inode_limit;
                mode_t root_dir_mode;
                bool read_only;
                bool no_exec;
            };

            struct MountProc {
                CStringView path;
                bool read_only;
                bool no_exec;
            };

            struct BindMount {
                CStringView source;
                CStringView dest;
                bool recursive;
                bool read_only;
                bool no_exec;
                bool symlink_nofollow;
            };

            struct CreateDir {
                CStringView path;
                mode_t mode;
            };

            struct CreateFile {
                CStringView path;
                mode_t mode;
            };

            using Operation = std::variant<MountTmpfs, MountProc, BindMount, CreateDir, CreateFile>;

            std::vector<Operation> operations;
            std::optional<CStringView> new_root_mount_path;
        } mount;
    } linux_namespaces;

    struct Cgroup {
        std::optional<uint32_t> process_num_limit;
        std::optional<uint64_t> memory_limit_in_bytes;
        std::optional<uint64_t> swap_limit_in_bytes;

        struct CpuMaxBandwidth {
            uint32_t max_usec;
            uint32_t period_usec;
        };

        std::optional<CpuMaxBandwidth> cpu_max_bandwidth;
    } cgroup;

    struct Prlimit {
        std::optional<uint64_t> max_address_space_size_in_bytes;
        std::optional<uint64_t> max_core_file_size_in_bytes;
        std::optional<uint64_t> cpu_time_limit_in_seconds;
        std::optional<uint64_t> max_file_size_in_bytes;
        std::optional<uint64_t> file_descriptors_num_limit;
        std::optional<uint64_t> max_stack_size_in_bytes;
    } prlimit;

    std::optional<timespec> time_limit;
    std::optional<timespec> cpu_time_limit;
    std::optional<int> seccomp_bpf_fd;
};

} // namespace sandbox::supervisor::request
