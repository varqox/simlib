#include <array>
#include <cerrno>
#include <fcntl.h>
#include <optional>
#include <simlib/ctype.hh>
#include <simlib/errmsg.hh>
#include <simlib/file_contents.hh>
#include <simlib/file_descriptor.hh>
#include <simlib/macros/throw.hh>
#include <simlib/pipe.hh>
#include <simlib/sandbox/sandbox.hh>
#include <simlib/sim/judge/test_on_test.hh>
#include <simlib/simple_parser.hh>
#include <simlib/string_transform.hh>
#include <simlib/temporary_file.hh>
#include <simlib/utilities.hh>
#include <string_view>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <unistd.h>

using std::string_view;

using BindMount = sandbox::RequestOptions::LinuxNamespaces::Mount::BindMount;
using CreateFile = sandbox::RequestOptions::LinuxNamespaces::Mount::CreateFile;

namespace sim::judge {

struct SpliceStdinAndStdoutRes {
    bool output_size_limit_exceeded;
};

SpliceStdinAndStdoutRes splice_stdin_and_stdout(
    FileDescriptor& stdin_pipe_write_end,
    FileDescriptor& stdin_file_fd,
    FileDescriptor& stdout_pipe_read_end,
    FileDescriptor& stdout_file_fd,
    decltype(TestArgs::Program::output_size_limit_in_bytes) output_size_limit_in_bytes
) {
    std::array<pollfd, 4> pfds;

    enum {
        STDIN_PIPE = 0,
        STDIN_FILE = 1,
        STDOUT_PIPE = 2,
        STDOUT_FILE = 3,
    };

    pfds[STDIN_PIPE] = {
        .fd = stdin_pipe_write_end,
        .events = POLLOUT,
        .revents = 0,
    };
    pfds[STDIN_FILE] = {
        .fd = stdin_file_fd,
        .events = POLLIN,
        .revents = 0,
    };
    pfds[STDOUT_PIPE] = {
        .fd = stdout_pipe_read_end,
        .events = POLLIN,
        .revents = 0,
    };
    pfds[STDOUT_FILE] = {
        .fd = stdout_file_fd,
        .events = POLLOUT,
        .revents = 0,
    };

    SpliceStdinAndStdoutRes res{
        .output_size_limit_exceeded = false,
    };
    auto remaining_output_size_limit = output_size_limit_in_bytes;
    while (pfds[STDIN_PIPE].fd >= 0 || pfds[STDOUT_PIPE].fd >= 0) {
        for (auto& pfd : pfds) {
            pfd.revents = 0;
        }
        int rc = poll(pfds.data(), pfds.size(), -1);
        if (rc == 0 || (rc == -1 && errno == EINTR)) {
            continue;
        }
        if (rc == -1) {
            THROW("poll()", errmsg());
        }

        auto close_stdin = [&] {
            if (stdin_pipe_write_end.close()) {
                THROW("close()", errmsg());
            }
            pfds[STDIN_PIPE] = {
                .fd = -1,
                .events = POLLOUT, // not to show this fd as marked writable
                .revents = 0,
            };
            if (stdin_file_fd.close()) {
                THROW("close()", errmsg());
            }
            pfds[STDIN_FILE] = {
                .fd = -1,
                .events = 0,
                .revents = 0,
            };
        };
        auto close_stdout = [&] {
            if (stdout_pipe_read_end.close()) {
                THROW("close()", errmsg());
            }
            pfds[STDOUT_PIPE] = {
                .fd = -1,
                .events = POLLIN, // not to show this fd as marked readable
                .revents = 0,
            };
            if (stdout_file_fd.close()) {
                THROW("close()", errmsg());
            }
            pfds[STDOUT_FILE] = {
                .fd = -1,
                .events = 0,
                .revents = 0,
            };
        };

        // Program closed stdin
        if (pfds[STDIN_PIPE].revents & POLLERR) {
            close_stdin();
        }
        // Program closed stdout and no data is readable
        if ((pfds[STDOUT_PIPE].revents & POLLHUP) && !(pfds[STDOUT_PIPE].revents & POLLIN)) {
            close_stdout();
        }

        // Disable listening of ready fds, to make poll wait on other fds
        if (pfds[STDIN_PIPE].revents & POLLOUT) {
            pfds[STDIN_PIPE].events = 0; // still listen for POLLERR
        }
        if (pfds[STDIN_FILE].revents & POLLIN) {
            pfds[STDIN_FILE].fd = -2;
        }
        if (pfds[STDOUT_PIPE].revents & POLLIN) {
            pfds[STDOUT_PIPE].events = 0; // still listen for POLLHUP
        }
        if (pfds[STDOUT_FILE].revents & POLLOUT) {
            pfds[STDOUT_FILE].fd = -2;
        }

        // Both stdin fds are ready, we can perform IO
        if (pfds[STDIN_PIPE].events == 0 && pfds[STDIN_FILE].fd < -1) {
            auto sent = splice(
                stdin_file_fd, nullptr, stdin_pipe_write_end, nullptr, 1 << 30, SPLICE_F_NONBLOCK
            );
            if (sent < 0) {
                THROW("splice()", errmsg());
            }
            // No more data
            if (sent == 0) {
                close_stdin();
            } else {
                pfds[STDIN_PIPE].events = POLLOUT;
                pfds[STDIN_FILE].fd = stdin_file_fd;
            }
        }

        // Both stdout fds are ready, we can perform IO
        if (pfds[STDOUT_PIPE].events == 0 && pfds[STDOUT_FILE].fd < -1) {
            if (remaining_output_size_limit == 0) {
                res.output_size_limit_exceeded = true;
                close_stdout();
            } else {
                auto sent = splice(
                    stdout_pipe_read_end,
                    nullptr,
                    stdout_file_fd,
                    nullptr,
                    remaining_output_size_limit,
                    SPLICE_F_NONBLOCK
                );
                if (sent < 0) {
                    THROW("splice()", errmsg());
                }
                // No more data
                if (sent == 0) {
                    close_stdout();
                } else {
                    pfds[STDOUT_PIPE].events = POLLIN;
                    pfds[STDOUT_FILE].fd = stdout_file_fd;
                    remaining_output_size_limit -= sent;
                }
            }
        }
    }
    return res;
}

TestReport test_on_test(TestArgs args) {
    static const auto page_size = sysconf(_SC_PAGESIZE);
    auto prog_output_file = TemporaryFile{"/tmp/sim-judge-test-on-test-program-output.XXXXXX"};
    auto prog_stdin_file_fd =
        FileDescriptor{args.test_input, O_RDONLY | O_LARGEFILE | O_CLOEXEC | O_NONBLOCK};
    if (!prog_stdin_file_fd.is_open()) {
        THROW("open(", args.test_input, ")", errmsg());
    }
    auto prog_stdout_file_fd =
        FileDescriptor{prog_output_file.path(), O_WRONLY | O_LARGEFILE | O_CLOEXEC | O_NONBLOCK};
    if (!prog_stdout_file_fd.is_open()) {
        THROW("open(", prog_output_file.path(), ")", errmsg());
    }

    auto stdin_pipe = pipe2(O_CLOEXEC);
    if (not stdin_pipe) {
        THROW("pipe2()", errmsg());
    }
    if (fcntl(stdin_pipe->writable, F_SETFL, O_NONBLOCK)) {
        THROW("fcntl()", errmsg());
    }

    auto stdout_pipe = pipe2(O_CLOEXEC);
    if (not stdout_pipe) {
        THROW("pipe2()", errmsg());
    }
    if (fcntl(stdout_pipe->readable, F_SETFL, O_NONBLOCK)) {
        THROW("fcntl()", errmsg());
    }

    args.compiled_program.async_run(
        {},
        {
            .stdin_fd = stdin_pipe->readable,
            .stdout_fd = stdout_pipe->writable,
            .stderr_fd = std::nullopt,
            .time_limit = args.program.time_limit,
            .cpu_time_limit = args.program.cpu_time_limit,
            // + page_size to allow detecting overuse
            .memory_limit_in_bytes = args.program.memory_limit_in_bytes + page_size,
            .max_stack_size_in_bytes = args.program.memory_limit_in_bytes + page_size,
            .max_file_size_in_bytes = 0,
        },
        {}
    );

    if (stdin_pipe->readable.close()) {
        THROW("close()", errmsg());
    }
    if (stdout_pipe->writable.close()) {
        THROW("close()", errmsg());
    }

    auto splice_res = splice_stdin_and_stdout(
        stdin_pipe->writable,
        prog_stdin_file_fd,
        stdout_pipe->readable,
        prog_stdout_file_fd,
        args.program.output_size_limit_in_bytes
    );

    auto prog_res = args.compiled_program.await_result();
    auto prog_cpu_time = prog_res.cgroup.cpu_time.total();
    TestReport report = {
        .status = TestReport::Status::OK,
        .runtime = prog_res.runtime,
        .cpu_time = prog_cpu_time,
        .peak_memory_in_bytes = prog_res.cgroup.peak_memory_in_bytes,
        .comment = {},
        .score = 0,
        .checker_runtime = std::nullopt,
        .checker_cpu_time = std::nullopt,
    };

    if (prog_res.runtime > args.program.time_limit || prog_cpu_time > args.program.cpu_time_limit) {
        report.status = TestReport::Status::TimeLimitExceeded;
        report.comment = "Time limit exceeded";
        return report;
    }

    if (prog_res.cgroup.peak_memory_in_bytes > args.program.memory_limit_in_bytes) {
        report.status = TestReport::Status::MemoryLimitExceeded,
        report.comment = "Memory limit exceeded";
        return report;
    }

    if (splice_res.output_size_limit_exceeded) {
        report.status = TestReport::Status::OutputSizeLimitExceeded;
        report.comment = "Output size limit exceeded";
        return report;
    }

    if (prog_res.si != sandbox::Si{.code = CLD_EXITED, .status = 0}) {
        report.status = TestReport::Status::RuntimeError;
        report.comment = "Runtime error: " + prog_res.si.description();
        return report;
    }

    auto checker_output_file = FileDescriptor{memfd_create("checker output", MFD_CLOEXEC)};
    if (!checker_output_file.is_open()) {
        THROW("memfd_create()", errmsg());
    }
    args.compiled_checker.async_run(
        {{
            "/in",
            "/out",
            "/prog_out",
        }},
        {
            .stdin_fd = std::nullopt,
            .stdout_fd = std::nullopt,
            .stderr_fd = checker_output_file,
            .time_limit = args.checker.time_limit,
            .cpu_time_limit = args.checker.cpu_time_limit,
            // + page_size to allow detecting overuse
            .memory_limit_in_bytes = args.checker.memory_limit_in_bytes + page_size,
            .max_stack_size_in_bytes = args.checker.memory_limit_in_bytes + page_size,
            .max_file_size_in_bytes = args.checker.max_comment_len + 32,
            .rootfs =
                {
                    .inode_limit = 3,
                },
        },
        {{
            CreateFile{.path = "/../in"},
            CreateFile{.path = "/../out"},
            CreateFile{.path = "/../prog_out"},
            BindMount{
                .source = string_view{args.test_input},
                .dest = "/../in",
            },
            BindMount{
                .source = string_view{args.expected_output},
                .dest = "/../out",
            },
            BindMount{
                .source = string_view{prog_output_file.path()},
                .dest = "/../prog_out",
            },
        }}
    );
    auto checker_res = args.compiled_checker.await_result();
    report.checker_runtime = checker_res.runtime;
    report.checker_cpu_time = checker_res.cgroup.cpu_time.total();

    if (checker_res.runtime > args.checker.time_limit ||
        report.checker_cpu_time > args.checker.cpu_time_limit)
    {
        report.status = TestReport::Status::CheckerError;
        report.comment = "Checker error: time limit exceeded";
        return report;
    }

    if (checker_res.cgroup.peak_memory_in_bytes > args.checker.memory_limit_in_bytes) {
        report.status = TestReport::Status::CheckerError,
        report.comment = "Checker error: memory limit exceeded";
        return report;
    }

    if (checker_res.si != sandbox::Si{.code = CLD_EXITED, .status = 0}) {
        report.status = TestReport::Status::CheckerError;
        report.comment = "Checker runtime error: " + checker_res.si.description();
        return report;
    }

    auto checker_output = get_file_contents(
        checker_output_file, 0, static_cast<off_t>(args.checker.max_comment_len) + 32
    );
    SimpleParser parser(checker_output);

    auto line1 = parser.extract_next('\n');
    if (!is_one_of(line1, "OK", "WRONG")) {
        report.status = TestReport::Status::CheckerError;
        report.comment = R"(Checker error: invalid first line (expected "OK" or "WRONG"))";
        return report;
    }

    auto line2 = parser.extract_next('\n');
    if (line1 == "OK") {
        report.status = TestReport::Status::OK;
        report.score = 1;
        if (!line2.empty()) {
            auto res = str2num<double>(line2, 0, 100);
            if (!res) {
                report.status = TestReport::Status::CheckerError;
                report.comment = "Checker error: invalid second line (expected real number in "
                                 "range [0, 100] or empty line)";
                report.score = 0;
                return report;
            }
            report.score = *res * 0.01;
        }
    } else {
        report.status = TestReport::Status::WrongAnswer;
    }

    // Leave only the comment
    checker_output.erase(checker_output.begin(), checker_output.end() - parser.size());
    // Remove trailing whitespace
    while (!checker_output.empty() && is_space(checker_output.back())) {
        checker_output.pop_back();
    }
    // Trim the comment if necessary
    if (checker_output.size() > args.checker.max_comment_len) {
        checker_output.resize(args.checker.max_comment_len);
    }

    report.comment = checker_output;
    return report;
}

} // namespace sim::judge
