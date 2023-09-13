#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <simlib/file_path.hh>
#include <simlib/sim/judge/language_suite/suite.hh>
#include <string>

namespace sim::judge {

struct TestReport {
    // Sorted by decreasing priority
    enum class Status : uint8_t {
        TimeLimitExceeded,
        MemoryLimitExceeded,
        OutputSizeLimitExceeded,
        RuntimeError,
        CheckerError,
        WrongAnswer,
        OK,
    } status;

    std::chrono::nanoseconds runtime;
    std::chrono::microseconds cpu_time;
    uint64_t peak_memory_in_bytes;
    std::string comment;
    double score; // in range [0, 1]
    std::optional<std::chrono::nanoseconds> checker_runtime;
    std::optional<std::chrono::microseconds> checker_cpu_time;
};

struct TestArgs {
    language_suite::Suite& compiled_program; // NOLINT
    language_suite::Suite& compiled_checker; // NOLINT
    FilePath test_input;
    FilePath expected_output;

    struct Program {
        std::chrono::nanoseconds time_limit;
        std::chrono::nanoseconds cpu_time_limit;
        uint64_t memory_limit_in_bytes;
        uint64_t output_size_limit_in_bytes;
    } program;

    struct Checker {
        std::chrono::nanoseconds time_limit;
        std::chrono::nanoseconds cpu_time_limit;
        uint64_t memory_limit_in_bytes;
        uint64_t max_comment_len;
    } checker;
};

TestReport test_on_test(TestArgs args);

} // namespace sim::judge
