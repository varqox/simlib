#include "run_in_fully_interpreted_language_suite.hh"

#include <gtest/gtest.h>
#include <simlib/sandbox/si.hh>
#include <simlib/sim/judge/language_suite/awk.hh>

constexpr auto test_prog = "BEGIN { exit ARGV[1] }";

// NOLINTNEXTLINE
TEST(sim_judge_language_suite, awk) {
    auto suite = sim::judge::language_suite::Awk{};
    ASSERT_TRUE(suite.is_supported());
    auto res = run_in_fully_intepreted_language_suite(suite, test_prog, {{"42"}});
    ASSERT_EQ(res.si, (sandbox::Si{.code = CLD_EXITED, .status = 42}));
}
