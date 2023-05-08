#include <gtest/gtest.h>
#include <simlib/http/response.hh>

// NOLINTNEXTLINE
TEST(http, quote) {
    using http::quote;

    EXPECT_EQ(quote(""), "\"\"");
    EXPECT_EQ(quote("abcdefghijklmnopqrstuvwxyz"), "\"abcdefghijklmnopqrstuvwxyz\"");
    EXPECT_EQ(quote("\""), "\"\\\"\"");
    EXPECT_EQ(
        quote("\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""),
        "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\""
    );
    EXPECT_EQ(quote("\n"), "\"\\\n\"");
    EXPECT_EQ(quote("a\tb"), "\"a\\\tb\"");
    EXPECT_EQ(quote("a\"b"), "\"a\\\"b\"");
}
