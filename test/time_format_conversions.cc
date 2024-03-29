#include <gtest/gtest.h>
#include <simlib/time_format_conversions.hh>

using std::chrono_literals::operator""ns;
using std::chrono_literals::operator""ms;
using std::chrono_literals::operator""s;

// NOLINTNEXTLINE
TEST(time, timespec_to_string) {
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 9, false) ==
        "1234567890.123456789"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 8, false) ==
        "1234567890.12345678"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 7, false) ==
        "1234567890.1234567"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 6, false) ==
        "1234567890.123456"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 5, false) ==
        "1234567890.12345"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 4, false) ==
        "1234567890.1234"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 3, false) ==
        "1234567890.123"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 2, false) ==
        "1234567890.12"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 1, false) ==
        "1234567890.1"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 0, false) ==
        "1234567890"
    );

    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 9, true) ==
        "1234567890.123456789"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 8, true) ==
        "1234567890.12345678"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 7, true) ==
        "1234567890.1234567"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 6, true) ==
        "1234567890.123456"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 5, true) ==
        "1234567890.12345"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 4, true) ==
        "1234567890.1234"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 3, true) ==
        "1234567890.123"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 2, true) ==
        "1234567890.12"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 1, true) ==
        "1234567890.1"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'789}, 0, true) ==
        "1234567890"
    );

    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'780}, 9, true) ==
        "1234567890.12345678"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'709}, 8, true) ==
        "1234567890.1234567"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'456'089}, 7, true) ==
        "1234567890.123456"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'450'789}, 6, true) ==
        "1234567890.12345"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'406'789}, 5, true) ==
        "1234567890.1234"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 123'056'789}, 4, true) ==
        "1234567890.123"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 120'456'789}, 3, true) ==
        "1234567890.12"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 103'456'789}, 2, true) ==
        "1234567890.1"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 23'456'789}, 1, true) ==
        "1234567890"
    );

    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 100'000'000}, 9, true) ==
        "1234567890.1"
    );
    static_assert(
        timespec_to_string({.tv_sec = 1'234'567'890, .tv_nsec = 0}, 9, true) == "1234567890"
    );
}

// NOLINTNEXTLINE
TEST(time, timeval_to_string) {
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 123'456}, 6, false) ==
        "1234567890.123456"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 123'456}, 5, false) ==
        "1234567890.12345"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 123'456}, 4, false) ==
        "1234567890.1234"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 123'456}, 3, false) ==
        "1234567890.123"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 123'456}, 2, false) ==
        "1234567890.12"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 123'456}, 1, false) == "1234567890.1"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 123'456}, 0, false) == "1234567890"
    );

    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 123'456}, 6, true) ==
        "1234567890.123456"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 123'456}, 5, true) ==
        "1234567890.12345"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 123'456}, 4, true) ==
        "1234567890.1234"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 123'456}, 3, true) ==
        "1234567890.123"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 123'456}, 2, true) == "1234567890.12"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 123'456}, 1, true) == "1234567890.1"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 123'456}, 0, true) == "1234567890"
    );

    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 123'450}, 6, true) ==
        "1234567890.12345"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 123'406}, 5, true) ==
        "1234567890.1234"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 123'056}, 4, true) ==
        "1234567890.123"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 120'456}, 3, true) == "1234567890.12"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 103'456}, 2, true) == "1234567890.1"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 23456}, 1, true) == "1234567890"
    );

    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 100'000}, 6, true) == "1234567890.1"
    );
    static_assert(
        timeval_to_string({.tv_sec = 1'234'567'890, .tv_usec = 0}, 6, true) == "1234567890"
    );
}

// NOLINTNEXTLINE
TEST(DISABLED_time, is_power_of_10) {
    // TODO: implement it
}

// NOLINTNEXTLINE
TEST(time, to_string_with_duration) {
    static_assert(from_unsafe{to_string(1s)} == "1");
    static_assert(from_unsafe{to_string(1'012'300'000ns)} == "1.0123");
    static_assert(from_unsafe{to_string(100'123'456'780ns)} == "100.12345678");
    static_assert(from_unsafe{to_string(123'123'456'789ns)} == "123.123456789");
    static_assert(from_unsafe{to_string(123'456'789ns)} == "0.123456789");
    static_assert(from_unsafe{to_string(89ns)} == "0.000000089");
    static_assert(from_unsafe{to_string(800ns)} == "0.0000008");
    static_assert(from_unsafe{to_string(12ms)} == "0.012");
    static_assert(from_unsafe{to_string(1'230'000ms)} == "1230");

    static_assert(from_unsafe{to_string(1'012'300'000ns, false)} == "1.012300000");
    static_assert(from_unsafe{to_string(800ns, false)} == "0.000000800");
    static_assert(from_unsafe{to_string(12ms, false)} == "0.012");
    static_assert(from_unsafe{to_string(1'230'000ms, false)} == "1230.000");
}

// NOLINTNEXTLINE
TEST(DISABLED_time, to_duration_with_timeval) {
    // TODO: implement it
}

// NOLINTNEXTLINE
TEST(DISABLED_time, to_duration_with_timespec) {
    // TODO: implement it
}

// NOLINTNEXTLINE
TEST(DISABLED_time, to_timespec) {
    // TODO: implement it
}

// NOLINTNEXTLINE
TEST(DISABLED_time, to_nanoseconds) {
    // TODO: implement it
}

// NOLINTNEXTLINE
TEST(time, floor_to_10ms) {
    static_assert(floor_to_10ms(1s) == 1s);
    static_assert(floor_to_10ms(1'012'300'000ns) == 1010ms);
    static_assert(floor_to_10ms(100'123'456'780ns) == 100'120ms);
    static_assert(floor_to_10ms(123'123'456'789ns) == 123'120ms);
    static_assert(floor_to_10ms(123'456'789ns) == 120ms);
    static_assert(floor_to_10ms(89ns) == 0s);
    static_assert(floor_to_10ms(800ns) == 0s);
    static_assert(floor_to_10ms(12ms) == 10ms);
    static_assert(floor_to_10ms(1'230'000ms) == 1230s);

    static_assert(floor_to_10ms(1230ms) == 1230ms);
    static_assert(floor_to_10ms(1231ms) == 1230ms);
    static_assert(floor_to_10ms(1232ms) == 1230ms);
    static_assert(floor_to_10ms(1233ms) == 1230ms);
    static_assert(floor_to_10ms(1234ms) == 1230ms);
    static_assert(floor_to_10ms(1235ms) == 1230ms);
    static_assert(floor_to_10ms(1236ms) == 1230ms);
    static_assert(floor_to_10ms(1237ms) == 1230ms);
    static_assert(floor_to_10ms(1238ms) == 1230ms);
    static_assert(floor_to_10ms(1239ms) == 1230ms);
}
