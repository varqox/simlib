#pragma once

#include <chrono>
#include <ctime>
#include <simlib/errmsg.hh>
#include <simlib/macros/throw.hh>
#include <simlib/string_view.hh>
#include <simlib/to_string.hh>

/**
 * @brief Converts a string containing time to time_t
 *
 * @param str a string containing time
 * @param format the format of the contained time
 *
 * @return time as time_t, or -1 if an error occurred
 *
 * @errors The same that occur for strptime(3) and timegm(3)
 */
inline time_t
str_to_time_t(CStringView str, CStringView format = CStringView{"%Y-%m-%d %H:%M:%S"}) noexcept {
    struct tm t = {};
    if (!strptime(str.c_str(), format.c_str(), &t)) {
        return -1;
    }
    return timegm(&t);
}

/**
 * @brief Converts a @p str containing time in format @p format to time_point
 * @errors The same that occur for str_to_time_t() but thrown as exceptions
 */
inline std::chrono::system_clock::time_point
str_to_time_point(CStringView str, CStringView format = CStringView{"%Y-%m-%d %H:%M:%S"}) {
    time_t t = str_to_time_t(str, format);
    if (t == -1) {
        THROW("str_to_time_t()", errmsg());
    }

    return std::chrono::system_clock::from_time_t(t);
}

namespace detail {

template <class T>
constexpr size_t append_decimal_point_with_digits(
    char* buff, uint max_precision, uint precision, bool trim_zeros, T val
) noexcept {
    assert(precision <= max_precision);
    buff[0] = '.';
    for (size_t i = max_precision; i > 0; --i) {
        buff[i] = static_cast<char>('0' + val % 10);
        val /= 10;
    }
    // Truncate trailing zeros
    size_t i = precision;
    if (trim_zeros) {
        while (i > 0 && buff[i] == '0') {
            --i;
        }
    }
    if (i == 0) {
        return 0;
    }
    return i + 1;
}

} // namespace detail

constexpr auto timespec_to_string(timespec ts, uint precision, bool trim_zeros = true) noexcept {
    auto sec_str = to_string(ts.tv_sec);
    StaticCStringBuff<decltype(sec_str)::max_size() + 10> res = sec_str;
    res.len_ +=
        detail::append_decimal_point_with_digits(res.end(), 9, precision, trim_zeros, ts.tv_nsec);
    *res.end() = '\0';
    return res;
}

constexpr auto timeval_to_string(timeval tv, uint precision, bool trim_zeros = true) noexcept {
    auto sec_str = to_string(tv.tv_sec);
    StaticCStringBuff<decltype(sec_str)::max_size() + 7> res = sec_str;
    res.len_ +=
        detail::append_decimal_point_with_digits(res.end(), 6, precision, trim_zeros, tv.tv_usec);
    *res.end() = '\0';
    return res;
}

template <class T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
constexpr bool is_power_of_10(T x) noexcept {
    if (x <= 0) {
        return false;
    }

    while (x > 1) {
        if (x % 10 != 0) {
            return false;
        }
        x /= 10;
    }

    return (x == 1);
}

/**
 * @brief Converts std::chrono::duration to string (as seconds)
 *
 * @param dur std::chrono::duration to convert to string
 * @param trim_zeros set whether to trim trailing zeros
 *
 * @return floating-point @p dur in seconds as string
 */
template <
    class Rep,
    class Period,
    size_t N = decltype(to_string(std::declval<Rep>()))::max_size() +
        3> // +3 for sign, terminating null and decimal point
constexpr StaticCStringBuff<N>
to_string(const std::chrono::duration<Rep, Period>& dur, bool trim_zeros = true) noexcept {
    static_assert(Period::num == 1, "Needed below");
    static_assert(is_power_of_10(Period::den), "Needed below");
    auto dec_dur = std::chrono::duration_cast<std::chrono::duration<intmax_t>>(dur);
    auto res = to_string<Rep, N>(dec_dur.count());
    res[res.len_++] = '.';

    auto x = std::chrono::duration<intmax_t, Period>(dur - dec_dur).count();
    constexpr int prec = to_string(Period::den).size() - 1;
    for (auto i = res.len_ + prec - 1; i >= res.len_; --i) {
        res[i] = '0' + x % 10;
        x /= 10;
    }

    if (trim_zeros) {
        // Truncate trailing zeros
        auto i = res.len_ + prec - 1;
        // i will point to the last character of the result
        while (i >= res.len_ and res[i] == '0') {
            --i;
        }

        if (i == res.len_ - 1) {
            res.len_ = i; // Trim trailing '.'
        } else {
            res.len_ = i + 1;
        }
    } else {
        res.len_ += prec;
    }

    *res.end() = '\0';
    return res;
}

constexpr std::chrono::microseconds to_duration(const timeval& tv) noexcept {
    return std::chrono::seconds(tv.tv_sec) + std::chrono::microseconds(tv.tv_usec);
}

constexpr std::chrono::nanoseconds to_duration(const timespec& ts) noexcept {
    return std::chrono::seconds(ts.tv_sec) + std::chrono::nanoseconds(ts.tv_nsec);
}

// TODO: This works for positive durations - check it for negative
template <class Rep, class Period>
timespec to_timespec(const std::chrono::duration<Rep, Period>& dur) noexcept {
    auto sec_dur = std::chrono::duration_cast<std::chrono::seconds>(dur);
    auto nsec = std::chrono::duration_cast<std::chrono::nanoseconds>(dur - sec_dur);
    return {sec_dur.count(), nsec.count()};
}

constexpr std::chrono::nanoseconds to_nanoseconds(const timespec& ts) noexcept {
    return std::chrono::seconds(ts.tv_sec) + std::chrono::nanoseconds(ts.tv_nsec);
}

template <class Rep, class Period>
constexpr auto floor_to_10ms(const std::chrono::duration<Rep, Period>& time) noexcept {
    return std::chrono::duration_cast<std::chrono::duration<intmax_t, std::centi>>(time);
}
