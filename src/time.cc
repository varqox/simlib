#include <algorithm>
#include <ctime>
#include <simlib/macros/throw.hh>
#include <simlib/string_view.hh>
#include <string>
#include <sys/time.h>
#include <utility>

using std::string;

int64_t microtime() noexcept {
    timeval mtime{};
    (void)gettimeofday(&mtime, nullptr);
    return (mtime.tv_sec * static_cast<int64_t>(1'000'000)) + mtime.tv_usec;
}

template <class F>
static string date_impl(CStringView format, time_t curr_time, F func) {
    if (curr_time < 0) {
        time(&curr_time);
    }

    string buff(format.size() + 1 + std::count(format.begin(), format.end(), '%') * 25, '0');

    tm ptm{};
    if (not func(&curr_time, &ptm)) {
        THROW("Failed to convert time");
    }

    size_t rc = strftime(const_cast<char*>(buff.data()), buff.size(), format.c_str(), &ptm);

    buff.resize(rc);
    return buff;
}

string date(CStringView format, time_t curr_time) { return date_impl(format, curr_time, gmtime_r); }

string localdate(CStringView format, time_t curr_time) {
    return date_impl(format, curr_time, localtime_r);
}

bool is_datetime(const CStringView& str) noexcept {
    struct tm t = {};
    return (str.size() == 19 && strptime(str.c_str(), "%Y-%m-%d %H:%M:%S", &t) != nullptr);
}
