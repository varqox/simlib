#pragma once

#include <optional>
#include <type_traits>

template <class T, class Func>
std::optional<std::invoke_result_t<Func&&, const T&>>
map(const std::optional<T>& opt, Func&& func) {
    if (opt) {
        return std::optional{std::forward<Func>(func)(*opt)};
    }
    return std::nullopt;
}

template <class T, class Func>
std::optional<std::invoke_result_t<Func&&, T&&>> map(std::optional<T>&& opt, Func&& func) {
    if (opt) {
        return std::optional{std::forward<Func>(func)(std::move(*opt))};
    }
    return std::nullopt;
}
