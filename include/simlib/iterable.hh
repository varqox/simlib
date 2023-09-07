#pragma once

#include <array>
#include <cstddef>
#include <exception>
#include <iterator>
#include <type_traits>
#include <utility>

template <class ItemT>
class Iterable {
public:
    constexpr Iterable() noexcept = default;

    constexpr Iterable(const Iterable&) = delete;
    constexpr Iterable(Iterable&&) = delete;
    constexpr Iterable& operator=(const Iterable&) = delete;
    constexpr Iterable& operator=(Iterable&&) = delete;

    virtual ~Iterable() = default;

    using Item = ItemT;

    [[nodiscard]] virtual constexpr Item* current() = 0;

    virtual constexpr void advance() = 0;

    class Iterator {
        Iterable* iterable;

        using difference_type = size_t;
        using value_type = Item;
        using pointer = Item*;
        using reference = Item&;
        using iterator_category = std::input_iterator_tag;

    public:
        explicit constexpr Iterator(Iterable* iterable)
        : iterable{iterable && iterable->current() ? iterable : nullptr} {}

        [[nodiscard]] constexpr reference operator*() const noexcept {
            return *iterable->current();
        }

        [[nodiscard]] constexpr pointer operator->() const noexcept { iterable->current(); }

        [[nodiscard]] constexpr Iterator& operator++() noexcept {
            iterable->advance();
            if (iterable->current() == nullptr) {
                iterable = nullptr;
            }
            return *this;
        }

        [[nodiscard]] constexpr Iterator& operator++(int) noexcept = delete;

        [[nodiscard]] constexpr friend bool operator==(Iterator a, Iterator b) {
            return a.iterable == b.iterable;
        }

        [[nodiscard]] constexpr friend bool operator!=(Iterator a, Iterator b) {
            return a.iterable != b.iterable;
        }
    };

    [[nodiscard]] constexpr Iterator begin() noexcept { return Iterator{this}; }

    [[nodiscard]] constexpr Iterator end() noexcept { return Iterator{nullptr}; }
};

template <class Iter>
class IterableFrom : public Iterable<std::remove_reference_t<decltype(*std::declval<Iter>())>> {
    Iter beg_;
    Iter end_;

public:
    using Item = std::remove_reference_t<decltype(*std::declval<Iter>())>;

    constexpr IterableFrom(Iter beg, Iter end) noexcept : beg_{beg}, end_{end} {}

    template <class C, std::enable_if_t<!std::is_same_v<C, IterableFrom<Iter>>, int> = 0>
    constexpr explicit IterableFrom(C&& container) noexcept
    : beg_{container.begin()}
    , end_{container.end()} {}

    [[nodiscard]] constexpr Item* current() override { return beg_ == end_ ? nullptr : &*beg_; }

    constexpr void advance() override {
        if (beg_ == end_) {
            std::terminate();
        }
        ++beg_;
    }
};

template <class C>
IterableFrom(const C&) -> IterableFrom<decltype(std::declval<const C&>().begin())>;
template <class C>
IterableFrom(C&) -> IterableFrom<decltype(std::declval<C&>().begin())>;
template <class C>
IterableFrom(C&&) -> IterableFrom<decltype(std::declval<C&&>().begin())>;

template <class ItemT, size_t N>
class IterableMerge : public Iterable<ItemT> {
    std::array<Iterable<ItemT>*, N> iterables;
    size_t curr = 0;

public:
    using Item = ItemT;

    template <class... T>
    constexpr explicit IterableMerge(T&&... iterables) : iterables{&iterables...} {
        static_assert(sizeof...(iterables) == N);
        while (curr < N && this->iterables[curr]->current() == nullptr) {
            ++curr;
        }
    }

    [[nodiscard]] constexpr Item* current() override {
        return curr == N ? nullptr : iterables[curr]->current();
    }

    constexpr void advance() override {
        if (curr == N) {
            std::terminate();
        }
        iterables[curr]->advance();
        while (curr < N && iterables[curr]->current() == nullptr) {
            ++curr;
        }
    }
};

template <class T, class... Args>
IterableMerge(T, Args...) -> IterableMerge<typename T::Item, 1 + sizeof...(Args)>;
