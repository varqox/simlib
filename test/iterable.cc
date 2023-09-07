#include <gtest/gtest.h>
#include <simlib/iterable.hh>
#include <simlib/slice.hh>
#include <vector>

using std::vector;

template <class T>
vector<std::remove_const_t<T>> to_vec(Iterable<T>&& iterable) {
    vector<std::remove_const_t<T>> vec;
    for (auto&& elem : iterable) {
        vec.emplace_back(elem);
    }
    return vec;
}

// NOLINTNEXTLINE
TEST(iterable_from, vec_size_0) { ASSERT_EQ(to_vec(IterableFrom{vector<int>{}}), (vector<int>{})); }

// NOLINTNEXTLINE
TEST(iterable_from, vec_size_1) { ASSERT_EQ(to_vec(IterableFrom{vector{1}}), (vector{1})); }

// NOLINTNEXTLINE
TEST(iterable_from, vec_size_2) { ASSERT_EQ(to_vec(IterableFrom{vector{1, 2}}), (vector{1, 2})); }

// NOLINTNEXTLINE
TEST(iterable_from, vec_size_3) {
    ASSERT_EQ(to_vec(IterableFrom{vector{1, 2, 3}}), (vector{1, 2, 3}));
}

// NOLINTNEXTLINE
TEST(iterable_from, slice_size_0) {
    ASSERT_EQ(to_vec(IterableFrom{Slice<int>{}}), (vector<int>{}));
}

// NOLINTNEXTLINE
TEST(iterable_from, slice_size_1) { ASSERT_EQ(to_vec(IterableFrom{Slice{{1}}}), (vector{1})); }

// NOLINTNEXTLINE
TEST(iterable_from, slice_size_2) {
    ASSERT_EQ(to_vec(IterableFrom{Slice{{1, 2}}}), (vector{1, 2}));
}

// NOLINTNEXTLINE
TEST(iterable_from, slice_size_3) {
    ASSERT_EQ(to_vec(IterableFrom{Slice{{1, 2, 3}}}), (vector{1, 2, 3}));
}

// NOLINTNEXTLINE
TEST(iterable_from, from_lvalue) {
    auto vec = vector{1, 2, 3};
    static_assert(std::is_same_v<decltype(IterableFrom{vec})::Item, int>);
    ASSERT_EQ(to_vec(IterableFrom{vec}), (vector{1, 2, 3}));
}

// NOLINTNEXTLINE
TEST(iterable_from, from_const_ref) {
    const auto vec = vector{1, 2, 3};
    static_assert(std::is_same_v<decltype(IterableFrom{vec})::Item, const int>);
    ASSERT_EQ(to_vec(IterableFrom{vec}), (vector{1, 2, 3}));
}

// NOLINTNEXTLINE
TEST(iterable_merge, empty) {
    ASSERT_EQ(
        to_vec(IterableMerge{
            IterableFrom{Slice<int>{}},
            IterableFrom{vector<int>{}},
        }),
        (vector<int>{})
    );
}

// NOLINTNEXTLINE
TEST(iterable_merge, simple) {
    ASSERT_EQ(
        to_vec(IterableMerge{
            IterableFrom{Slice<int>{}},
            IterableFrom{vector{1, 2}},
            IterableFrom{vector<int>{}},
            IterableFrom{Slice{{3, 4}}},
        }),
        (vector{1, 2, 3, 4})
    );
    ASSERT_EQ(
        to_vec(IterableMerge{
            IterableFrom{Slice<int>{}},
            IterableFrom{vector{1, 2}},
            IterableFrom{Slice{{3, 4}}},
            IterableFrom{vector<int>{}},
        }),
        (vector{1, 2, 3, 4})
    );
}
