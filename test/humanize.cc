#include "simlib/humanize.hh"

#include <gtest/gtest.h>

// NOLINTNEXTLINE(cppcoreguidelines-special-member-functions)
TEST(humanize, humanize_file_size) {
	EXPECT_EQ(humanize_file_size(0), "0 bytes");
	EXPECT_EQ(humanize_file_size(1), "1 byte");
	EXPECT_EQ(humanize_file_size(2), "2 bytes");
	EXPECT_EQ(humanize_file_size(1023), "1023 bytes");
	EXPECT_EQ(humanize_file_size(1024), "1.0 KiB");
	EXPECT_EQ(humanize_file_size(129747), "127 KiB");
	EXPECT_EQ(humanize_file_size(97379112), "92.9 MiB");
	EXPECT_EQ(humanize_file_size(1.423 * (1ULL << 10)), "1.4 KiB");
	EXPECT_EQ(humanize_file_size(14.23 * (1ULL << 10)), "14.2 KiB");
	EXPECT_EQ(humanize_file_size(142.3 * (1ULL << 10)), "142 KiB");
	EXPECT_EQ(humanize_file_size(1.423 * (1ULL << 20)), "1.4 MiB");
	EXPECT_EQ(humanize_file_size(14.23 * (1ULL << 20)), "14.2 MiB");
	EXPECT_EQ(humanize_file_size(142.3 * (1ULL << 20)), "142 MiB");
	EXPECT_EQ(humanize_file_size(1.423 * (1ULL << 30)), "1.4 GiB");
	EXPECT_EQ(humanize_file_size(14.23 * (1ULL << 30)), "14.2 GiB");
	EXPECT_EQ(humanize_file_size(142.3 * (1ULL << 30)), "142 GiB");
	EXPECT_EQ(humanize_file_size(1.423 * (1ULL << 40)), "1.4 TiB");
	EXPECT_EQ(humanize_file_size(14.23 * (1ULL << 40)), "14.2 TiB");
	EXPECT_EQ(humanize_file_size(142.3 * (1ULL << 40)), "142 TiB");
	EXPECT_EQ(humanize_file_size(1.423 * (1ULL << 50)), "1.4 PiB");
	EXPECT_EQ(humanize_file_size(14.23 * (1ULL << 50)), "14.2 PiB");
	EXPECT_EQ(humanize_file_size(142.3 * (1ULL << 50)), "142 PiB");
	EXPECT_EQ(humanize_file_size(1.423 * (1ULL << 60)), "1.4 EiB");
	EXPECT_EQ(humanize_file_size(14.23 * (1ULL << 60)), "14.2 EiB");

	EXPECT_EQ(humanize_file_size((1ULL << 10) - 1), "1023 bytes");
	EXPECT_EQ(humanize_file_size((1ULL << 10)), "1.0 KiB");
	EXPECT_EQ(humanize_file_size((1ULL << 20) - 1), "1024 KiB");
	EXPECT_EQ(humanize_file_size((1ULL << 20)), "1.0 MiB");
	EXPECT_EQ(humanize_file_size((1ULL << 30) - 1), "1024 MiB");
	EXPECT_EQ(humanize_file_size((1ULL << 30)), "1.0 GiB");
	EXPECT_EQ(humanize_file_size((1ULL << 40) - 1), "1024 GiB");
	EXPECT_EQ(humanize_file_size((1ULL << 40)), "1.0 TiB");
	EXPECT_EQ(humanize_file_size((1ULL << 50) - 1), "1024 TiB");
	EXPECT_EQ(humanize_file_size((1ULL << 50)), "1.0 PiB");
	EXPECT_EQ(humanize_file_size((1ULL << 60) - 1), "1024 PiB");
	EXPECT_EQ(humanize_file_size((1ULL << 60)), "1.0 EiB");

	EXPECT_EQ(humanize_file_size(102349ULL - 1), "99.9 KiB");
	EXPECT_EQ(humanize_file_size(102349ULL), "100 KiB");
	EXPECT_EQ(humanize_file_size(104805172ULL - 1), "99.9 MiB");
	EXPECT_EQ(humanize_file_size(104805172ULL), "100 MiB");
	EXPECT_EQ(humanize_file_size(107320495309ULL - 1), "99.9 GiB");
	EXPECT_EQ(humanize_file_size(107320495309ULL), "100 GiB");
	EXPECT_EQ(humanize_file_size(109896187196212ULL - 1), "99.9 TiB");
	EXPECT_EQ(humanize_file_size(109896187196212ULL), "100 TiB");
	EXPECT_EQ(humanize_file_size(112533595688920269ULL - 1), "99.9 PiB");
	EXPECT_EQ(humanize_file_size(112533595688920269ULL), "100 PiB");
}
