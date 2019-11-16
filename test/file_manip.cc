#include "../include/file_manip.hh"
#include "../include/defer.hh"
#include "../include/directory.hh"
#include "../include/file_contents.hh"
#include "../include/file_descriptor.hh"
#include "../include/file_info.hh"
#include "../include/opened_temporary_file.hh"
#include "../include/random.hh"
#include "../include/temporary_directory.hh"

#include <gtest/gtest.h>

using std::max;
using std::pair;
using std::string;
using std::vector;

static mode_t get_file_permissions(FilePath path) {
	struct stat64 st;
	EXPECT_EQ(stat64(path, &st), 0);
	return st.st_mode & ACCESSPERMS;
}

static string some_random_data(size_t len) {
	string data(len, '0');
	read_from_dev_urandom(data.data(), data.size());
	return data;
}

TEST(DISABLED_file_manip, remove_r) { // TODO:
}

TEST(file_manip, mkdir) {
	TemporaryDirectory tmp_dir("/tmp/filesystem-test.XXXXXX");
	EXPECT_EQ(mkdir(concat(tmp_dir.path(), "a")), 0);
	EXPECT_TRUE(is_directory(concat(tmp_dir.path(), "a")));

	EXPECT_EQ(mkdir(concat(tmp_dir.path(), "a/b")), 0);
	EXPECT_TRUE(is_directory(concat(tmp_dir.path(), "a/b")));

	EXPECT_EQ(mkdir(concat(tmp_dir.path(), "x/d")), -1);
	EXPECT_FALSE(is_directory(concat(tmp_dir.path(), "x")));
}

TEST(file_manip, mkdir_r) {
	TemporaryDirectory tmp_dir("/tmp/filesystem-test.XXXXXX");
	EXPECT_EQ(mkdir_r(concat_tostr(tmp_dir.path(), "x/d")), 0);
	EXPECT_TRUE(is_directory(concat(tmp_dir.path(), "x")));
	EXPECT_TRUE(is_directory(concat(tmp_dir.path(), "x/d")));
}

TEST(file_manip, remove_dir_contents) {
	TemporaryDirectory tmp_dir("/tmp/filesystem-test.XXXXXX");

	FileDescriptor(concat(tmp_dir.path(), "a"), O_CREAT);
	FileDescriptor(concat(tmp_dir.path(), "b"), O_CREAT);
	FileDescriptor(concat(tmp_dir.path(), "c"), O_CREAT);
	FileDescriptor(concat(tmp_dir.path(), "abc"), O_CREAT);
	FileDescriptor(concat(tmp_dir.path(), "xyz"), O_CREAT);
	stdlog(mkdir_r(concat_tostr(tmp_dir.path(), "k/l/m/nn/")), errmsg());
	EXPECT_EQ(mkdir_r(concat_tostr(tmp_dir.path(), "k/l/m/nn/")), 0);
	FileDescriptor(concat(tmp_dir.path(), "k/l/m/nn/x"), O_CREAT);
	FileDescriptor(concat(tmp_dir.path(), "k/l/m/x"), O_CREAT);
	FileDescriptor(concat(tmp_dir.path(), "k/l/x"), O_CREAT);
	FileDescriptor(concat(tmp_dir.path(), "k/x"), O_CREAT);

	EXPECT_EQ(remove_dir_contents(tmp_dir.path()), 0);

	for_each_dir_component(tmp_dir.path(),
	                       [](dirent* f) { ADD_FAILURE() << f->d_name; });
}

TEST(file_manip, create_subdirectories) {
	TemporaryDirectory tmp_dir("/tmp/filesystem-test.XXXXXX");

	auto file_path = concat(tmp_dir.path(), "a/b/c/d/file.txt");
	auto dir_path = concat(tmp_dir.path(), "a/b/c/d/");

	EXPECT_EQ(create_subdirectories(file_path), 0);
	EXPECT_TRUE(path_exists(dir_path));
	for_each_dir_component(dir_path,
	                       [](dirent* f) { ADD_FAILURE() << f->d_name; });
	EXPECT_FALSE(path_exists(file_path));

	EXPECT_EQ(remove_dir_contents(tmp_dir.path()), 0);
	EXPECT_EQ(create_subdirectories(dir_path), 0);
	EXPECT_TRUE(path_exists(dir_path));
	for_each_dir_component(dir_path,
	                       [](dirent* f) { ADD_FAILURE() << f->d_name; });
}

TEST(file_manip, blast) {
	OpenedTemporaryFile a("/tmp/filesystem-test.XXXXXX");
	OpenedTemporaryFile b("/tmp/filesystem-test.XXXXXX");

	string data = some_random_data(1 << 20);
	write_all_throw(a, data);

	EXPECT_EQ(get_file_size(a.path()), data.size());
	EXPECT_EQ(get_file_size(b.path()), 0);

	EXPECT_EQ(lseek(a, 0, SEEK_SET), 0);
	EXPECT_EQ(blast(a, b), 0);

	EXPECT_EQ(get_file_size(a.path()), data.size());
	EXPECT_EQ(get_file_size(b.path()), data.size());

	string b_data = get_file_contents(b.path());
	EXPECT_EQ(data.size(), b_data.size());
	EXPECT_TRUE(data == b_data);

	string str = "abcdefghij";
	EXPECT_EQ(pwrite(a, str.data(), str.size(), 0), str.size());
	string other = "0123456789";
	EXPECT_EQ(pwrite(b, other.data(), other.size(), 0), other.size());

	EXPECT_EQ(lseek(a, 3, SEEK_SET), 3);
	EXPECT_EQ(ftruncate(a, 6), 0);
	EXPECT_EQ(lseek(b, 1, SEEK_SET), 1);

	EXPECT_EQ(blast(a, b), 0);
	EXPECT_EQ(get_file_size(b.path()), data.size());
	EXPECT_EQ(pread(b, other.data(), other.size(), 0), other.size());
	EXPECT_EQ(other, "0def456789");

	EXPECT_EQ(blast(a, b), 0); // Nothing should happen now
	EXPECT_EQ(get_file_size(b.path()), data.size());
	EXPECT_EQ(pread(b, other.data(), other.size(), 0), other.size());
	EXPECT_EQ(other, "0def456789");

	// Copying from already read out fd is no-op for dest fd
	EXPECT_EQ(blast(a, -1), 0);

	EXPECT_EQ(blast(-1, b), -1);
	EXPECT_EQ(blast(b, -1), -1);
	EXPECT_EQ(get_file_size(b.path()), data.size());
}

TEST(file_manip, copy) {
	TemporaryDirectory tmp_dir("/tmp/filesystem-test.XXXXXX");
	OpenedTemporaryFile a("/tmp/filesystem-test.XXXXXX");

	string data = some_random_data(1 << 18);
	write_all_throw(a, data);

	string bigger_data = some_random_data(1 << 19);
	string smaller_data = some_random_data(1 << 17);

	std::set<string> allowed_files;
	auto check_allowed_files = [&](size_t line) {
		size_t k = 0;
		for_each_dir_component(tmp_dir.path(), [&](dirent* f) {
			++k;
			if (allowed_files.count(concat_tostr(tmp_dir.path(), f->d_name)) ==
			    0) {
				ADD_FAILURE() << f->d_name << " (at line: " << line << ')';
			}
		});
		EXPECT_EQ(k, allowed_files.size()) << " (at line: " << line << ')';
	};

	EXPECT_EQ(get_file_size(a.path()), data.size());
	check_allowed_files(__LINE__);

	string b_path = concat_tostr(tmp_dir.path(), "bbb");
	allowed_files.emplace(b_path);
	EXPECT_EQ(::copy(a.path(), b_path, S_0644), 0);
	EXPECT_EQ(get_file_size(b_path), data.size());
	EXPECT_TRUE(get_file_contents(b_path) == data);
	EXPECT_EQ(get_file_permissions(b_path), S_0644);
	check_allowed_files(__LINE__);

	string c_path = concat_tostr(tmp_dir.path(), "ccc");
	allowed_files.emplace(c_path);
	EXPECT_EQ(::copy(a.path(), c_path, S_0755), 0);
	EXPECT_EQ(get_file_size(c_path), data.size());
	EXPECT_TRUE(get_file_contents(c_path) == data);
	EXPECT_EQ(get_file_permissions(c_path), S_0755);
	check_allowed_files(__LINE__);

	EXPECT_EQ(lseek(a, 0, SEEK_SET), 0);
	write_all_throw(a, bigger_data);
	EXPECT_EQ(::copy(a.path(), b_path, S_0755), 0);
	EXPECT_EQ(get_file_size(b_path), bigger_data.size());
	EXPECT_TRUE(get_file_contents(b_path) == bigger_data);
	EXPECT_EQ(get_file_permissions(b_path), S_0644);
	check_allowed_files(__LINE__);

	EXPECT_EQ(lseek(a, 0, SEEK_SET), 0);
	write_all_throw(a, smaller_data);
	EXPECT_EQ(ftruncate(a, smaller_data.size()), 0);

	EXPECT_EQ(::copy(a.path(), c_path, S_0644), 0);
	EXPECT_EQ(get_file_size(c_path), smaller_data.size());
	EXPECT_TRUE(get_file_contents(c_path) == smaller_data);
	EXPECT_EQ(get_file_permissions(c_path), S_0755);
	check_allowed_files(__LINE__);
}

TEST(file_manip, copy_r) {
	TemporaryDirectory tmp_dir("/tmp/filesystem-test.XXXXXX");

	struct FileInfo {
		string path;
		string data;

		bool operator<(const FileInfo& fi) const {
			return pair(path, data) < pair(fi.path, fi.data);
		}

		bool operator==(const FileInfo& fi) const {
			return (path == fi.path and data == fi.data);
		}
	};

	vector<FileInfo> orig_files = {
	   {"a", some_random_data(1023)},
	   {"b", some_random_data(1024)},
	   {"c", some_random_data(1025)},
	   {"dir/a", some_random_data(1023)},
	   {"dir/aa", some_random_data(100000)},
	   {"dir/b", some_random_data(1024)},
	   {"dir/bb", some_random_data(100000)},
	   {"dir/c", some_random_data(1025)},
	   {"dir/cc", some_random_data(100000)},
	   {"dir/dir/a", some_random_data(1023)},
	   {"dir/dir/aa", some_random_data(100000)},
	   {"dir/dir/b", some_random_data(1024)},
	   {"dir/dir/bb", some_random_data(100000)},
	   {"dir/dir/c", some_random_data(1025)},
	   {"dir/dir/cc", some_random_data(100000)},
	   {"dir/dir/xxx/a", some_random_data(1023)},
	   {"dir/dir/xxx/aa", some_random_data(100000)},
	   {"dir/dir/xxx/b", some_random_data(1024)},
	   {"dir/dir/xxx/bb", some_random_data(100000)},
	   {"dir/dir/xxx/c", some_random_data(1025)},
	   {"dir/dir/xxx/cc", some_random_data(100000)},
	   {"dir/dur/a", some_random_data(1023)},
	   {"dir/dur/aa", some_random_data(100000)},
	   {"dir/dur/b", some_random_data(1024)},
	   {"dir/dur/bb", some_random_data(100000)},
	   {"dir/dur/c", some_random_data(1025)},
	   {"dir/dur/cc", some_random_data(100000)},
	   {"dir/dur/xxx/a", some_random_data(1023)},
	   {"dir/dur/xxx/aa", some_random_data(100000)},
	   {"dir/dur/xxx/b", some_random_data(1024)},
	   {"dir/dur/xxx/bb", some_random_data(100000)},
	   {"dir/dur/xxx/c", some_random_data(1025)},
	   {"dir/dur/xxx/cc", some_random_data(100000)},
	};

	throw_assert(is_sorted(orig_files));

	for (auto& [path, data] : orig_files) {
		auto full_path = concat(tmp_dir.path(), path);
		EXPECT_EQ(create_subdirectories(full_path), 0);
		put_file_contents(full_path, data);
	}

	auto dump_files = [&](FilePath path) {
		InplaceBuff<PATH_MAX> prefix = {path, '/'};

		vector<FileInfo> res;
		InplaceBuff<PATH_MAX> curr_path;
		auto process_dir = [&](auto& self) -> void {
			for_each_dir_component(
			   concat(prefix, curr_path), [&](dirent* file) {
				   Defer undoer = [&, old_len = curr_path.size] {
					   curr_path.size = old_len;
				   };
				   curr_path.append(file->d_name);
				   if (is_directory(concat(prefix, curr_path))) {
					   curr_path.append('/');
					   self(self);
				   } else {
					   res.push_back(
					      {curr_path.to_string(),
					       get_file_contents(concat(prefix, curr_path))});
				   }
			   });
		};

		process_dir(process_dir);
		sort(res);
		return res;
	};

	auto orig_files_slice = [&](StringView prefix) {
		vector<FileInfo> res;
		for (auto& [path, data] : orig_files) {
			if (has_prefix(path, prefix))
				res.push_back({path.substr(prefix.size()), data});
		}

		return res;
	};

	auto check_equality = [&](const vector<FileInfo>& fir,
	                          const vector<FileInfo>& sec, size_t line) {
		size_t len = max(fir.size(), sec.size());
		for (size_t i = 0; i < len; ++i) {
			if (i < fir.size() and i < sec.size()) {
				if (not(fir[i] == sec[i]))
					ADD_FAILURE_AT(__FILE__, line)
					   << "Unequal files:\t" << fir[i].path << "\t"
					   << sec[i].path;

				continue;
			} else if (i < fir.size()) {
				ADD_FAILURE_AT(__FILE__, line)
				   << "Extra file in fir:\t" << fir[i].path;
			} else {
				ADD_FAILURE_AT(__FILE__, line)
				   << "Extra file in sec:\t" << sec[i].path;
			}
		}
	};

	// Typical two levels
	{
		TemporaryDirectory dest_dir("/tmp/filesystem-test.XXXXXX");
		auto dest_path = concat(dest_dir.path(), "dest/dir");
		EXPECT_EQ(copy_r(concat(tmp_dir.path(), "dir"), dest_path), 0);
		check_equality(dump_files(dest_path), orig_files_slice("dir/"),
		               __LINE__);
	}

	// Typical one level
	{
		TemporaryDirectory dest_dir("/tmp/filesystem-test.XXXXXX");
		auto dest_path = concat(dest_dir.path(), "dest");
		stdlog(copy_r(concat(tmp_dir.path(), "dir"), dest_path), errmsg());
		EXPECT_EQ(copy_r(concat(tmp_dir.path(), "dir"), dest_path), 0);
		check_equality(dump_files(dest_path), orig_files_slice("dir/"),
		               __LINE__);
	}

	// Typical into existing
	{
		TemporaryDirectory dest_dir("/tmp/filesystem-test.XXXXXX");
		auto dest_path = dest_dir.path();
		EXPECT_EQ(copy_r(concat(tmp_dir.path(), "dir"), dest_path), 0);
		check_equality(dump_files(dest_path), orig_files_slice("dir/"),
		               __LINE__);
	}

	// Without creating subdirs into existing
	{
		TemporaryDirectory dest_dir("/tmp/filesystem-test.XXXXXX");
		auto dest_path = dest_dir.path();
		EXPECT_EQ(copy_r(concat(tmp_dir.path(), "dir"), dest_path, false), 0);
		check_equality(dump_files(dest_path), orig_files_slice("dir/"),
		               __LINE__);
	}

	// Without creating subdirs one level
	{
		TemporaryDirectory dest_dir("/tmp/filesystem-test.XXXXXX");
		auto dest_path = concat(dest_dir.path(), "dest/");
		EXPECT_EQ(copy_r(concat(tmp_dir.path(), "dir"), dest_path, false), 0);
		check_equality(dump_files(dest_path), orig_files_slice("dir/"),
		               __LINE__);
	}

	// Without creating subdirs two levels
	{
		TemporaryDirectory dest_dir("/tmp/filesystem-test.XXXXXX");
		auto dest_path = concat(dest_dir.path(), "dest/dir");
		errno = 0;
		EXPECT_EQ(copy_r(concat(tmp_dir.path(), "dir"), dest_path, false), -1);
		EXPECT_EQ(errno, ENOENT);
		EXPECT_FALSE(path_exists(dest_path));
	}
}

TEST(DISABLED_file_manip, move) { // TODO:
}

TEST(DISABLED_file_manip, create_file) { // TODO:
}

TEST(DISABLED_file_manip, FileRemover) { // TODO:
}

TEST(DISABLED_file_manip, DirectoryRemover) { // TODO:
}