#include "../include/config_file.h"
#include "../include/debug.h"
#include "../include/filesystem.h"
#include "../include/sim_problem.h"
#include "../include/string.h"
#include "../include/utility.h"

#include <cerrno>
#include <cmath>

#define foreach(i,x) for (__typeof(x.begin()) i = x.begin(), \
	i ##__end = x.end(); i != i ##__end; ++i)

using std::string;
using std::vector;

string ProblemConfig::dump() const {
	string res;
	append(res) << "name: " << makeSafeString(name) << '\n'
		<< "tag: " << makeSafeString(tag) << '\n'
		<< "statement: " << makeSafeString(statement) << '\n'
		<< "checker: " << makeSafeString(checker) << '\n'
		<< "memory_limit: " << toString(memory_limit) << '\n'
		<< "main_solution: " << makeSafeString(main_solution) << '\n';

	// Solutions
	res += "solutions: [";
	foreach (i, solutions)
		append(res) << (i == solutions.begin() ? "" : ", ")
			<< makeSafeString(*i);
	res += "]\n";

	// Tests
	res += "tests: [";
	bool first_test = true;
	foreach (i, test_groups) {
		if (i->tests.empty())
			continue;

		if (first_test)
			first_test = false;
		else
			res += ",\n";
		append(res) << "\n\t'" << i->tests[0].name << ' '
			<< usecToSecStr(i->tests[0].time_limit, 2) << ' '
			<< toString(i->points) << '\'';

		for (vector<Test>::const_iterator j = ++i->tests.begin(),
				end = i->tests.end(); j != end; ++j)
			append(res) << ",\n\t'" << j->name << ' '
				<< usecToSecStr(j->time_limit, 2) << '\'';
	}
	res += "\n]\n";
	return res;
}

void ProblemConfig::loadConfig(string package_path) {
	// Append slash to package_path
	if (package_path.size() > 0 && *--package_path.end() != '/')
		package_path += '/';

	ConfigFile config;
	config.addVar("name");
	config.addVar("tag");
	config.addVar("statement");
	config.addVar("checker");
	config.addVar("memory_limit");
	config.addVar("solutions");
	config.addVar("main_solution");
	config.addVar("tests");

	config.loadConfigFromFile(package_path + "config.conf");

	// Problem name
	name = config.getString("name");
	if (name.empty())
		throw std::runtime_error("config.conf: Missing problem name");

	// Problem tag
	tag = config.getString("tag");
	if (tag.size() > 4) // Invalid tag
		throw std::runtime_error("conf.cfg: Problem tag too long "
			"(max 4 characters)");

	// Statement
	statement = config.getString("statement");
	if (statement.size()) {
		if (statement.find('/') < statement.size())
			throw std::runtime_error("config.conf: statement cannot contain "
				"'/' character");

		if (access(package_path + "doc/" + statement, F_OK) == -1)
			throw std::runtime_error("config.conf: invalid statement '" +
				statement + "': 'doc/" + statement + "' - " + strerror(errno));
	}

	// Checker
	checker = config.getString("checker");
	if (checker.size()) {
		if (checker.find('/') < checker.size())
			throw std::runtime_error("config.conf: checker cannot contain "
				"'/' character");

		if (access(package_path + "check/" + checker, F_OK) == -1)
			throw std::runtime_error("config.conf: invalid checker '" +
				checker + "': 'check/" + checker + "' - " + strerror(errno));
	}

	// Solutions
	solutions = config.getArray("solutions");
	foreach (i, solutions) {
		if (i->find('/') < i->size())
			throw std::runtime_error("config.conf: solution cannot contain "
				"'/' character");

		if (access(package_path + "prog/" + *i, F_OK) == -1)
			throw std::runtime_error("config.conf: invalid solution '" +
				*i + "': 'prog/" + *i + "' - " + strerror(errno));
	}

	// Main solution
	main_solution = config.getString("main_solution");
	if (std::find(solutions.begin(), solutions.end(), main_solution) ==
			solutions.end())
		throw std::runtime_error("config.conf: main_solution has to be set in "
			"solutions");

	// Memory limit (in kB)
	if (!config.isSet("memory_limit"))
		throw std::runtime_error("config.conf: missing memory limit\n");

	if (strtou(config.getString("memory_limit"), &memory_limit) <= 0)
		throw std::runtime_error("config.conf: invalid memory limit\n");

	// Tests
	test_groups.clear();
	vector<string> tests = config.getArray("tests");
	foreach (i, tests) {
		*i += '\0'; // i->data() is now null-terminated
		Test test;

		// Test name
		size_t pos = 0;
		while (pos < i->size() && !isspace((*i)[pos]))
			++pos;
		test.name.assign(*i, 0, pos);

		if (test.name.find('/') != string::npos)
			throw std::runtime_error("config.conf: test name cannot contain "
				"'/' character");

		if (access(package_path + "tests/" + test.name + ".in", F_OK) == -1)
			throw std::runtime_error("config.conf: invalid test name '" +
				test.name + "': 'tests/" + test.name + ".in' - " +
				strerror(errno));

		// Time limit
		errno = 0;
		char *ptr;
		test.time_limit = round(strtod(i->data() + pos, &ptr) * 1000000LL);
		if (errno)
			throw std::runtime_error("config.conf: " + test.name +
				": invalid time limit");
		pos = ptr - i->data();
		i->erase(i->size() - 1); // Remove trailing '\0'

		while (pos < i->size() && isspace((*i)[pos]))
			++pos;

		// Points
		if (pos < i->size()) {
			test_groups.push_back(Group());

			// Remove trailing white spaces
			size_t end = i->size();
			while (end > pos && isspace((*i)[end - 1]))
				--end;

			if (strtoi(*i, &test_groups.back().points, pos, end) <= 0)
				throw std::runtime_error("config.conf: " + test.name +
					": invalid points");
		}

		test_groups.back().tests.push_back(test);
	}
}

string ProblemConfig::makeSafeString(const StringView &str) {
	if (ConfigFile::isStringLiteral(str))
		return str.to_string();

	if (str.find('\n') != StringView::npos)
		return '"' + ConfigFile::safeDoubleQuotedString(str) + '"';

	return '\'' + ConfigFile::safeSingleQuotedString(str) + '\'';
}

string getTag(const string& str) {
	string tag;
	for (size_t i = 0, len = str.size(); tag.size() < 3 && i < len; ++i)
		if (!isblank(str[i]))
			tag += tolower(str[i]);

	return tag;
}