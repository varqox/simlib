#pragma once

#include <optional>
#include <simlib/file_path.hh>
#include <simlib/sandbox/sandbox.hh>
#include <simlib/sim/judge/language_suite/fully_compiled_language.hh>
#include <simlib/slice.hh>
#include <string_view>

namespace sim::judge::language_suite {

class Rust final : public FullyCompiledLanguage {
    std::string_view edition_str;

    [[nodiscard]] sandbox::Result run_compiler(
        Slice<std::string_view> extra_args,
        std::optional<int> compilation_errors_fd,
        Slice<sandbox::RequestOptions::LinuxNamespaces::Mount::Operation> mount_ops,
        const CompileOptions& options
    );

public:
    enum class Edition {
        ed2018,
        ed2021,
        ed2024,
    };

    explicit Rust(Edition edition);

protected:
    sandbox::Result is_supported_impl(const CompileOptions& options) final;

    sandbox::Result compile_impl(
        FilePath source,
        FilePath executable,
        int compilation_errors_fd,
        const CompileOptions& options
    ) final;
};

} // namespace sim::judge::language_suite
