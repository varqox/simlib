#pragma once

#include <simlib/sandbox/sandbox.hh>
#include <simlib/sim/judge/language_suite/fully_interpreted_language.hh>
#include <simlib/slice.hh>
#include <string_view>

namespace sim::judge::language_suite {

class Awk final : public FullyInterpretedLanguage {
public:
    Awk();

    void async_run(
        Slice<std::string_view> args,
        const RunOptions& options,
        Slice<sandbox::RequestOptions::LinuxNamespaces::Mount::Operation> mount_ops
    ) final;
};

} // namespace sim::judge::language_suite
