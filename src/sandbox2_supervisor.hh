#pragma once

#include "simlib/file_descriptor.hh"
#include "simlib/sandbox2.hh"

namespace sandbox::supervisor {

[[noreturn]] void execute(const Options& options, FileDescriptor error_fd) noexcept;

} // namespace sandbox::supervisor
