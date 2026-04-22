#include <stdint.h>

/// Defined to avoid "undefined symbol" linker errors.
///
/// Changes to codegen in Zig 0.16.0 seem to cause problems with `export threadlocal` variables
/// so this variable is defined in C instead. Specifically, the emitted LLVM IR seems to be for an
/// `alias` of an `internal thread_local` instead of a `dso_local thread_local` in prior versions.
///
/// https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-stack-depth
_Thread_local uintptr_t __sancov_lowest_stack;
