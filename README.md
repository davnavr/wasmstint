# `wasmstint`

A *st*ackless, in-place *int*erpreter for [WebAssembly] written in [Zig].

Inspired by the following projects:

- [`piccolo`](https://github.com/kyren/piccolo), a stackless Lua interpreter
- ["A fast in-place interpreter for WebAssembly" (2022)](https://doi.org/10.5281/zenodo.7093079),
  which provides the design and data structures that make fast in-place interpretation possible.

Note that `wasmstint` is still in development and it's API is **very** unstable!

# Supported Features

- Fuel-metering (like all the other WASM runtimes)
- Full control over memory allocations thanks to Zig's `std.mem.Allocator` API.
- Passes specification testsuite tests (for supported WASM proposals)

## WASM Proposal Support

`wasmstint` currently supports and passes test for WebAssembly 2.0 as well as few additional
proposals:

- [Mutable Globals](https://github.com/WebAssembly/mutable-global)
- [Non-Trapping Float-to-Int Conversions](https://github.com/WebAssembly/nontrapping-float-to-int-conversions)
- [Sign Extension Operators](https://github.com/WebAssembly/sign-extension-ops)
- [Multi-Value](https://github.com/WebAssembly/multi-value)
- [Reference Types](https://github.com/WebAssembly/reference-types)
- [Bulk Memory Operations](https://github.com/WebAssembly/bulk-memory-operations)
- [Fixed-Width SIMD](https://github.com/webassembly/simd)
- [Tail Call](https://github.com/WebAssembly/tail-call)
- [Extended Constant Expressions](https://github.com/WebAssembly/extended-const)

Currently, support for all of these features is always enabled. Disabling of features at compile-
time may be added in the future.

# WASI support

`wasmstint` currently has incomplete support for `wasi_snapshot_preview1` applications.

To run the WASI preview 1 interpreter, run the following command:

```sh
zig build run-wasip1 -- -m /path/to/application.wasm --dir /path/to/dir guest/name rw
```

Due to the way WASI sandboxing is implemented on Windows, building the WASI interpreter requires
targeting at least Windows 10 version 1607 or higher.

```sh
zig build run-wasip1 -Dtarget=x86_64-windows.win10_rs1
```

# Building

Run `zig build --help` for more information.

`wasmstint` is currently only known to build and run its tests successfully for the `x86_64-linux`
and `x86_64-windows` targets. Building for 32-bit targets is likely to result in compile errors.
Due to the use of tail calls in `wasmstint`, building for non-`x86_64` targets also currently
requires the LLVM backend, set with the `-Duse-llvm=always` build option.

Additionally, big-endian targets are not supported at all.

[WebAssembly]: https://webassembly.org/
[Zig]: https://ziglang.org/
