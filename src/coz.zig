//! Zig support for the [`coz` Causal Profiler].
//!
//! This module is a translation of [`coz.h`].
//!
//! [`coz.h`]: https://github.com/plasma-umass/coz/blob/674e4e7e3784dd554d3bc7e7c63cd7b2e20738ac/include/coz.h

// Based on code from `coz`
//
// Copyright (c) 2015, Charlie Curtsinger and Emery Berger,
// University of Massachusetts Amherst
//
// For more information, see https://github.com/plasma-umass/coz/blob/master/LICENSE.md

const coz_supported = builtin.link_libc and builtin.os.tag == .linux;

// If this needs to get turned into a library/package/whatever, uncomment this:

// pub const Options = struct {
//     /// Enables `coz` profiling code, only when building on Linux.
//     ///
//     /// On other platforms (where this value is ignored) or when disabled, and all `coz` operations
//     /// are no-ops.
//     enabled: bool = false,
// };
// const chosen_options: Options = if (@hasField(root, "coz_options")) root.coz_options else Options{};

const enabled = @import("options").enabled;

const CounterType = enum(c_int) {
    throughput = 1,
    begin = 2,
    end = 3,
};

// Declare `dlsym` as a weak reference so `libdl` isn't required
const dlsym = @extern(
    ?*const fn (handle: ?*anyopaque, symbol: [*:0]const u8) callconv(.c) ?*anyopaque,
    std.builtin.ExternOptions{
        .name = "dlsym",
        .linkage = .weak,
    },
);

const GetCounterFn = *const fn (@"type": CounterType, name: [*:0]const u8) callconv(.c) ?*Counter;

const Counter = extern struct {
    count: usize,
    backoff: usize,

    var coz_get_counter: ?GetCounterFn = null;

    fn initCozGetCounter() void {
        if (dlsym) |dlsym_fn| {
            const known_rtld_default = builtin.abi.isGnu() or builtin.abi.isMusl();

            // Could maybe `dlopen(null, LAZY)` if hardcoded `rtld_default` is unavailable
            const rtld_default: ?*anyopaque = if (builtin.link_libc and known_rtld_default)
                @ptrFromInt(0)
            else if (!builtin.link_libc)
                @compileError("libc is required when coz is enabled")
            else
                @compileError("please provide hardcoded RTLD_DEFAULT value from libc for " ++
                    @tagName(builtin.target.cpu.arch) ++ "-linux-" ++
                    @tagName(builtin.target.abi));

            coz_get_counter = @ptrCast(dlsym_fn(rtld_default, "_coz_get_counter"));
        }
    }

    var init_get_counter = std.once(initCozGetCounter);

    /// Locates and invokes the `_coz_get_counter` provided via `LD_PRELOAD` when run under `coz`.
    ///
    /// Equivalent of the [`_call_coz_get_counter()`] function.
    ///
    /// [`_call_coz_get_counter()`]: https://github.com/plasma-umass/coz/blob/674e4e7e3784dd554d3bc7e7c63cd7b2e20738ac/include/coz.h#L44
    fn get(@"type": CounterType, name: [*:0]const u8) ?*Counter {
        init_get_counter.call();
        return if (coz_get_counter) |get_counter|
            get_counter(@"type", name)
        else
            null; // profiler not found
    }
};

/// Initializes and increments a counter.
///
/// Equivalent of the [`COZ_INCREMENT_COUNTER`] macro.
///
/// [`COZ_INCREMENT_COUNTER`]: https://github.com/plasma-umass/coz/blob/674e4e7e3784dd554d3bc7e7c63cd7b2e20738ac/include/coz.h#L66
pub inline fn incrementCounter(comptime @"type": CounterType, comptime name: [:0]const u8) void {
    const state = struct {
        var init = std.once(initCounter);

        // This should be a unique variable for every unique `name`.
        var counter: ?*Counter = null;

        fn initCounter() void {
            counter = Counter.get(@"type", name);
        }
    };

    if (comptime (!enabled or builtin.os.tag != .linux)) {
        return;
    }

    state.init.call();

    if (state.counter) |counter| {
        _ = @atomicRmw(usize, &counter.count, .Add, 1, .monotonic);
    }
}

/// Equivalent of the [`COZ_PROGRESS_NAMED`] macro.
///
/// [`COZ_PROGRESS_NAMED`]: https://github.com/plasma-umass/coz/blob/674e4e7e3784dd554d3bc7e7c63cd7b2e20738ac/include/coz.h#L83
pub inline fn progressNamed(comptime name: [:0]const u8) void {
    incrementCounter(.throughput, name);
}

/// Equivalent of the [`COZ_PROGRESS`] macro.
///
/// # Usage
///
/// ```
/// coz.progress(@src());
/// ```
///
/// [`COZ_PROGRESS`]: https://github.com/plasma-umass/coz/blob/674e4e7e3784dd554d3bc7e7c63cd7b2e20738ac/include/coz.h#L85
pub inline fn progress(comptime src: std.builtin.SourceLocation) void {
    progressNamed(std.fmt.comptimePrint("{s}:{d}", .{ src.file, src.line }));
}

/// Equivalent of the [`COZ_BEGIN`] macro.
///
/// [`COZ_BEGIN`]: https://github.com/plasma-umass/coz/blob/674e4e7e3784dd554d3bc7e7c63cd7b2e20738ac/include/coz.h#L86
pub inline fn begin(comptime name: [:0]const u8) Transaction(name) {
    incrementCounter(.begin, name);
    var transaction = Transaction(name){ .lock = .{} };
    transaction.lock.lock();
    return transaction;
}

pub fn Transaction(comptime name: [:0]const u8) type {
    return struct {
        lock: std.debug.SafetyLock,

        /// Equivalent of the [`COZ_END`] macro.
        ///
        /// Works nicely with Zig's `defer`.
        ///
        /// [`COZ_END`]: https://github.com/plasma-umass/coz/blob/674e4e7e3784dd554d3bc7e7c63cd7b2e20738ac/include/coz.h#L87
        pub inline fn end(transaction: *@This()) void {
            transaction.lock.unlock();
            incrementCounter(.end, name);
        }
    };
}

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root");
