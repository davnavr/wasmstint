/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#size
pub const Size = u32;

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#filesize
pub const FileSize = packed struct(u64) { bytes: u64 };

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#timestamp
pub const Timestamp = packed struct(u64) { ns: u64 };

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#clockid
pub const ClockId = enum(u32) {
    /// The clock measuring real time. Time value zero corresponds with `1970-01-01T00:00:00Z`.
    realtime,
    /// The store-wide monotonic clock, which is defined as a clock measuring real time, whose
    /// value cannot be adjusted and which cannot have negative clock jumps.
    ///
    /// The epoch of this clock is undefined. The absolute time value of this clock therefore has
    /// no meaning.
    monotonic,

    // Apparently these were never widely supported

    /// The CPU-time clock associated with the current process.
    process_cputime_id,
    /// The CPU-time clock associated with the current thread.
    thread_cputime_id,
    _,
};

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#prestat
pub const Prestat = extern struct {
    /// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#preopentype
    pub const Type = enum(u8) { dir };

    tag: Type,
    payload: Payload,

    pub const Payload = extern union {
        dir: Dir,
    };

    /// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#prestat_dir
    pub const Dir = extern struct {
        pr_name_len: Size,
    };

    pub fn init(comptime tag: Type, payload: @FieldType(Payload, @tagName(tag))) Prestat {
        return .{
            .tag = tag,
            .payload = @unionInit(Payload, @tagName(tag), payload),
        };
    }

    comptime {
        std.debug.assert(@sizeOf(Prestat) == 8);
    }
};

const std = @import("std");
