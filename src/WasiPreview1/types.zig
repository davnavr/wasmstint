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
