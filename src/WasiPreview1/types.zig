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

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#dircookie
pub const DirCookie = packed struct(u64) {
    n: u64,

    pub const start = DirCookie{ .n = 0 };

    pub fn format(cookie: DirCookie, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        if (cookie.n == start.n) {
            try writer.writeAll("start");
        } else {
            try writer.print("{d}", .{cookie.n});
        }
    }
};

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#inode
pub const INode = packed struct(u64) {
    n: u64,

    pub const HashSeed = enum(u64) { _ };

    /// `inode` numbers exposed to WASI guests are hashed
    pub fn init(seed: HashSeed, n: u64) INode {
        return .{ .n = std.hash.Wyhash.hash(@intFromEnum(seed), std.mem.asBytes(&n)) };
    }
};

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#dirent
pub const DirEnt = extern struct {
    next: DirCookie,
    ino: INode,
    namlen: u32,
    type: FileType,
};

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#filetype
pub const FileType = enum(u8) {
    unknown,
    block_device,
    character_device,
    directory,
    regular_file,
    /// The file descriptor or file refers to a datagram socket.
    socket_dgram,
    /// The file descriptor or file refers to a byte-stream socket.
    socket_stream,
    symbolic_link,
};

const std = @import("std");
