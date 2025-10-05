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

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#rights
pub const Rights = packed struct(u64) {
    pub const Valid = packed struct(u30) {
        /// The right to invoke `fd_datasync`.
        ///
        /// If `path_open` is set, includes the right to invoke `path_open` with `fdflags::dsync`.
        fd_datasync: bool = false,
        /// The right to invoke `fd_read` and `sock_recv`.
        ///
        /// If `rights::fd_seek` is set, includes the right to invoke `fd_pread`.
        fd_read: bool = false,
        /// The right to invoke `fd_seek`. This flag implies `rights::fd_tell`.
        fd_seek: bool = false,
        /// The right to invoke `fd_fdstat_set_flags`.
        fd_fdstat_set_flags: bool = false,
        /// The right to invoke `fd_sync`.
        ///
        /// If `path_open` is set, includes the right to invoke
        /// `path_open` with `fdflags::rsync` and `fdflags::dsync`.
        fd_sync: bool = false,
        /// The right to invoke `fd_seek` in such a way that the file offset
        /// remains unaltered (i.e., `whence::cur` with offset zero), or to
        /// invoke `fd_tell`.
        fd_tell: bool = false,
        /// The right to invoke `fd_write` and `sock_send`.
        /// If `rights::fd_seek` is set, includes the right to invoke `fd_pwrite`.
        fd_write: bool = false,
        /// The right to invoke `fd_advise`.
        fd_advise: bool = false,
        /// The right to invoke `fd_allocate`.
        fd_allocate: bool = false,
        /// The right to invoke `path_create_directory`.
        path_create_directory: bool = false,
        /// If `path_open` is set, the right to invoke `path_open` with `oflags::creat`.
        path_create_file: bool = false,
        /// The right to invoke `path_link` with the file descriptor as the
        /// source directory.
        path_link_source: bool = false,
        /// The right to invoke `path_link` with the file descriptor as the
        /// target directory.
        path_link_target: bool = false,
        /// The right to invoke `path_open`.
        path_open: bool = false,
        /// The right to invoke `fd_readdir`.
        fd_readdir: bool = false,
        /// The right to invoke `path_readlink`.
        path_readlink: bool = false,
        /// The right to invoke `path_rename` with the file descriptor as the source directory.
        path_rename_source: bool = false,
        /// The right to invoke `path_rename` with the file descriptor as the target directory.
        path_rename_target: bool = false,
        /// The right to invoke `path_filestat_get`.
        path_filestat_get: bool = false,
        /// The right to change a file's size.
        ///
        /// If `path_open` is set, includes the right to invoke `path_open` with `oflags::trunc`.
        ///
        /// Note: there is no function named `path_filestat_set_size`. This follows POSIX design,
        /// which only has `ftruncate` and does not provide `ftruncateat`.
        /// While such function would be desirable from the API design perspective, there are virtually
        /// no use cases for it since no code written for POSIX systems would use it.
        /// Moreover, implementing it would require multiple syscalls, leading to inferior performance.
        path_filestat_set_size: bool = false,
        /// The right to invoke `path_filestat_set_times`.
        path_filestat_set_times: bool = false,
        /// The right to invoke `fd_filestat_get`.
        fd_filestat_get: bool = false,
        /// The right to invoke `fd_filestat_set_size`.
        fd_filestat_set_size: bool = false,
        /// The right to invoke `fd_filestat_set_times`.
        fd_filestat_set_times: bool = false,
        /// The right to invoke `path_symlink`.
        path_symlink: bool = false,
        /// The right to invoke `path_remove_directory`.
        path_remove_directory: bool = false,
        /// The right to invoke `path_unlink_file`.
        path_unlink_file: bool = false,
        /// If `rights::fd_read` is set, includes the right to invoke `poll_oneoff` to subscribe to
        /// `eventtype::fd_read`.
        ///
        /// If `rights::fd_write` is set, includes the right to invoke `poll_oneoff` to subscribe to
        /// `eventtype::fd_write`.
        poll_fd_readwrite: bool = false,
        /// The right to invoke `sock_shutdown`.
        sock_shutdown: bool = false,
        /// The right to invoke `sock_accept`.
        sock_accept: bool = false,
    };

    valid: Valid = .{},
    padding: u34 = 0,

    fn checkValid(rights: Rights) error{InvalidRightsFlags}!Valid {
        return if (rights.padding == 0) rights.valid else error.InvalidRightsFlags;
    }

    fn assumeValid(rights: Rights) Valid {
        return rights.checkValid() catch unreachable;
    }
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

    pub fn fromZigKind(kind: std.fs.File.Kind) error{UnknownSocketType}!FileType {
        const is_windows = builtin.os.tag == .windows;
        return switch (kind) {
            .block_device => if (!is_windows) .block_device else unreachable,
            .character_device => if (!is_windows) .character_device else unreachable,
            .directory => .directory,
            .named_pipe => if (!is_windows) .unknown else unreachable,
            .sym_link => if (!is_windows) .symbolic_link else unreachable,
            .file => .regular_file,
            .unix_domain_socket => if (!is_windows)
                error.UnknownSocketType
            else
                unreachable,
            .whiteout => if (!is_windows) .unknown else unreachable, // BSD thing
            .door, .event_port => if (builtin.os.tag == .solaris) .unknown else unreachable,
            .unknown => .unknown,
        };
    }
};

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fdflags
pub const FdFlags = packed struct(u16) {
    pub const Valid = packed struct(u5) {
        append: bool,
        dsync: bool,
        nonblock: bool,
        rsync: bool,
        sync: bool,
    };

    valid: Valid,
    padding: u11 = 0,
};

pub const FdStat = extern struct {
    file: File,
    rights_base: Rights,
    rights_inheriting: Rights,

    pub const File = extern struct {
        type: FileType,
        flags: FdFlags,
    };

    comptime {
        std.debug.assert(@sizeOf(FdStat) == 24);
        std.debug.assert(@offsetOf(File, "flags") == 2);
        std.debug.assert(@offsetOf(FdStat, "rights_base") == 8);
    }
};

const std = @import("std");
const builtin = @import("builtin");
