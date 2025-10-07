/// Equivalent of `usize` or `size_t`.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#size
pub const Size = u32;

/// Non-negative file size or length of a region within a file.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#filesize
pub const FileSize = packed struct(u64) { bytes: u64 };

/// Timestamp in nanoseconds.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#timestamp
pub const Timestamp = packed struct(u64) { ns: u64 };

/// Identifiers for clocks.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#clockid
pub const ClockId = enum(u32) {
    /// The clock measuring real time. Time value zero corresponds with `1970-01-01T00:00:00Z`.
    real_time,
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

/// File or memory access pattern advisory information.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#advice
pub const Advice = enum(u8) {
    /// The application has no advice to give on its behavior with respect to the specified data.
    normal,
    /// The application expects to access the specified data sequentially from lower offsets to
    /// higher offsets.
    sequential,
    /// The application expects to access the specified data in a random order.
    random,
    ///  The application expects to access the specified data in the near future.
    will_need,
    /// The application expects that it will not access the specified data in the near future.
    dont_need,
    /// The application expects to access the specified data once and then not reuse it thereafter.
    no_reuse,
};

/// Relative offset within a file.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#filedelta
pub const FileDelta = packed struct(i64) { offset: i64 };

/// The position relative to which to set the offset of the file descriptor.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#whence
pub const Whence = enum(u8) {
    /// Seek relative to start-of-file.
    set,
    /// Seek relative to current position.
    cur,
    /// Seek relative to end-of-file.
    end,
};

fn flagsFormatter(comptime T: type) fn (T, *std.Io.Writer) std.Io.Writer.Error!void {
    return struct {
        fn format(flags: T, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            if (@as(@typeInfo(T).@"struct".backing_integer.?, @bitCast(flags)) == 0) {
                try writer.writeByte('0');
            } else {
                inline for (0.., @typeInfo(T).@"struct".fields) |i, f| {
                    if (@field(flags, f.name)) {
                        if (i > 0) {
                            try writer.writeAll("|");
                        }

                        try writer.writeAll(f.name);
                    }
                }
            }
        }
    }.format;
}

fn flagsFormatterWithInvalid(comptime T: type) fn (T, *std.Io.Writer) std.Io.Writer.Error!void {
    return struct {
        fn format(flags: T, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            const Valid = @FieldType(T, "valid");

            if (@as(@typeInfo(Valid).@"struct".backing_integer.?, @bitCast(flags.valid)) == 0) {
                try writer.print("0x{X}", .{flags.padding});
            } else {
                if (flags.padding != 0) {
                    try writer.print("0x{X}|", .{flags.padding});
                }

                try flagsFormatter(Valid)(flags.valid, writer);
            }
        }
    }.format;
}

fn validateFlags(comptime T: type) fn (T) ?@FieldType(T, "valid") {
    return struct {
        fn validate(flags: T) ?@FieldType(T, "valid") {
            return if (flags.padding == 0) flags.valid else null;
        }
    }.validate;
}

/// File descriptor rights, determining which actions may be performed.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#rights
pub const Rights = packed struct(u64) {
    pub const Valid = packed struct(u30) {
        /// The right to invoke `fd_datasync`.
        ///
        /// If `path_open` is set, includes the right to invoke `path_open` with
        /// `FdFlags.Valid.dsync`.
        fd_datasync: bool = false,
        /// The right to invoke `fd_read` and `sock_recv`.
        ///
        /// If `Rights.Valid.fd_seek` is set, includes the right to invoke `fd_pread`.
        fd_read: bool = false,
        /// The right to invoke `fd_seek`. This flag implies `Rights.Valid.fd_tell`.
        fd_seek: bool = false,
        /// The right to invoke `fd_fdstat_set_flags`.
        fd_fdstat_set_flags: bool = false,
        /// The right to invoke `fd_sync`.
        ///
        /// If `path_open` is set, includes the right to invoke
        /// `path_open` with `FdFlags.Valid.rsync` and `FdFlags.Validdsync`.
        fd_sync: bool = false,
        /// The right to invoke `fd_seek` in such a way that the file offset
        /// remains unaltered (i.e., `Whence.cur` with offset zero), or to
        /// invoke `fd_tell`.
        fd_tell: bool = false,
        /// The right to invoke `fd_write` and `sock_send`.
        /// If `Rights.Valid.fd_seek` is set, includes the right to invoke `fd_pwrite`.
        fd_write: bool = false,
        /// The right to invoke `fd_advise`.
        fd_advise: bool = false,
        /// The right to invoke `fd_allocate`.
        fd_allocate: bool = false,
        /// The right to invoke `path_create_directory`.
        path_create_directory: bool = false,
        /// If `path_open` is set, the right to invoke `path_open` with `OpenFlags.creat`.
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
        /// If `path_open` is set, includes the right to invoke `path_open` with
        /// `OpenFlags.Valid.trunc`.
        ///
        /// Note: there is no function named `path_filestat_set_size`. This follows POSIX design,
        /// which only has `ftruncate` and does not provide `ftruncateat`.
        /// While such function would be desirable from the API design perspective, there are
        /// virtually no use cases for it since no code written for POSIX systems would use it.
        /// Moreover, implementing it would require multiple syscalls, leading to inferior
        /// performance.
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
        /// If `Rights.Valid.fd_read` is set, includes the right to invoke `poll_oneoff` to
        /// subscribe to `EventType.fd_read`.
        ///
        /// If `Rights.Valid.fd_write` is set, includes the right to invoke `poll_oneoff` to
        /// subscribe to `EventType.fd_write`.
        poll_fd_readwrite: bool = false,
        /// The right to invoke `sock_shutdown`.
        sock_shutdown: bool = false,
        /// The right to invoke `sock_accept`.
        sock_accept: bool = false,

        pub const format = flagsFormatter(Valid);

        pub fn contains(super: Valid, sub: Valid) bool {
            const super_bits: u30 = @bitCast(super);
            return super_bits | @as(u30, @bitCast(sub)) == super_bits;
        }
    };

    valid: Valid = .{},
    padding: u34 = 0,

    pub const format = flagsFormatterWithInvalid(Rights);

    pub const validate = validateFlags(Rights);
};

/// Identifier for a device containing a file system.
///
/// Can be used in combination with `INode` to uniquely identify a file or directory in the
/// filesystem.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#device
pub const Device = packed struct(u64) {
    n: u64,
};

/// File attributes.
///
/// This is similar to `struct stat` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#filestat
pub const FileStat = extern struct {
    /// Device ID of device containing the file.
    dev: Device,
    /// File serial number.
    ino: INode,
    type: FileType,
    /// Number of hard links to the file.
    nlink: u64,
    /// For regular files, the file size in bytes.
    /// For symbolic links, the length in bytes of the pathname contained in the symbolic link.
    size: FileSize,
    /// Last data access timestamp.
    atim: Timestamp,
    /// Last data modification timestamp.
    mtim: Timestamp,
    /// Last file status change timestamp.
    ctim: Timestamp,

    comptime {
        std.debug.assert(@sizeOf(FileStat) == 64);
        std.debug.assert(@offsetOf(FileStat, "ctim") == 56);
    }
};

/// Information about a pre-opened capability.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#prestat
pub const PreStat = extern struct {
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

    pub fn init(comptime tag: Type, payload: @FieldType(Payload, @tagName(tag))) PreStat {
        return .{
            .tag = tag,
            .payload = @unionInit(Payload, @tagName(tag), payload),
        };
    }

    comptime {
        std.debug.assert(@sizeOf(PreStat) == 8);
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

/// File serial number that is unique within its file system.
///
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
        // FILE_FLAG_WRITE_THROUGH on Windows? https://github.com/golang/go/issues/35358
        sync: bool,

        pub const format = flagsFormatter(Valid);

        const has_dsync = @hasField(std.posix.O, "DSYNC");
        const has_rsync = @hasField(std.posix.O, "RSYNC");

        pub fn fromFlagsPosix(flags: std.posix.O) Valid {
            return Valid{
                .append = flags.APPEND,
                .dsync = if (has_dsync) flags.DSYNC else false,
                .nonblock = flags.NONBLOCK,
                // O_RSYNC not implemented on Linux
                .rsync = if (has_rsync) flags.RSYNC else false,
                .sync = flags.SYNC,
            };
        }

        // pub fn fromFlagsPosix
    };

    valid: Valid,
    padding: u11 = 0,

    pub const Param = packed struct(u32) {
        valid: Valid,
        padding: u27 = 0,

        pub const format = flagsFormatterWithInvalid(Param);
        pub const validate = validateFlags(Param);
    };
};

/// File descriptor attributes.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fdstat
pub const FdStat = extern struct {
    file: File,
    rights_base: Rights,
    /// Maximum set of rights that may be installed on new file descriptors that are created through
    /// this file descriptor, e.g., through `path_open`.
    rights_inheriting: Rights,

    comptime {
        std.debug.assert(@sizeOf(FdStat) == 24);
        std.debug.assert(@offsetOf(File, "flags") == 2);
        std.debug.assert(@offsetOf(FdStat, "rights_base") == 8);
    }

    pub const File = extern struct {
        type: FileType,
        flags: FdFlags,
    };
};

/// Which file time attributes to adjust.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fstflags
pub const FstFlags = packed struct(u16) {
    pub const Valid = packed struct(u4) {
        /// Adjust the last data access timestamp to the value stored in `FileStat.atim`.
        atim: bool,
        /// Adjust the last data access timestamp to the time of clock `ClockId.real_time`.
        atim_now: bool,
        /// Adjust the last data modification timestamp to the value stored in `FileStat.mtim`.
        mtim: bool,
        /// Adjust the last data modification timestamp to the time of clock `ClockId.real_time`.
        mtim_now: bool,

        pub const format = flagsFormatter(Valid);
    };

    valid: Valid,
    padding: u12,

    pub const Param = packed struct(u32) {
        valid: Valid,
        padding: u28 = 0,

        pub const format = flagsFormatterWithInvalid(Param);
        pub const validate = validateFlags(Param);
    };
};

/// Flags determining the method of how paths are resolved.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#lookupflags
pub const LookupFlags = packed struct(u32) {
    pub const Valid = packed struct(u1) {
        /// As long as the resolved path corresponds to a symbolic link, it is expanded.
        symlink_follow: bool,

        pub const format = flagsFormatter(Valid);
    };

    valid: Valid,
    padding: u31,

    pub const format = flagsFormatterWithInvalid(LookupFlags);
    pub const validate = validateFlags(LookupFlags);
};

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#oflags
pub const OpenFlags = packed struct(u16) {
    pub const Valid = packed struct(u4) {
        /// Create file if it does not exist.
        creat: bool,
        /// Fail if not a directory.
        directory: bool,
        /// Fail if file already exists.
        excl: bool,
        /// Truncate file to size `0`.
        trunc: bool,

        pub const format = flagsFormatter(Valid);
    };

    valid: Valid,
    padding: u12,

    pub const Param = packed struct(u32) {
        valid: Valid,
        padding: u28 = 0,

        pub const format = flagsFormatterWithInvalid(Param);
        pub const validate = validateFlags(Param);
    };
};

/// User-provided value that may be attached to objects that is retained when extracted from
/// the implementation.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#userdata
pub const UserData = u64;

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#eventtype
pub const EventType = enum(u8) {
    /// The time value of clock `Subscription.Clock.id` has reached timestamp
    /// `Subscription.Clock.timeout`.
    clock,
    /// `Subscription.FdReadWrite.file_descriptor` has data available for reading. This event
    /// always triggers for regular files.
    fd_read,
    /// `Subscription.FdReadWrite.file_descriptor` has capacity available for writing. This event
    /// always triggers for regular files.
    fd_write,
};

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#subscription
pub const Subscription = extern struct {
    /// User-provided value that is attached to the subscription in the implementation and returned
    /// through `Event.user_data`.
    user_data: UserData,
    /// The type of the event to which to subscribe, and its contents.
    u: Union,

    comptime {
        std.debug.assert(@sizeOf(Subscription) == 48);
        std.debug.assert(@offsetOf(Subscription, "user_data") == 0);
        std.debug.assert(@offsetOf(Subscription, "u") == 8);
    }

    /// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#subscription_u
    pub const Union = extern struct {
        tag: EventType,
        payload: Payload,

        comptime {
            std.debug.assert(@sizeOf(Union) == 40);
            std.debug.assert(@sizeOf(Payload) == 32);
            std.debug.assert(@offsetOf(Union, "payload") == 8);
        }

        pub const Payload = extern union {
            clock: Clock,
            fd_read: FdReadWrite,
            fd_write: FdReadWrite,
        };
    };

    /// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#subscription_clock
    pub const Clock = extern struct {
        /// The clock against which to compare the timestamp.
        id: ClockId,
        /// The absolute or relative timestamp.
        timeout: Timestamp,
        /// The amount of time that the implementation may wait additionally to coalesce with other
        /// events.
        precision: Timestamp,
        /// Flags specifying whether the timeout is absolute or relative.
        flags: SubclockFlags,

        comptime {
            std.debug.assert(@sizeOf(Clock) == 32);
        }
    };

    /// Flags determining how to interpret the timestamp provided in `Subscription.Clock.timeout`.
    ///
    /// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#subclockflags
    pub const SubclockFlags = packed struct(u16) {
        pub const Valid = packed struct(u1) {
            /// If set, treat the timestamp provided in `Subscription.Clock.timeout` as an absolute
            /// timestamp of clock `Subscription.Clock.id`.
            ///
            /// If clear, treat the timestamp provided in `Subscription.Clock.timeout` relative to
            /// the current time value of clock `Subscription.Clock.id`.
            subscription_clock_abstime: bool,

            pub const format = flagsFormatter(Valid);
        };

        valid: Valid,
        padding: u15 = 0,

        pub const format = flagsFormatterWithInvalid(SubclockFlags);

        pub const validate = validateFlags(SubclockFlags);
    };

    /// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#subscription_fd_readwrite
    pub const FdReadWrite = extern struct {
        /// The file descriptor on which to wait for it to become ready for reading or writing.
        file_descriptor: u32,

        comptime {
            std.debug.assert(@sizeOf(FdReadWrite) == 4);
        }
    };
};

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#event
pub const Event = extern struct {
    /// User-provided value that got attached to `Subscription.user_data`.
    user_data: UserData,
    /// If non-zero, an error that occurred while processing the subscription request.
    @"error": Errno,
    /// The type of event that occured.
    type: EventType,
    /// The contents of the event, if it is an `EventType.fd_read` or `EventType.fd_write`.
    /// `EventType.clock` events ignore this field.
    fd_read_write: FdReadWrite,

    comptime {
        std.debug.assert(@sizeOf(Event) == 32);
        std.debug.assert(@offsetOf(Event, "user_data") == 0);
        std.debug.assert(@offsetOf(Event, "error") == 8);
        std.debug.assert(@offsetOf(Event, "type") == 10);
        std.debug.assert(@offsetOf(Event, "fd_read_write") == 16);
    }

    /// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#event_fd_readwrite
    pub const FdReadWrite = extern struct {
        /// The number of bytes available for reading or writing.
        num_bytes: FileSize,
        /// The state of the file descriptor.
        flags: RwFlags,

        comptime {
            std.debug.assert(@sizeOf(FdReadWrite) == 16);
        }
    };

    /// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#eventrwflags
    pub const RwFlags = packed struct(u16) {
        pub const Valid = packed struct(u1) {
            /// The peer of this socket has closed or disconnected.
            fd_read_write_hangup: bool,

            pub const format = flagsFormatter(Valid);
        };

        valid: Valid,
        padding: u15 = 0,

        pub const format = flagsFormatterWithInvalid(RwFlags);

        pub const validate = validateFlags(RwFlags);
    };
};

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#signal
pub const Signal = enum(u8) {
    /// No signal. Note that POSIX has special semantics for `kill(pid, 0)`,
    /// so this value is reserved.
    none,
    /// Hangup.
    /// Action: Terminates the process.
    hup,
    /// Terminate interrupt signal.
    /// Action: Terminates the process.
    int,
    /// Terminal quit signal.
    /// Action: Terminates the process.
    quit,
    /// Illegal instruction.
    /// Action: Terminates the process.
    ill,
    /// Trace/breakpoint trap.
    /// Action: Terminates the process.
    trap,
    /// Process abort signal.
    /// Action: Terminates the process.
    abrt,
    /// Access to an undefined portion of a memory object.
    /// Action: Terminates the process.
    bus,
    /// Erroneous arithmetic operation.
    /// Action: Terminates the process.
    fpe,
    /// Kill.
    /// Action: Terminates the process.
    kill,
    /// User-defined signal 1.
    /// Action: Terminates the process.
    usr1,
    /// Invalid memory reference.
    /// Action: Terminates the process.
    segv,
    /// User-defined signal 2.
    /// Action: Terminates the process.
    usr2,
    /// Write on a pipe with no one to read it.
    /// Action: Ignored.
    pipe,
    /// Alarm clock.
    /// Action: Terminates the process.
    alrm,
    /// Termination signal.
    /// Action: Terminates the process.
    term,
    /// Child process terminated, stopped, or continued.
    /// Action: Ignored.
    chld,
    /// Continue executing, if stopped.
    /// Action: Continues executing, if stopped.
    cont,
    /// Stop executing.
    /// Action: Stops executing.
    stop,
    /// Terminal stop signal.
    /// Action: Stops executing.
    tstp,
    /// Background process attempting read.
    /// Action: Stops executing.
    ttin,
    /// Background process attempting write.
    /// Action: Stops executing.
    ttou,
    /// High bandwidth data is available at a socket.
    /// Action: Ignored.
    urg,
    /// CPU time limit exceeded.
    /// Action: Terminates the process.
    xcpu,
    /// File size limit exceeded.
    /// Action: Terminates the process.
    xfsz,
    /// Virtual timer expired.
    /// Action: Terminates the process.
    vtalrm,
    /// Profiling timer expired.
    /// Action: Terminates the process.
    prof,
    /// Window changed.
    /// Action: Ignored.
    winch,
    /// I/O possible.
    /// Action: Terminates the process.
    poll,
    /// Power failure.
    /// Action: Terminates the process.
    pwr,
    /// Bad system call.
    /// Action: Terminates the process.
    sys,
};

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#riflags
pub const RiFlags = packed struct(u16) {
    pub const Valid = packed struct(u2) {
        /// Returns the message without removing it from the socket's receive queue.
        recv_peek: bool,
        /// On byte-stream sockets, block until the full amount of data can be returned.
        recv_wait_all: bool,

        pub const format = flagsFormatter(Valid);
    };

    valid: Valid,
    padding: u14 = 0,

    pub const Param = packed struct(u32) {
        valid: Valid,
        padding: u30 = 0,

        pub const format = flagsFormatterWithInvalid(Param);
        pub const validate = validateFlags(Param);
    };
};

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#roflags
pub const RoFlags = packed struct(u16) {
    pub const Valid = packed struct(u1) {
        /// Message data has been truncated.
        recv_data_truncated: bool,

        pub const format = flagsFormatter(Valid);
    };

    valid: Valid,
    padding: u15 = 0,
};

/// Which channels on a socket to shut down.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#sdflags
pub const SdFlags = packed struct(u8) {
    pub const Valid = packed struct(u2) {
        /// Disables further receive operations.
        rd: bool,
        /// Disables further send operations.
        wr: bool,

        pub const format = flagsFormatter(Valid);
    };

    valid: Valid,
    padding: u6,

    pub const Param = packed struct(u32) {
        valid: Valid,
        padding: u30 = 0,

        pub const format = flagsFormatterWithInvalid(Param);
        pub const validate = validateFlags(Param);
    };
};

const std = @import("std");
const builtin = @import("builtin");
const Errno = @import("errno.zig").Errno;
