/// A file descriptor handle.
pub const Fd = packed struct(u32) {
    comptime {
        std.debug.assert(std.math.maxInt(u31) == std.math.maxInt(i32));
    }

    /// Must be less than `2^31`.
    n: u31,
    padding: enum(u1) { padding } = .padding,

    pub const stdin = Fd{ .n = 0 };
    pub const stdout = Fd{ .n = 1 };
    pub const stderr = Fd{ .n = 2 };

    pub const standard_streams: [3]Fd = .{ stdin, stdout, stderr };

    pub const Table = FdTable;

    pub const Error = error{BadFd};

    pub fn initRaw(n: i32) Error!Fd {
        return if (0 <= n)
            .{ .n = @intCast(n) }
        else
            error.BadFd;
    }

    pub fn format(fd: Fd, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        return writer.print("{}", .{fd.n});
    }
};

const FdTable = struct {
    // Is https://github.com/ziglang/zig/issues/17851 a concern here?
    const Entries = std.ArrayHashMapUnmanaged(Fd, File, EntryContext, false);

    entries: Entries,
    /// Used to generate new `Fd` numbers.
    rng: std.Random.Xoroshiro128,

    const EntryContext = struct {
        pub fn hash(ctx: EntryContext, fd: Fd) u32 {
            _ = ctx;
            // `Fd` keys are random anyways, so a simple hash works fine.
            return std.hash.int(@as(u32, fd.n));
        }

        pub fn eql(ctx: EntryContext, x: Fd, y: Fd, idx: usize) bool {
            _ = ctx;
            _ = idx;
            return x.n == y.n;
        }
    };

    pub fn unlockTable(table: *FdTable) void {
        table.entries.unlockPointers();
    }

    pub const CreateError = Allocator.Error || error{
        /// Too many open file descriptors.
        ProcessFdQuotaExceeded,
    };

    /// Callers must write to the returned pointer to initialize the `File`.
    ///
    /// Don't forget to call `unlockTable()`!
    pub fn create(table: *FdTable, allocator: Allocator) CreateError!*File {
        // Ensure the function returns evenntually even if the RNG is really messed up, or somehow,
        // too many FDs are open
        const create_max_attempts = 8;

        try table.entries.ensureUnusedCapacity(allocator, 1);
        for (0..create_max_attempts) |_| {
            errdefer comptime unreachable;

            // For simplicity, never pick the standard stream numbers + 1st preopen.
            const chosen = Fd{
                .n = table.rng.random().intRangeAtMost(u31, 4, std.math.maxInt(u31)),
            };

            const entry = table.entries.getOrPutAssumeCapacity(chosen);
            if (entry.found_existing) {
                // More likely to hit underlying OS open FD limit before branch hint is wrong
                @branchHint(.cold);
                continue;
            } else {
                entry.value_ptr.* = undefined;
                table.entries.lockPointers();
                return entry.value_ptr;
            }
        } else {
            @branchHint(.cold);
            // exceeded attempt count, too many open FDs to effectively pick a new random one
            return error.ProcessFdQuotaExceeded;
        }
    }

    /// Don't forget to call `unlockTable()`!
    pub fn get(table: *FdTable, fd: Fd) Fd.Error!*File {
        table.entries.lockPointers();
        return table.entries.getPtr(fd) orelse error.BadFd;
    }

    pub fn close(table: *FdTable, file_allocator: Allocator, fd: Fd) Fd.Error!void {
        var removed = table.entries.fetchSwapRemove(fd) orelse return error.BadFd;
        removed.value.deinit(file_allocator);
        table.entries.pointer_stability.assertUnlocked();
    }

    /// Returns `true` if `fd` was valid and successfully removed.
    pub fn remove(table: *FdTable, fd: Fd) bool {
        if (table.entries.fetchSwapRemove(fd)) |removed| {
            removed.value.deinit();
            return true;
        } else {
            return false;
        }
    }

    const preopens_start = 3;

    pub fn init(
        allocator: Allocator,
        rng_init: *std.Random.SplitMix64,
        standard_streams: File.StandardStreams,
        preopen_dirs: *[]PreopenDir,
    ) Allocator.Error!FdTable {
        var entries = Entries.empty;

        const reserve_count = std.math.add(
            u31,
            preopens_start,
            std.math.cast(u31, preopen_dirs.len) orelse return error.OutOfMemory,
        ) catch return error.OutOfMemory; // too many preopens

        try entries.ensureTotalCapacity(allocator, reserve_count);
        errdefer entries.deinit(allocator);

        inline for (
            0..preopens_start,
            comptime std.meta.fieldNames(File.StandardStreams),
        ) |i, stream_name| {
            const fd: Fd = comptime @field(Fd, stream_name);
            comptime {
                std.debug.assert(fd.n == i);
            }

            entries.putAssumeCapacityNoClobber(fd, @field(standard_streams, stream_name));
        }

        const preopen_count = preopen_dirs.len;
        for (preopens_start..(preopens_start + preopen_count)) |i| {
            const fd = Fd{ .n = @intCast(i) };
            const preopen: *PreopenDir = &preopen_dirs.*[0];
            entries.putAssumeCapacityNoClobber(fd, try File.preopen.init(preopen, allocator));
            preopen_dirs.* = preopen_dirs.*[1..];
        }
        std.debug.assert(preopen_dirs.len == 0);

        return .{
            .entries = entries,
            .rng = std.Random.Xoroshiro128{ .s = .{ rng_init.next(), rng_init.next() } },
        };
    }

    pub fn deinit(table: *FdTable, allocator: Allocator) void {
        for (table.entries.values()[preopens_start..]) |*file| {
            file.deinit(allocator);
        }

        table.entries.deinit(allocator);
        table.* = undefined;
    }
};

const std = @import("std");
const Allocator = std.mem.Allocator;
const File = @import("File.zig");
const PreopenDir = @import("PreopenDir.zig");
