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

    pub fn initRaw(n: i32) error{BadFd}!Fd {
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
            // `Fd` keys are random anyways, so a simple fast hash works fine.
            return std.hash.int(@as(u32, fd.n));
        }

        pub fn eql(ctx: EntryContext, x: Fd, y: Fd, idx: usize) bool {
            _ = ctx;
            _ = idx;
            return x.n == y.n;
        }
    };

    /// Callers must write to the returned pointer to initialize the `File`.
    pub fn create(table: *FdTable, allocator: Allocator) Allocator.Error!*File {
        try table.entries.ensureUnusedCapacity(allocator, 1);
        while (true) {
            // For simplicity, never pick the standard stream numbers.
            const chosen = Fd{
                .n = table.rng.random().intRangeAtMost(u31, 3, std.math.maxInt(u31)),
            };

            const entry = table.entries.getOrPutAssumeCapacity(chosen);
            if (entry.found_existing) {
                // More likely to hit underlying OS open FD limit before branch hint is wrong
                @branchHint(.cold);
                continue;
            } else {
                entry.value_ptr.* = undefined;
                return entry.value_ptr;
            }
        }
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

    pub fn init(
        allocator: Allocator,
        seed: [2]u64,
        standard_streams: File.StandardStreams,
    ) Allocator.Error!FdTable {
        var entries = Entries.empty;
        try entries.ensureTotalCapacity(allocator, 3);
        inline for (comptime std.meta.fieldNames(File.StandardStreams)) |stream_name| {
            entries.putAssumeCapacityNoClobber(
                comptime @field(Fd, stream_name),
                @field(standard_streams, stream_name),
            );
        }

        return .{ .entries = entries, .rng = .{ .s = seed } };
    }

    pub fn deinit(table: *FdTable, allocator: Allocator) void {
        for (table.entries.values()) |*file| {
            file.deinit(allocator);
        }

        table.entries.deinit(allocator);
        table.* = undefined;
    }
};

const std = @import("std");
const Allocator = std.mem.Allocator;
const File = @import("File.zig");
