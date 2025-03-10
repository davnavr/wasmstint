const std = @import("std");

comptime {
    _ = @import("rust_alloc.zig");
}

pub const Result = enum(c_int) {
    ok = 0,
    skip = -1,
};

extern fn wasmstint_fuzz_arbitrary_module(input: *FfiSlice(.@"const", u8), output: *FfiVec(u8)) bool;

extern fn wasmstint_fuzz_free_bytes(bytes: *FfiVec(u8)) void;

// TODO: Something about an oracle with wasmi or wasmtime (differential test)

pub const Generator = struct {
    src: Bytes,

    const Bytes = FfiSlice(.@"const", u8);

    pub fn init(src: []const u8) Generator {
        return .{ .src = Bytes.init(src) };
    }

    pub const Error = error{OutOfDataBytes};

    pub fn validWasmModule(gen: *Generator) Error!FfiVec(u8) {
        var output: FfiVec(u8) = undefined;
        return if (wasmstint_fuzz_arbitrary_module(&gen.src, &output))
            output
        else
            error.OutOfDataBytes;
    }

    pub fn bytes(gen: *Generator, size: usize) Error![]const u8 {
        if (gen.src.len >= size) {
            const src: []const u8 = gen.src.toSlice();
            gen.src = Bytes.init(src[size..]);
            return src[0..size];
        } else return error.OutOfDataBytes;
    }

    pub fn byteArray(gen: *Generator, comptime size: usize) Error!*const [size]u8 {
        return (try gen.bytes(size))[0..size];
    }

    pub fn int(gen: *Generator, comptime T: type) Error!T {
        comptime {
            std.debug.assert(@typeInfo(T) == .int);
        }

        return @truncate(
            std.mem.readInt(
                std.math.ByteAlignedInt(T),
                try gen.byteArray(@sizeOf(T)),
                .little,
            ),
        );
    }

    const Random = struct {
        gen: *Generator,
        err: ?Error = null,

        fn fill(ptr: *anyopaque, dst: []u8) void {
            const state: *Random = @ptrCast(@alignCast(ptr));
            if (state.err != null) {
                @memset(dst, 0);
                return;
            }

            const src = state.gen.bytes(dst.len) catch |e| {
                state.err = e;
                @memset(dst, 0);
                return;
            };

            @memcpy(dst, src);
        }

        fn random(state: *Random) std.Random {
            return .{
                .fillFn = fill,
                .ptr = @ptrCast(state),
            };
        }

        fn checkForError(state: Random) Error!void {
            if (state.err) |err|
                return err;
        }
    };

    fn random(gen: *Generator) Random {
        return .{ .gen = gen };
    }

    pub fn intRangeAtMost(gen: *Generator, comptime T: type, at_least: T, at_most: T) Error!T {
        var r = gen.random();
        const value = r.random().intRangeAtMost(T, at_least, at_most);
        try r.checkForError();
        return value;
    }

    pub fn uintLessThan(gen: *Generator, comptime T: type, less_than: T) Error!T {
        var r = gen.random();
        const value = r.random().uintLessThan(T, less_than);
        try r.checkForError();
        return value;
    }
};

pub fn FfiSlice(comptime constness: enum { @"const", mut }, comptime T: type) type {
    return extern struct {
        ptr: switch (constness) {
            .mut => [*]T,
            .@"const" => [*]const T,
        },
        len: usize,

        const Self = @This();

        const Slice = switch (constness) {
            .mut => []T,
            .@"const" => []const T,
        };

        pub fn init(slice: Slice) Self {
            return .{ .ptr = slice.ptr, .len = slice.len };
        }

        pub fn toSlice(slice: Self) Slice {
            return slice.ptr[0..slice.len];
        }
    };
}

pub fn FfiVec(comptime T: type) type {
    return extern struct {
        pub const Items = FfiSlice(.mut, T);

        items: Items,
        capacity: usize,

        pub const deinit: fn (*FfiVec(T)) callconv(.c) void = if (T == u8)
            wasmstint_fuzz_free_bytes
        else
            @compileError("no deinit method available for FfiVec containing " ++ @typeName(T));
    };
}

const SegfaultHandler = enum(u32) {
    starting = 0,
    installing = 1,
    attached = 2,

    // TODO: Figure out if AFL++ calls LLVMFuzzerTestOneInput in a multi-threaded environment
    var current = std.atomic.Value(SegfaultHandler).init(.starting);

    inline fn currentAsInt() *std.atomic.Value(u32) {
        return @ptrCast(&current);
    }

    fn installSlowPath() void {
        @branchHint(.cold);
        perform_install: {
            const previous: SegfaultHandler = @enumFromInt(
                currentAsInt().fetchMax(
                    @intFromEnum(SegfaultHandler.installing),
                    .acq_rel,
                ),
            );

            switch (previous) {
                .starting => break :perform_install,
                .attached => return,
                .installing => while (true) {
                    std.Thread.Futex.wait(currentAsInt(), @intFromEnum(SegfaultHandler.installing));

                    if (current.load(.acquire) == .attached)
                        return;
                },
            }
        }

        std.debug.attachSegfaultHandler();
    }

    inline fn install() void {
        if (std.debug.have_segfault_handling_support and current.load(.acquire) != .attached) {
            @branchHint(.cold);
            @call(.never_inline, installSlowPath, .{});
        }
    }
};

pub fn defineFuzzTarget(comptime target: anytype) void {
    // const TargetFn = @typeInfo(@TypeOf(target)).@"fn";

    const Fuzzer = struct {
        fn fuzzer(data: [*]const u8, size: usize) callconv(.c) c_int {
            SegfaultHandler.install();

            const result: Result = @call(
                .never_inline,
                target,
                .{data[0..size]},
            ) catch |e| switch (@as(anyerror, e)) {
                error.OutOfDataBytes, error.OutOfMemory => |err| skip: {
                    std.debug.print("skipping results: {!}\n", .{err});
                    if (@errorReturnTrace()) |trace| {
                        std.debug.dumpStackTrace(trace.*);
                    }

                    break :skip .skip;
                },
                else => |err| std.debug.panic("target failed with error: {!}", .{err}),
            };

            return @intFromEnum(result);
        }
    };

    comptime {
        @export(&Fuzzer.fuzzer, .{ .name = "LLVMFuzzerTestOneInput" });
    }
}
