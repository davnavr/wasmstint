const std = @import("std");

comptime {
    _ = @import("rust_alloc.zig");
}

pub export fn wasmstint_fuzz_rust_hash_bytes(seed: u64, bytes_ptr: [*]const u8, bytes_len: usize) u64 {
    var hasher = std.hash.XxHash3.init(seed);
    hasher.update(bytes_ptr[0..bytes_len]);
    return hasher.final();
}

pub const Result = enum(c_int) {
    ok = 0,
    skip = -1,
};

extern fn wasmstint_fuzz_arbitrary_module(input: *FfiSlice(.@"const", u8), output: *FfiVec(u8)) bool;

extern fn wasmstint_fuzz_free_bytes(bytes: *FfiVec(u8)) void;

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
        /// Rather than filling buffers with dummy values/zero on `Error`, use
        /// pseudo-random values that don't hang Lemire's algorithm.
        err_rng: std.Random.Xoroshiro128,
        err: ?Error = null,

        fn fill(ptr: *anyopaque, dst: []u8) void {
            const state: *Random = @ptrCast(@alignCast(ptr));
            if (state.err != null) {
                state.err_rng.fill(dst);
                return;
            }

            const src = state.gen.bytes(dst.len) catch |e| {
                state.err = e;
                state.err_rng.fill(dst);
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
        return .{
            .gen = gen,
            .err_rng = .init(@truncate(@returnAddress())),
        };
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

pub fn defineFuzzTarget(comptime target: anytype) void {
    // const TargetFn = @typeInfo(@TypeOf(target)).@"fn";

    const Fuzzer = struct {
        fn fuzzer(data: [*]const u8, size: usize) callconv(.c) Result {
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

            return result;
        }
    };

    comptime {
        @export(&Fuzzer.fuzzer, .{ .name = "LLVMFuzzerTestOneInput" });
    }
}
