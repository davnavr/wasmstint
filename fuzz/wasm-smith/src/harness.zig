const std = @import("std");

pub const Result = enum(c_int) {
    ok = 0,
    skip = -1,
};

extern fn wasmstint_fuzz_arbitrary_module(input: *FfiSlice(.@"const", u8), output: *FfiVec(u8)) bool;

extern fn wasmstint_fuzz_free_bytes(bytes: *FfiVec(u8)) void;

// TODO: Something about an oracle with wasmi or wasmtime (differential test)

pub fn generateValidModule(input: *[]const u8) error{GenerateError}!FfiVec(u8) {
    var ffi_input = FfiSlice(.@"const", u8).init(input.*);
    defer input.* = ffi_input.toSlice();

    var output: FfiVec(u8) = undefined;
    return if (wasmstint_fuzz_arbitrary_module(&ffi_input, &output))
        output
    else
        error.GenerateError;
}

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
        fn fuzzer(data: [*]const u8, size: usize) callconv(.c) c_int {
            const result: Result = @call(
                .never_inline,
                target,
                .{data[0..size]},
            ) catch |e| switch (@as(anyerror, e)) {
                error.GenerateError => .skip,
                else => |err| std.debug.panic("target failed with error: {!}", .{err}),
            };

            return @intFromEnum(result);
        }
    };

    comptime {
        @export(&Fuzzer.fuzzer, .{ .name = "LLVMFuzzerTestOneInput" });
    }
}
