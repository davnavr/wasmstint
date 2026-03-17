//! Produces an LLVM IR bitcode (`.bc`) file that will be translated to assembly, which will later
//! be used to detect whether intrinsics are compiled to instructions or `compiler_rt` calls.

pub const TargetInfo = struct {
    data_layout: []const u8,
    triple: []const u8,
    cpu_features: []const u8,
};

pub const std_options: std.Options = .{ .networking = false };

pub fn main(init: std.process.Init.Minimal) std.mem.Allocator.Error!void {
    var io_impl = std.Io.Threaded.init_single_threaded;
    const io = io_impl.io();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);

    var cli_args = try init.args.iterateAllocator(arena.allocator());
    _ = cli_args.next().?;

    const cwd = std.Io.Dir.cwd();
    const target_info = info: {
        const path = cli_args.next().?;
        const contents = cwd.readFileAllocOptions(
            io,
            path,
            arena.allocator(),
            .limited(4096 * 4),
            .@"16",
            0,
        ) catch |e| std.debug.panic("cannot open {s} for reading: {t}", .{ path, e });

        break :info std.zon.parse.fromSliceAlloc(
            TargetInfo,
            arena.allocator(),
            contents,
            null,
            .{ .free_on_error = false },
        ) catch |e| switch (e) {
            error.ParseZon => std.debug.panic("error parsing target info:\n{s}\n", .{contents}),
            else => |err| return err,
        };
    };

    const bc_file = file: {
        const path = cli_args.next().?;
        break :file cwd.createFile(io, path, .{}) catch |e|
            std.debug.panic("cannot open {s} for writing: {t}", .{ path, e });
    };

    std.debug.assert(cli_args.next() == null);

    var b = try Builder.init(Builder.Options{
        .allocator = arena.allocator(),
        .strip = true,
        .name = "sample_intrinsics",
        .triple = target_info.triple,
        .target = undefined, // Looking at the source, this seems to not be used
    });
    b.data_layout = try b.string(target_info.data_layout);

    const result_ty = try b.structType(.normal, &.{ .float, .double });
    const func_ty = try b.fnType(result_ty, &.{ .float, .double }, .normal);
    const func = try b.addFunction(func_ty, try b.strtabString("foobarbaz"), .default);
    {
        var attrs = Builder.FunctionAttributes.Wip{};
        try attrs.addFnAttr(.{
            .string = .{
                .kind = try b.string("target-features"),
                .value = try b.string(target_info.cpu_features),
            },
        }, &b);
        // Seems to work w/o needing to provide "target-cpu" attribute, probably because the
        // "target-features" seem to be what impact code generation.
        func.setAttributes(try attrs.finish(&b), &b);
    }

    var result = try b.poisonValue(result_ty);
    var wip = try WipFunction.init(&b, .{ .function = func, .strip = true });
    wip.cursor = .{ .block = try wip.block(0, "Entry") };
    // roundevenf
    result = try wip.insertValue(
        result,
        try wip.callIntrinsic(.normal, .none, .roundeven, &.{.float}, &.{wip.arg(0)}, ""),
        &.{0},
        "",
    );
    // roundeven
    result = try wip.insertValue(
        result,
        try wip.callIntrinsic(.normal, .none, .roundeven, &.{.double}, &.{wip.arg(1)}, ""),
        &.{1},
        "",
    );
    _ = try wip.ret(result);
    try wip.finish();

    const bitcode: []const u32 = try b.toBitcode(std.heap.page_allocator, .{
        .name = "wasmstint-sample-intrinsics",
        .version = .{ .major = 0, .minor = 0, .patch = 0 },
    });

    bc_file.writeStreamingAll(io, @ptrCast(bitcode)) catch |e| {
        std.debug.panic("cannot write bitcode: {t}", .{e});
    };
}

const std = @import("std");
const Builder = std.zig.llvm.Builder;
const WipFunction = Builder.WipFunction;
