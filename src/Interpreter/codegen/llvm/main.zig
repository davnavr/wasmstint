const Options = struct {
    optimize: std.builtin.OptimizeMode,
    symbol_prefix: []const u8,
    strip: bool,
    use_llvm: bool,
    target: struct {
        triple: []const u8,
        cpu_features: []const u8,
    },
};

const TargetInfo = struct {
    data_layout: []const u8,
    triple: []const u8,
};

pub fn main(init: std.process.Init.Minimal) !void {
    var io_impl = std.Io.Threaded.init_single_threaded;
    const io = io_impl.ioBasic();

    var arena = ArenaAllocator.init(std.heap.page_allocator); // process lifetime

    var cli_args = try init.args.iterateAllocator(arena.allocator());
    _ = cli_args.next().?;

    const options = try std.zon.parse.fromSliceAlloc(
        Options,
        arena.allocator(),
        cli_args.next().?,
        null,
        .{ .free_on_error = false },
    );

    const cwd = std.Io.Dir.cwd();
    const target_info = target: {
        const path = cli_args.next().?;
        const contents = cwd.readFileAllocOptions(
            io,
            path,
            arena.allocator(),
            .limited(4096 * 4),
            .@"16",
            0,
        ) catch |e| {
            std.debug.panic("cannot open {s}", .{path});
            return e;
        };

        break :target try std.zon.parse.fromSliceAlloc(
            TargetInfo,
            arena.allocator(),
            contents,
            null,
            .{ .free_on_error = false },
        );
    };

    const bc_file = file: {
        const path = cli_args.next().?;
        break :file cwd.createFile(io, path, .{}) catch |e| {
            std.debug.panic("cannot open {s}: {t}", .{ path, e });
            return e;
        };
    };

    std.debug.assert(cli_args.next() == null);

    const target_query = try std.Target.Query.parse(.{
        .arch_os_abi = options.target.triple,
        .cpu_features = options.target.cpu_features,
    });
    const target = try std.zig.system.resolveTargetQuery(io, target_query);
    var builder = try Builder.init(.{
        .allocator = arena.allocator(),
        .strip = options.strip,
        .name = "wasmstint.interpreter",
        .target = &target,
        .triple = target_info.triple,
    });
    try buildLlvmModule(&builder, &target, &target_info, &options);

    const bitcode: []const u32 = try builder.toBitcode(std.heap.page_allocator, .{
        .name = "wasmstint.codegen.llvm",
        .version = .{ .major = 0, .minor = 0, .patch = 0 },
    });

    try bc_file.writeStreamingAll(io, @ptrCast(bitcode));
}

fn enumFieldCount(comptime E: type) comptime_int {
    return @typeInfo(E).@"enum".fields.len;
}

fn buildLlvmModule(
    builder: *Builder,
    target: *const std.Target,
    target_info: *const TargetInfo,
    options: *const Options,
) !void {
    builder.data_layout = try builder.string(target_info.data_layout);
    try builder.functions.ensureUnusedCapacity(
        builder.gpa,
        enumFieldCount(opcodes.ByteOpcode) + enumFieldCount(opcodes.FCPrefixOpcode),
    );

    const cconv: Builder.CallConv = if (target.cpu.arch == .x86_64 and options.use_llvm)
        .x86_regcallcc
    else
        .ccc;

    _ = cconv;
}

const std = @import("std");
const Builder = std.zig.llvm.Builder;
const ArenaAllocator = std.heap.ArenaAllocator;
const opcodes = @import("opcodes");
