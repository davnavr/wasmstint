const Arguments = cli_args.CliArgs(.{
    .description = "WebAssembly specification JSON test interpreter.",
    .flags = &[_]cli_args.Flag{
        .string(
            .{
                .long = "invoke",
                .short = 'i',
                .description = "Path to .wasm program to execute",
            },
            "PATH",
        ),

        cli_args.Flag.intUnsigned(
            .{
                .long = "rt-rng-seed",
                .description = "RNG seed used for internal data structures",
            },
            "SEED",
            u128,
        ).optional(),

        cli_args.Flag.intUnsigned(
            .{
                .long = "max-stack-size",
                .description = "Limits the size of the WASM value/call stack",
            },
            "AMOUNT",
            u32,
        ).withDefault(8192),
        cli_args.Flag.intUnsigned(
            .{
                .long = "max-memory-size",
                .description = "Upper bound on the size of WASM linear memory, in bytes",
            },
            "SIZE",
            usize,
        ).withDefault(1 * 1024 * 1024 * 1024), // 1 GiB
    },
});

fn oom(comptime context: []const u8) noreturn {
    @panic("out of memory: " ++ context);
}

const ErrorCode = enum(u8) {
    failure = 1,
    bad_arg = 2,

    fn print(code: ErrorCode, comptime fmt: []const u8, args: anytype) u8 {
        @branchHint(.cold);
        var buf: [256]u8 align(16) = undefined;
        const stderr = std.debug.lockStderrWriter(&buf);
        const color = std.Io.tty.detectConfig(
            @as(*std.fs.File.Writer, @fieldParentPtr("interface", stderr)).file,
        );
        color.setColor(stderr, .bright_red) catch {};
        stderr.writeAll("error: ") catch {};
        color.setColor(stderr, .reset) catch {};
        stderr.print(fmt ++ "\n", args) catch {};
        stderr.flush() catch {};
        return @intFromEnum(code);
    }
};

pub fn main() u8 {
    var arena = ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var scratch = ArenaAllocator.init(std.heap.page_allocator);
    defer scratch.deinit();

    const arguments = args: {
        const parser = Arguments.init(arena.allocator()) catch oom("CLI argument lookup");
        break :args parser.programArguments(&scratch, &arena) catch oom("CLI arguments");
    };

    const fmt_wasm_path = std.fmt.allocPrint(
        arena.allocator(),
        "{f}",
        .{std.unicode.fmtUtf8(arguments.invoke)},
    ) catch oom("path to wasm file");
    const wasm_binary = wasmstint.FileContent.readFileZ(
        std.fs.cwd(),
        arguments.invoke,
    ) catch |e| switch (e) {
        error.OutOfMemory => oom("module bytes"),
        else => |io_err| return ErrorCode.bad_arg.print(
            "failed to open program file {s}, {t}",
            .{ fmt_wasm_path, io_err },
        ),
    };

    const csprng = WasiPreview1.Csprng.os;
    const rt_rng_num: u128 = arguments.@"rt-rng-seed" orelse seed: {
        var seed: u128 = undefined;
        csprng.get(std.mem.asBytes(&seed)) catch |e|
            return ErrorCode.failure.print("could not access OS CSPRNG: {t}", .{e});
        break :seed seed;
    };

    const rt_rng_seeds: [2]u64 = .{ @truncate(rt_rng_num), @truncate(rt_rng_num >> 64) };

    var parse_diagnostics = std.Io.Writer.Allocating.init(arena.allocator());
    const parsed_module = module: {
        var wasm: []const u8 = wasm_binary.contents;
        break :module wasmstint.Module.parse(
            arena.allocator(),
            &wasm,
            &scratch,
            .{ .diagnostics = .init(&parse_diagnostics.writer), .random_seed = rt_rng_seeds[0] },
        ) catch |e| switch (e) {
            error.OutOfMemory => oom("module"),
            error.InvalidWasm => return ErrorCode.failure.print(
                "module {s} is invalid, {s}",
                .{ fmt_wasm_path, parse_diagnostics.written() },
            ),
            error.MalformedWasm => return ErrorCode.failure.print(
                "failed to parse module {s}: {s}",
                .{ fmt_wasm_path, parse_diagnostics.written() },
            ),
            else => return ErrorCode.failure.print(
                "could not parse module {s}: {t}",
                .{ fmt_wasm_path, e },
            ),
        };
    };
    _ = scratch.reset(.retain_capacity);

    std.debug.assert(parse_diagnostics.written().len == 0);
    // TODO: switch to enable lazy validation, also helper thread to validate in background
    const validation_finished = parsed_module.finishCodeValidation(
        arena.allocator(),
        &scratch,
        .init(&parse_diagnostics.writer),
    ) catch |e| switch (e) {
        error.OutOfMemory => oom("module code entries"),
        error.InvalidWasm => return ErrorCode.failure.print(
            "invalid function in module {s}, {s}",
            .{ fmt_wasm_path, parse_diagnostics.written() },
        ),
        error.MalformedWasm => return ErrorCode.failure.print(
            "malformed function in module {s}, {s}",
            .{ fmt_wasm_path, parse_diagnostics.written() },
        ),
        else => return ErrorCode.failure.print(
            "failed to parse function in module {s}: {t}",
            .{ fmt_wasm_path, e },
        ),
    };
    _ = scratch.reset(.retain_capacity);

    std.debug.assert(validation_finished);

    const argv_0 = WasiPreview1.Arguments.String.initTruncated(fmt_wasm_path);
    var wasip1 = WasiPreview1.init(
        arena.allocator(),
        .{
            .arguments = WasiPreview1.Arguments.applicationName(&argv_0),
            .fd_rng_seed = rt_rng_seeds[1],
            .csprng = csprng,
        },
    ) catch |e| switch (e) {
        error.OutOfMemory => oom("WASIp1 state"),
    };
    defer wasip1.deinit();

    var import_error: wasmstint.runtime.ImportProvider.FailedRequest = undefined;
    var module_allocating = wasmstint.runtime.ModuleAllocating.begin(
        parsed_module,
        wasip1.importProvider(),
        arena.allocator(),
        &import_error,
    ) catch |e| switch (e) {
        error.OutOfMemory => oom("module allocating"),
        error.ImportFailure => return ErrorCode.failure.print(
            "could not resolve imports: {f}",
            .{import_error},
        ),
    };

    _ = &module_allocating;

    @panic("TODO");
}

const std = @import("std");
const builtin = @import("builtin");
const ArenaAllocator = std.heap.ArenaAllocator;
const wasmstint = @import("wasmstint");
const cli_args = @import("cli_args");
const WasiPreview1 = @import("WasiPreview1");
