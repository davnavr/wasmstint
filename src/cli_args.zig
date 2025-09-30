// No, I don't want to reimplement `std.process.ArgIteratorWindows`, and by extension, Windows
// argument parsing just to get WTF-16 strings.

// /// A string of platform-specific characters passed as a command-line argument.
// ///
// /// Similar to Rust's `std::ffi::OsStr`.
// pub const Arg = struct {
//     const Encoding = enum { wtf8, wtf16le };
//
//     pub const encoding: Encoding = if (builtin.os.tag == .windows) .wtf16le else .wtf8;
//
//     pub const Inner = switch (encoding) {
//         .wtf16 => [:0]const u16,
//         .wtf8 => [:0]const u8,
//     };
//
//     inner: Inner,
//
//     pub fn format(arg: Arg, writer: *Writer) Writer.Error!void {
//         switch (encoding) {
//             .wtf8 => try std.unicode.fmtUtf8(arg.inner).format(writer),
//         }
//     }
// };

pub const ArgIterator = struct {
    remaining: []const [:0]const u8,

    fn initComptime(comptime args: []const [:0]const u8) ArgIterator {
        return .{ .remaining = args };
    }

    pub fn initProcessArgs(arena: *ArenaAllocator) Oom!ArgIterator {
        return .{
            .remaining = args: switch (builtin.os.tag) {
                .wasi => (try std.process.ArgIteratorWasi.init(arena.allocator())).args,
                .windows => {
                    // Copied from `std.process.ArgIterator.initWithAllocator`.
                    const command_line = std.os.windows.peb().ProcessParameters.CommandLine;
                    var args = try std.process.ArgIteratorWindows.init(
                        arena.allocator(),
                        command_line.Buffer.?[0..(command_line.Length / 2)],
                    );

                    var arg_list = std.ArrayList([:0]const u8).empty;
                    // Arguments are allocated in separate parts of `args.buffer` in the `arena`.
                    while (args.next()) |a| {
                        try arg_list.append(arena.allocator(), a);
                    }

                    break :args arg_list.items;
                },
                else => {
                    var args = try arena.allocator().alloc(
                        [:0]const u8,
                        std.os.argv.len,
                    );
                    errdefer comptime unreachable;

                    for (0.., std.os.argv) |i, a| {
                        args[i] = std.mem.sliceTo(a, 0);
                    }

                    break :args args;
                },
            },
        };
    }

    pub fn next(args: *ArgIterator) ?[:0]const u8 {
        if (args.remaining.len == 0) {
            return null;
        } else {
            const a = args.remaining[0];
            args.remaining = args.remaining[1..];
            return a;
        }
    }

    pub fn nextDupe(args: *ArgIterator, arena: *ArenaAllocator) Oom!?[:0]u8 {
        const a = args.next() orelse return null;
        return try arena.allocator().dupeZ(u8, a);
    }
};

pub const Flag = struct {
    const Info = struct {
        long: [:0]const u8,
        short: ?u8 = null,
        description: [:0]const u8 = "",

        fn names(comptime info: Info) [:0]const u8 {
            return "--" ++ info.long ++
                (if (info.short) |short| "/-" ++ .{short} else "");
        }

        fn reportDuplicate(comptime info: Info, diag: ?*Diagnostics) InvalidError {
            return Diagnostics.report(
                diag,
                comptime "cannot specify flag " ++ info.names() ++ " more than once",
            );
        }

        pub fn reportMissing(
            comptime info: Info,
            diag: ?*Diagnostics,
            comptime arg_help: ArgHelp,
        ) InvalidError {
            return Diagnostics.report(
                diag,
                comptime "missing " ++ arg_help.string() ++ " argument for flag " ++ info.names(),
            );
        }
    };

    const ArgHelp = struct {
        optional: bool,
        name: [:0]const u8,

        fn string(comptime arg_help: ArgHelp) []const u8 {
            const name: []const u8 = .{'<'} ++ arg_help.name ++ .{'>'};
            return if (arg_help.optional)
                [1]u8{'['} ++ name ++ [1]u8{']'}
            else
                name;
        }
    };

    info: Info,
    arg_help: ?ArgHelp,
    namespace: type,

    pub const Diagnostics = struct {
        message: []const u8,

        pub fn report(diag: ?*Diagnostics, message: [:0]const u8) InvalidError {
            if (diag) |diagnostics| {
                diagnostics.* = .{ .message = message };
            }

            return InvalidError.InvalidCliFlag;
        }

        pub fn reportFmt(
            diag: ?*Diagnostics,
            arena: *ArenaAllocator,
            comptime fmt: []const u8,
            args: anytype,
        ) (InvalidError || Oom) {
            if (diag) |diagnostics| {
                var writer = try Writer.Allocating.initCapacity(
                    arena.allocator(),
                    comptime fmt.len * 2,
                );

                writer.writer.print(fmt, args) catch |e| switch (e) {
                    Writer.Error.WriteFailed => return Oom.OutOfMemory,
                };

                diagnostics.* = .{ .message = writer.toArrayList().items };
            }

            return InvalidError.InvalidCliFlag;
        }

        pub fn print(
            diag: *const Diagnostics,
            writer: *Writer,
            color: std.Io.tty.Config,
        ) std.Io.tty.Config.SetColorError!void {
            try color.setColor(writer, .bright_red);
            try writer.writeAll("error: ");
            try color.setColor(writer, .reset);
            try writer.writeAll(diag.message);
            try writer.writeByte('\n');
        }
    };

    pub const InvalidError = error{
        /// Must only be returned by `Diagnostics` methods.
        InvalidCliFlag,
    };

    pub const FinishError = InvalidError || Oom;

    pub const HelpError = error{
        /// Used by the `--help` flag to print usage information.
        PrintCliUsage,
    };

    pub const RemainingError = error{
        /// Stop all argument parsing to allow retrieval of the remaining CLI arguments.
        ParseRemainingArguments,
        ParseCustomArgument,
    };

    pub const ParseError = HelpError || RemainingError || FinishError;

    fn init(
        comptime info: Info,
        comptime arg_help: ?ArgHelp,
        comptime ParserState: type,
        comptime initial_parser_state: ParserState,
        comptime ParserResult: type,
        /// Parses any argument strings that come after the flag.
        comptime parseArgs: fn (
            args: *ArgIterator,
            arena: *ArenaAllocator,
            diagnostics: ?*Diagnostics,
            state: ParserState,
        ) ParseError!ParserState,
        /// Takes the parser state, and converts it to the final value inserted in the result
        /// struct.
        comptime parseFinish: fn (
            @TypeOf(initial_parser_state),
            diagnostics: ?*Diagnostics,
        ) FinishError!ParserResult,
    ) Flag {
        comptime {
            std.debug.assert(info.long[0] != '-');
            if (info.short) |short| std.debug.assert(std.ascii.isAlphanumeric(short));
        }

        return .{
            .info = info,
            .arg_help = arg_help,
            .namespace = struct {
                pub const State = ParserState;
                pub const initial_state: State = initial_parser_state;
                pub const Result = ParserResult;
                pub const parse = parseArgs;
                pub const finish = parseFinish;
            },
        };
    }

    fn idFinish(comptime T: type) fn (T, ?*Diagnostics) FinishError!T {
        return struct {
            fn finish(state: T, _: ?*Diagnostics) FinishError!T {
                return state;
            }
        }.finish;
    }

    fn parseHelpArgs(
        args: *ArgIterator,
        arena: *ArenaAllocator,
        diagnostics: ?*Diagnostics,
        state: void,
    ) ParseError!void {
        _ = args;
        _ = arena;
        _ = diagnostics;
        _ = state;
        return error.PrintCliUsage;
    }

    const help = Flag.init(
        .{
            .long = "help",
            .short = 'h',
            .description = "Print this help message and exit",
        },
        null,
        void,
        {},
        void,
        parseHelpArgs,
        idFinish(void),
    );

    fn stopParsing(
        args: *ArgIterator,
        arena: *ArenaAllocator,
        diagnostics: ?*Diagnostics,
        state: void,
    ) ParseError!void {
        _ = args;
        _ = arena;
        _ = diagnostics;
        _ = state;
        return error.ParseRemainingArguments;
    }

    /// Use `remainingArguments()` or `parseRemaining()`.
    pub const remainder = Flag.init(
        .{ .long = "" },
        null,
        void,
        {},
        void,
        stopParsing,
        idFinish(void),
    );

    fn parseCustom(
        args: *ArgIterator,
        arena: *ArenaAllocator,
        diagnostics: ?*Diagnostics,
        state: void,
    ) ParseError!void {
        _ = args;
        _ = arena;
        _ = diagnostics;
        _ = state;
        return error.ParseCustomArgument;
    }

    /// Use `parseRemainingWithCustom()`.
    pub fn custom(comptime info: Info, comptime arg_help: ?ArgHelp) Flag {
        return .init(
            info,
            arg_help,
            void,
            {},
            void,
            parseCustom,
            idFinish(void),
        );
    }

    fn parseBoolean(
        args: *ArgIterator,
        arena: *ArenaAllocator,
        diagnostics: ?*Diagnostics,
        state: bool,
    ) ParseError!bool {
        _ = args;
        _ = arena;
        _ = diagnostics;
        _ = state;
        return true;
    }

    pub fn boolean(comptime info: Info) Flag {
        return Flag.init(
            info,
            null,
            bool,
            false,
            bool,
            parseBoolean,
            idFinish(bool),
        );
    }

    pub fn string(comptime info: Info, comptime arg_name: [:0]const u8) Flag {
        const arg_help = ArgHelp{ .name = arg_name, .optional = true };
        const Parser = struct {
            fn parse(
                args: *ArgIterator,
                arena: *ArenaAllocator,
                diagnostics: ?*Diagnostics,
                state: ?[:0]const u8,
            ) ParseError!?[:0]const u8 {
                return if (state) |_|
                    info.reportDuplicate(diagnostics)
                else
                    try args.nextDupe(arena) orelse info.reportMissing(diagnostics, arg_help);
            }
        };

        return Flag.init(
            info,
            arg_help,
            ?[:0]const u8,
            null,
            ?[:0]const u8,
            Parser.parse,
            idFinish(?[:0]const u8),
        );
    }

    pub fn integerGeneric(
        comptime info: Info,
        comptime arg_name: [:0]const u8,
        comptime T: type,
        comptime parse: fn ([:0]const u8) std.fmt.ParseIntError!T,
    ) Flag {
        const arg_help = ArgHelp{ .name = arg_name, .optional = true };
        const Parser = struct {
            const flag_names = info.names();

            fn parseArg(
                args: *ArgIterator,
                arena: *ArenaAllocator,
                diagnostics: ?*Diagnostics,
                state: ?T,
            ) ParseError!?T {
                if (state != null) {
                    return info.reportDuplicate(diagnostics);
                }

                const str = args.next() orelse return info.reportMissing(diagnostics, arg_help);

                return parse(str) catch |e| switch (e) {
                    error.Overflow => Diagnostics.reportFmt(
                        diagnostics,
                        arena,
                        "flag " ++ flag_names ++ " does not accept {s}, a value greater than " ++
                            std.fmt.comptimePrint("{}", .{std.math.maxInt(T)}),
                        .{str},
                    ),
                    error.InvalidCharacter => Diagnostics.reportFmt(
                        diagnostics,
                        arena,
                        "'{f}' is not a valid integer argument for flag " ++ flag_names,
                        .{std.unicode.fmtUtf8(str)},
                    ),
                };
            }
        };

        return Flag.init(
            info,
            arg_help,
            ?T,
            null,
            ?T,
            Parser.parseArg,
            idFinish(?T),
        );
    }

    pub fn integer(comptime info: Info, comptime arg_name: [:0]const u8, comptime T: type) Flag {
        const Parser = struct {
            fn parse(s: [:0]const u8) std.fmt.ParseIntError!T {
                return switch (@typeInfo(T).int.signedness) {
                    .signed => std.fmt.parseInt(T, s, 0),
                    .unsigned => std.fmt.parseUnsigned(T, s, 0),
                };
            }
        };

        return integerGeneric(info, arg_name, T, Parser.parse);
    }

    pub fn integerSizeSuffix(comptime info: Info, comptime T: type) Flag {
        const Parser = struct {
            fn parse(s: [:0]const u8) std.fmt.ParseIntError!T {
                return std.math.cast(T, try std.fmt.parseIntSizeSuffix(s, 10)) orelse
                    error.Overflow;
            }
        };

        return integerGeneric(info, "SIZE", T, Parser.parse);
    }

    pub fn withDefault(
        comptime flag: Flag,
        comptime default_value: @typeInfo(flag.namespace.State).optional.child,
    ) Flag {
        comptime {
            std.debug.assert(flag.namespace.State == flag.namespace.Result);
        }

        const T = @typeInfo(flag.namespace.State).optional.child;

        const Parser = struct {
            fn finish(state: ?T, _: ?*Diagnostics) FinishError!T {
                return state orelse default_value;
            }
        };

        var new_info = flag.info;
        new_info.description = flag.info.description ++ " (default: " ++ switch (T) {
            []const u8, [:0]const u8 => default_value,
            else => std.fmt.comptimePrint("{any}", .{default_value}),
        } ++ ")";

        return Flag.init(
            new_info,
            flag.arg_help.?,
            ?T,
            null,
            T,
            flag.namespace.parse,
            Parser.finish,
        );
    }

    pub fn required(comptime flag: Flag) Flag {
        comptime {
            std.debug.assert(flag.namespace.State == flag.namespace.Result);
        }

        const T = @typeInfo(flag.namespace.State).optional.child;

        const arg_help = ArgHelp{ .name = flag.arg_help.?.name, .optional = false };
        const Parser = struct {
            fn finish(state: ?T, diag: ?*Diagnostics) FinishError!T {
                return state orelse flag.info.reportMissing(diag, arg_help);
            }
        };

        return Flag.init(
            flag.info,
            arg_help,
            ?T,
            null,
            T,
            flag.namespace.parse,
            Parser.finish,
        );
    }
};

const AppInfo = struct {
    // name: [:0]const u8,
    description: [:0]const u8 = "",
    flags: []const Flag,
};

/// Simple CLI argument parser.
pub fn CliArgs(comptime app_info: AppInfo) type {
    return struct {
        const Self = @This();

        const flags: []const Flag = app_info.flags ++ .{Flag.help};

        pub const State = @Type(.{
            .@"struct" = Type.Struct{
                .layout = .auto,
                .decls = &.{},
                .is_tuple = false,
                .fields = fields: {
                    var fields: [flags.len]Type.StructField = undefined;
                    for (&fields, flags) |*struct_field, f| {
                        struct_field.* = .{
                            .name = f.info.long,
                            .type = f.namespace.State,
                            .default_value_ptr = @as(
                                *const anyopaque,
                                @ptrCast(&f.namespace.initial_state),
                            ),
                            .is_comptime = false,
                            .alignment = @alignOf(f.namespace.State),
                        };
                    }
                    break :fields &fields;
                },
            },
        });

        const non_void_flag_result_count = count: {
            var count = 0;
            for (flags) |f| {
                if (f.namespace.Result != void) {
                    count += 1;
                }
            }
            break :count count;
        };

        pub const Parsed = @Type(.{
            .@"struct" = Type.Struct{
                .layout = .auto,
                .decls = &.{},
                .is_tuple = false,
                .fields = fields: {
                    var fields: [non_void_flag_result_count]Type.StructField = undefined;
                    var fields_idx = 0;
                    for (&fields) |*struct_field| {
                        const f = flags[fields_idx];
                        std.debug.assert(f.namespace.Result != void);
                        struct_field.* = .{
                            .name = f.info.long,
                            .type = f.namespace.Result,
                            .default_value_ptr = null,
                            .is_comptime = false,
                            .alignment = @alignOf(f.namespace.Result),
                        };
                        fields_idx += 1;
                    }
                    std.debug.assert(fields.len == fields_idx);
                    break :fields &fields;
                },
            },
        });

        pub const FlagEnum = @Type(.{
            .@"enum" = Type.Enum{
                .tag_type = std.math.IntFittingRange(0, flags.len - 1),
                .decls = &.{},
                .is_exhaustive = true,
                .fields = fields: {
                    var cases: [flags.len]Type.EnumField = undefined;
                    for (0.., flags, &cases) |i, f, *enum_field| {
                        enum_field.* = .{ .name = f.info.long, .value = i };
                    }
                    break :fields &cases;
                },
            },
        });

        const FlagLookup = std.hash_map.StringHashMapUnmanaged(FlagEnum);

        const all_flags_count_and_more = all_flags_count * 4;

        const flags_map_buffer_len = (@sizeOf(*anyopaque) * 3) + // Header
            std.mem.alignForward(usize, all_flags_count_and_more, @alignOf(*anyopaque)) + // Metadata
            (@sizeOf([]const u8) * all_flags_count_and_more) + // Keys
            std.mem.alignForward(
                usize,
                @sizeOf(FlagEnum) * all_flags_count_and_more,
                @alignOf(*anyopaque),
            );

        flags_map_buffer: [flags_map_buffer_len]u8 align(16) = undefined,
        flags_map: FlagLookup,

        const FlagLookupEntry = struct {
            s: [:0]const u8,
            flag: FlagEnum,
        };

        const all_flags_count: usize = count: {
            var count: usize = 0;
            for (flags) |f| {
                count += 1;
                if (f.info.short) |_| count += 1;
            }
            break :count count;
        };

        const all_flags: [all_flags_count]FlagLookupEntry = flags: {
            @setEvalBranchQuota(all_flags_count);

            var entries: [all_flags_count]FlagLookupEntry = undefined;
            var entries_idx = 0;
            for (flags) |*f| {
                const value = @field(FlagEnum, f.info.long);
                entries[entries_idx] = .{ .s = "--" ++ f.info.long, .flag = value };
                entries_idx += 1;

                if (f.info.short) |short| {
                    entries[entries_idx] = .{ .s = &.{ '-', short }, .flag = value };
                    entries_idx += 1;
                }
            }

            std.debug.assert(all_flags_count == entries_idx);
            break :flags entries;
        };

        pub fn init(parser: *Self) void {
            parser.* = .{ .flags_map = .empty };
            var map_buf = std.heap.FixedBufferAllocator.init(&parser.flags_map_buffer);
            parser.flags_map.ensureTotalCapacity(map_buf.allocator(), all_flags.len) catch
                unreachable;

            for (all_flags) |entry| {
                parser.flags_map.putAssumeCapacityNoClobber(entry.s, entry.flag);
            }
        }

        pub const ParseError = Flag.HelpError || Flag.FinishError;

        fn ParseCustomArguments(comptime Context: type) type {
            return fn (
                Context,
                comptime FlagEnum,
                *ArgIterator,
                arena: *ArenaAllocator,
                ?*Flag.Diagnostics,
            ) Flag.FinishError!void;
        }

        pub fn parseRemainingWithCustom(
            self: *const Self,
            args: *ArgIterator,
            arena: *ArenaAllocator,
            diagnostics: ?*Flag.Diagnostics,
            context: anytype,
            comptime parseCustomArguments: ParseCustomArguments(@TypeOf(context)),
        ) ParseError!Parsed {
            var state = State{};
            while (args.next()) |flag_arg| {
                const chosen_flag: FlagEnum = self.flags_map.get(flag_arg) orelse {
                    return Flag.Diagnostics.reportFmt(
                        diagnostics,
                        arena,
                        "unknown flag '{f}'",
                        .{std.unicode.fmtUtf8(flag_arg)},
                    );
                };

                switch (chosen_flag) {
                    inline else => |f| {
                        const known_flag = comptime flags[@intFromEnum(f)];

                        comptime {
                            std.debug.assert(std.mem.eql(u8, @tagName(f), known_flag.info.long));
                        }

                        @field(state, known_flag.info.long) = known_flag.namespace.parse(
                            args,
                            arena,
                            diagnostics,
                            @field(state, known_flag.info.long),
                        ) catch |e| switch (e) {
                            error.ParseRemainingArguments => break,
                            error.ParseCustomArgument => {
                                try parseCustomArguments(
                                    context,
                                    f,
                                    args,
                                    arena,
                                    diagnostics,
                                );
                                continue;
                            },
                            else => |err| return err,
                        };
                    },
                }
            }

            var result: Parsed = undefined;
            inline for (flags) |f| {
                if (@hasField(Parsed, f.info.long)) {
                    @field(result, f.info.long) =
                        try f.namespace.finish(@field(state, f.info.long), diagnostics);
                }
            }

            return result;
        }

        fn noCustomArguments(
            _: void,
            comptime _: FlagEnum,
            _: *ArgIterator,
            _: *ArenaAllocator,
            _: ?*Flag.Diagnostics,
        ) Flag.FinishError!void {}

        pub fn parseRemaining(
            self: *const Self,
            args: *ArgIterator,
            arena: *ArenaAllocator,
            diagnostics: ?*Flag.Diagnostics,
        ) ParseError!Parsed {
            return self.parseRemainingWithCustom(
                args,
                arena,
                diagnostics,
                {},
                noCustomArguments,
            );
        }

        pub fn parseProcessArgs(
            self: *const Self,
            scratch: *ArenaAllocator,
            arena: *ArenaAllocator,
            diagnostics: ?*Flag.Diagnostics,
        ) ParseError!Parsed {
            var args = try ArgIterator.initProcessArgs(scratch);
            _ = args.next().?;
            return self.parseRemaining(&args, arena, diagnostics);
        }

        pub fn parseComptime(
            self: *const Self,
            comptime args: []const [:0]const u8,
            arena: *ArenaAllocator,
            diagnostics: ?*Flag.Diagnostics,
        ) ParseError!Parsed {
            var args_iter = ArgIterator.initComptime(args);
            return self.parseRemaining(&args_iter, arena, diagnostics);
        }

        pub fn printUsage(
            writer: *Writer,
            color: std.Io.tty.Config,
        ) std.Io.tty.Config.SetColorError!void {
            @branchHint(.cold);

            if (comptime app_info.description.len > 0) {
                try writer.writeAll(app_info.description ++ "\n\n");
            }

            try writer.writeAll("OPTIONS:\n");

            inline for (flags) |f| {
                if (f.namespace == Flag.remainder.namespace) {
                    continue;
                }

                try writer.writeByte('\n');

                if (f.info.short) |short| {
                    try color.setColor(writer, .bright_cyan);
                    try writer.writeAll(&[2]u8{ '-', short });
                    try color.setColor(writer, .reset);
                    try writer.writeAll(", ");
                }

                try color.setColor(writer, .bright_cyan);
                const has_args_help = f.arg_help != null;
                try writer.writeAll("--" ++ f.info.long ++ (if (has_args_help) " " else ""));

                if (has_args_help) {
                    try color.setColor(writer, .bright_blue);
                    try writer.writeAll(f.arg_help.?.string());
                }

                try color.setColor(writer, .reset);
                if (f.info.description.len > 0) {
                    try writer.writeAll("\n    " ++ f.info.description ++ "\n");
                } else {
                    try writer.writeByte('\n');
                }
            }
        }

        fn exitBadArguments(diagnostics: ?Flag.Diagnostics) noreturn {
            @branchHint(.cold);
            {
                var stderr_buffer: [1024]u8 align(16) = undefined;
                const stderr = std.debug.lockStderrWriter(&stderr_buffer);
                defer std.debug.unlockStderrWriter();

                const color = std.Io.tty.detectConfig(std.fs.File.stderr());

                if (diagnostics) |diag| {
                    diag.print(stderr, color) catch {};
                } else {
                    printUsage(stderr, color) catch {};
                }
            }

            if (builtin.os.tag == .windows) {
                std.os.windows.kernel32.ExitProcess(std.math.maxInt(u32));
            } else {
                std.process.exit(2);
            }
        }

        inline fn parsedArgumentsOrExit(
            result: ParseError!Parsed,
            diagnostics: *const Flag.Diagnostics,
        ) Oom!Parsed {
            exitBadArguments(diag: {
                // Can't store error{PrintCliUsage, InvalidCliFlag}, Zig bug?
                return result catch |e| switch (e) {
                    Oom.OutOfMemory => |oom| oom,
                    Flag.HelpError.PrintCliUsage => break :diag null,
                    Flag.FinishError.InvalidCliFlag => break :diag diagnostics.*,
                };
            });
        }

        pub fn remainingArgumentsWithCustom(
            self: *const Self,
            args: *ArgIterator,
            arena: *ArenaAllocator,
            context: anytype,
            comptime parseCustomArguments: ParseCustomArguments(@TypeOf(context)),
        ) Oom!Parsed {
            var diagnostics: Flag.Diagnostics = undefined;
            return parsedArgumentsOrExit(
                self.parseRemainingWithCustom(
                    args,
                    arena,
                    &diagnostics,
                    context,
                    parseCustomArguments,
                ),
                &diagnostics,
            );
        }

        pub fn remainingArguments(
            self: *const Self,
            args: *ArgIterator,
            arena: *ArenaAllocator,
        ) Oom!Parsed {
            return self.remainingArgumentsWithCustom(args, arena, {}, noCustomArguments);
        }

        pub fn programArguments(
            self: *const Self,
            scratch: *ArenaAllocator,
            arena: *ArenaAllocator,
        ) Oom!Parsed {
            var diagnostics: Flag.Diagnostics = undefined;
            return parsedArgumentsOrExit(
                self.parseProcessArgs(scratch, arena, &diagnostics),
                &diagnostics,
            );
        }
    };
}

const std = @import("std");
const Writer = std.Io.Writer;
const Type = std.builtin.Type;
const builtin = @import("builtin");
const ArenaAllocator = std.heap.ArenaAllocator;
const Oom = std.mem.Allocator.Error;

fn expectPrintCliUsage(
    parser: anytype,
    comptime input: []const [:0]const u8,
) !void {
    var arena = ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(
        Flag.ParseError.PrintCliUsage,
        parser.parseComptime(input, &arena, null),
    );
}

fn expectInvalidCliFlag(
    parser: anytype,
    comptime input: []const [:0]const u8,
    expected_message: []const u8,
) !void {
    var arena = ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var diagnostics: Flag.Diagnostics = undefined;
    try std.testing.expectError(
        Flag.ParseError.InvalidCliFlag,
        parser.parseComptime(input, &arena, &diagnostics),
    );

    try std.testing.expectEqualStrings(expected_message, diagnostics.message);
}

test "simple" {
    const ExampleArgs = CliArgs(.{
        .flags = &.{
            Flag.integer(.{ .long = "foo" }, "INTEGER", u32),
            Flag.string(.{ .long = "bar" }, "STRING"),
            Flag.boolean(.{ .long = "switch" }),
        },
    });

    var parser: ExampleArgs = undefined;
    parser.init();

    try expectPrintCliUsage(&parser, &.{"--help"});
    try expectPrintCliUsage(&parser, &.{"-h"});
    try expectPrintCliUsage(&parser, &.{ "-h", "--foo", "42" });
    try expectPrintCliUsage(&parser, &.{ "--help", "--invalid" });
    try expectPrintCliUsage(&parser, &.{ "--foo", "123", "--help" });
    try expectPrintCliUsage(&parser, &.{ "--help", "--foo", "123", "--bar", "--help" });
    try expectPrintCliUsage(&parser, &.{ "--switch", "--foo", "12345678", "--switch", "--help" });
}

fn expectSuccessfulParse(
    parser: anytype,
    comptime input: []const [:0]const u8,
    expected: std.meta.Child(@TypeOf(parser)).Parsed,
) !void {
    var arena = ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var diagnostics: Flag.Diagnostics = undefined;
    const result: std.meta.Child(@TypeOf(parser)).Parsed = parser.parseComptime(
        input,
        &arena,
        &diagnostics,
    ) catch |e| {
        if (e == Flag.ParseError.InvalidCliFlag) {
            std.debug.print("{s}\n", .{diagnostics.message});
        }

        return e;
    };

    try std.testing.expectEqual(expected, result);
}

test "required" {
    const ExampleArgs = CliArgs(.{
        .flags = &.{
            Flag.integer(.{ .long = "bar" }, "INTEGER", u32).required(),
            Flag.boolean(.{ .long = "do-something" }),
        },
    });

    var parser: ExampleArgs = undefined;
    parser.init();

    try expectPrintCliUsage(&parser, &.{"--help"});
    try expectSuccessfulParse(
        &parser,
        &.{ "--bar", "456" },
        .{ .bar = 456, .@"do-something" = false },
    );
    try expectSuccessfulParse(
        &parser,
        &.{ "--bar", "4294967295", "--do-something" },
        .{ .bar = std.math.maxInt(u32), .@"do-something" = true },
    );
}

test "remainder" {
    const ExampleArgs = CliArgs(.{
        .flags = &.{
            Flag.integer(.{ .long = "loquaciousness" }, "INTEGER", u64).required(),
            Flag.remainder,
        },
    });

    var parser: ExampleArgs = undefined;
    parser.init();

    try expectSuccessfulParse(
        &parser,
        &.{ "--loquaciousness", "999999" },
        .{ .loquaciousness = 999999 },
    );
    try expectInvalidCliFlag(
        &parser,
        &.{ "--loquaciousness", "1", "--invalid" },
        "unknown flag '--invalid'",
    );
    try expectSuccessfulParse(
        &parser,
        &.{ "--loquaciousness", "9999999", "--" },
        .{ .loquaciousness = 9999999 },
    );
    try expectSuccessfulParse(
        &parser,
        &.{ "--loquaciousness", "999", "--", "--invalid" },
        .{ .loquaciousness = 999 },
    );
}
