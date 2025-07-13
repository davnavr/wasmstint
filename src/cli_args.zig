pub const ArgIterator = struct {
    remaining: []const [:0]const u8,

    fn initComptime(comptime args: []const [:0]const u8) ArgIterator {
        return .{ .remaining = args };
    }

    fn initProcessArgs(arena: *ArenaAllocator) Oom!ArgIterator {
        return .{
            .remaining = switch (builtin.os.tag) {
                .wasi => (try std.process.ArgIteratorWasi.init(arena.allocator())).args,
                .windows => try std.process.argsAlloc(arena.allocator()),
                else => posix: {
                    var args = try arena.allocator().alloc(
                        [:0]const u8,
                        std.os.argv.len,
                    );
                    errdefer comptime unreachable;

                    for (0.., std.os.argv) |i, a| {
                        args[i] = std.mem.sliceTo(a, 0);
                    }

                    break :posix args;
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

    pub fn nextAlloc(args: *ArgIterator, arena: *ArenaAllocator) Oom!?[:0]u8 {
        const a = args.next() orelse return null;
        return try arena.allocator().dupeZ(u8, a);
    }
};

pub const Flag = struct {
    pub const Info = struct {
        long: [:0]const u8,
        short: ?u8 = null,
        description: [:0]const u8 = "",

        fn names(comptime info: Info) [:0]const u8 {
            return "--" ++ info.long ++
                (if (info.short) |short| "/-" ++ &.{short} else "");
        }
    };

    info: Info,
    args_help: [:0]const u8 = "",
    type: type,

    pub const Diagnostics = struct {
        message: [:0]const u8,

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
                diagnostics.* = .{
                    .message = try std.fmt.allocPrintZ(arena.allocator(), fmt, args),
                };
            }

            return InvalidError.InvalidCliFlag;
        }
    };

    const InvalidError = error{
        /// Must only be returned by `Diagnostics` methods.
        InvalidCliFlag,
    };

    pub const FinishError = InvalidError || Oom;
    pub const ParseError = error{PrintCliUsage} || FinishError;

    pub fn init(
        comptime info: Info,
        comptime args_help: [:0]const u8,
        comptime ParserState: type,
        comptime ParserResult: type,
        comptime default_state_value: ParserState,
        comptime parser: fn (
            args: *ArgIterator,
            arena: *ArenaAllocator,
            diagnostics: ?*Diagnostics,
            state: *ParserState,
        ) ParseError!void,
        comptime parser_finish: fn (
            ParserState,
            diagnostics: ?*Diagnostics,
        ) FinishError!ParserResult,
    ) Flag {
        comptime {
            std.debug.assert(info.long[0] != '-');
            if (info.short) |short| std.debug.assert(std.ascii.isAlphanumeric(short));
        }

        return .{
            .info = info,
            .args_help = args_help,
            .type = struct {
                pub const State = ParserState;
                pub const Result = ParserResult;
                pub const parse = parser;
                pub const finish = parser_finish;
                pub const default_state: State = default_state_value;
            },
        };
    }

    fn help_parser(
        _: *ArgIterator,
        _: *ArenaAllocator,
        _: ?*Diagnostics,
        _: *void,
    ) ParseError!void {
        return ParseError.PrintCliUsage;
    }

    fn idFinish(
        comptime State: type,
        comptime Result: type,
    ) fn (State, ?*Diagnostics) FinishError!Result {
        return struct {
            fn finish(state: State, _: ?*Diagnostics) FinishError!Result {
                return state;
            }
        }.finish;
    }

    pub const help = Flag.init(
        .{
            .long = "help",
            .short = 'h',
            .description = "Print this help message and exit",
        },
        "",
        void,
        void,
        {},
        help_parser,
        idFinish(void, void),
    );

    fn finishRequiredFromOptional(
        comptime info: Info,
        comptime T: type,
    ) fn (?T, ?*Diagnostics) FinishError!T {
        const flag_names = comptime info.names();
        return struct {
            fn finish(state: ?T, diagnostics: ?*Diagnostics) FinishError!T {
                return state orelse Diagnostics.report(
                    diagnostics,
                    "missing required flag " ++ flag_names,
                );
            }
        }.finish;
    }

    pub fn oneArg(comptime info: Info, comptime arg_name: [:0]const u8) Flag {
        const flag_names = comptime info.names();
        const Parser = struct {
            fn parse(
                args: *ArgIterator,
                arena: *ArenaAllocator,
                diagnostics: ?*Diagnostics,
                state: *?[:0]const u8,
            ) ParseError!void {
                if (state.* != null) {
                    return Diagnostics.report(
                        diagnostics,
                        "cannot specify flag " ++ flag_names ++ " more than once",
                    );
                }

                state.* = try args.nextAlloc(arena) orelse return Diagnostics.report(
                    diagnostics,
                    "missing " ++ arg_name ++ " argument for flag " ++ flag_names,
                );
            }
        };

        return Flag.init(
            info,
            arg_name,
            ?[:0]const u8,
            [:0]const u8,
            null,
            Parser.parse,
            finishRequiredFromOptional(info, [:0]const u8),
        );
    }

    pub fn parseUnsigned(
        comptime info: Info,
        comptime arg_name: ?[:0]const u8,
        comptime T: type,
    ) Flag {
        const used_arg_name = arg_name orelse "INTEGER";
        const flag_names = comptime info.names();

        const Parser = struct {
            fn parse(
                args: *ArgIterator,
                arena: *ArenaAllocator,
                diagnostics: ?*Diagnostics,
                state: *?T,
            ) ParseError!void {
                if (state.* != null) {
                    return Diagnostics.report(
                        diagnostics,
                        "cannot specify flag " ++ flag_names ++ " more than once",
                    );
                }

                const int_string = args.next() orelse return Diagnostics.report(
                    diagnostics,
                    "missing " ++ used_arg_name ++ " argument for flag " ++ flag_names,
                );

                state.* = std.fmt.parseUnsigned(T, int_string, 0) catch |e| return switch (e) {
                    error.Overflow => Diagnostics.reportFmt(
                        diagnostics,
                        arena,
                        "flag " ++ flag_names ++ " does not accept {s}, a value greater than " ++
                            std.fmt.comptimePrint("{}", .{std.math.maxInt(T)}),
                        .{int_string},
                    ),
                    error.InvalidCharacter => Diagnostics.reportFmt(
                        diagnostics,
                        arena,
                        "'{}' is not a valid integer argument for flag " ++ flag_names,
                        .{std.unicode.fmtUtf8(int_string)},
                    ),
                };
            }
        };

        return Flag.init(
            info,
            "<" ++ used_arg_name ++ ">",
            ?T,
            T,
            null,
            Parser.parse,
            finishRequiredFromOptional(info, T),
        );
    }

    pub fn optional(comptime flag: Flag) Flag {
        std.debug.assert(?flag.type.Result == flag.type.State);

        const T = flag.type.Result;
        const Parser = struct {
            fn finish(state: ?T, diagnostics: ?*Diagnostics) FinishError!?T {
                return if (state) |not_null|
                    try flag.type.finish(not_null, diagnostics)
                else
                    null;
            }
        };

        return Flag.init(
            flag.info,
            "[" ++ flag.args_help ++ "]",
            ?T,
            ?T,
            null,
            flag.type.parse,
            Parser.finish,
        );
    }
};

/// Simple CLI argument parser.
pub fn CliArgs(comptime flags: []const Flag) type {
    return struct {
        const Self = @This();

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
                            .type = f.type.State,
                            .default_value_ptr = &f.type.default_state,
                            .is_comptime = false,
                            .alignment = 0,
                        };
                    }
                    break :fields &fields;
                },
            },
        });

        pub const Parsed = @Type(.{
            .@"struct" = Type.Struct{
                .layout = .auto,
                .decls = &.{},
                .is_tuple = false,
                .fields = fields: {
                    var fields: [flags.len]Type.StructField = undefined;
                    for (&fields, flags) |*struct_field, f| {
                        struct_field.* = .{
                            .name = f.info.long,
                            .type = f.type.Result,
                            .default_value_ptr = null,
                            .is_comptime = false,
                            .alignment = 0,
                        };
                    }
                    break :fields &fields;
                },
            },
        });

        pub const FlagEnum = @Type(.{
            .@"enum" = Type.Enum{
                .tag_type = std.math.IntFittingRange(0, flags.len -| 1),
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

        flags: FlagLookup,

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

        pub fn init(allocator: std.mem.Allocator) Oom!Self {
            var lookup = FlagLookup.empty;
            try lookup.ensureTotalCapacity(allocator, all_flags.len);
            errdefer comptime unreachable;
            for (all_flags) |entry| {
                lookup.putAssumeCapacityNoClobber(entry.s, entry.flag);
            }

            return .{ .flags = lookup };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.flags.deinit(allocator);
            self.* = undefined;
        }

        pub const ParseError = Flag.ParseError;

        pub fn parseRemaining(
            self: *Self,
            args: *ArgIterator,
            arena: *ArenaAllocator,
            diagnostics: ?*Flag.Diagnostics,
        ) ParseError!Parsed {
            var state = State{};
            while (args.next()) |flag_arg| {
                const chosen_flag: FlagEnum = self.flags.get(flag_arg) orelse
                    return Flag.Diagnostics.reportFmt(
                        diagnostics,
                        arena,
                        "unknown flag '{}'",
                        .{std.unicode.fmtUtf8(flag_arg)},
                    );

                switch (chosen_flag) {
                    inline else => |f| {
                        const known_flag = comptime flags[@intFromEnum(f)];

                        comptime {
                            std.debug.assert(std.mem.eql(u8, @tagName(f), known_flag.info.long));
                        }

                        try known_flag.type.parse(
                            args,
                            arena,
                            diagnostics,
                            &@field(state, known_flag.info.long),
                        );
                    },
                }
            }

            var result: Parsed = undefined;
            inline for (flags) |f| {
                @field(result, f.info.long) =
                    try f.type.finish(@field(state, f.info.long), diagnostics);
            }

            return result;
        }

        pub fn parseProcessArgs(
            self: *Self,
            scratch: *ArenaAllocator,
            arena: *ArenaAllocator,
            diagnostics: ?*Flag.Diagnostics,
        ) ParseError!Parsed {
            var args = try ArgIterator.initProcessArgs(scratch);
            return self.parseRemaining(&args, arena, diagnostics);
        }

        pub fn parseComptime(
            self: *Self,
            comptime args: []const [:0]const u8,
            arena: *ArenaAllocator,
            diagnostics: ?*Flag.Diagnostics,
        ) ParseError!Parsed {
            var args_iter = ArgIterator.initComptime(args);
            return self.parseRemaining(&args_iter, arena, diagnostics);
        }
    };
}

fn expectPrintCliUsage(
    parser: anytype,
    arena: *ArenaAllocator,
    comptime input: []const [:0]const u8,
) !void {
    try std.testing.expectError(
        Flag.ParseError.PrintCliUsage,
        parser.parseComptime(input, arena, null),
    );
}

fn expectFlagInvalidError(
    parser: anytype,
    arena: *ArenaAllocator,
    comptime input: []const [:0]const u8,
    expected_message: []const u8,
) !void {
    var diagnostics: Flag.Diagnostics = undefined;
    try std.testing.expectError(
        Flag.ParseError.InvalidCliFlag,
        parser.parseComptime(input, arena, &diagnostics),
    );

    try std.testing.expectEqualStrings(expected_message, diagnostics);
}

test "simple" {
    const ExampleArgs = CliArgs(&.{
        Flag.help,
        Flag.parseUnsigned(.{ .long = "foo" }, null, u32).optional(),
        Flag.oneArg(.{ .long = "bar" }, "STRING").optional(),
    });

    var parser = try ExampleArgs.init(std.testing.allocator);
    defer parser.deinit(std.testing.allocator);

    var arena = ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    try expectPrintCliUsage(&parser, &arena, &.{"--help"});
    try expectPrintCliUsage(&parser, &arena, &.{"-h"});
    try expectPrintCliUsage(&parser, &arena, &.{ "-h", "--foo", "42" });
    try expectPrintCliUsage(&parser, &arena, &.{ "--help", "--invalid" });
    try expectPrintCliUsage(&parser, &arena, &.{ "--foo", "123", "--help" });
    try expectPrintCliUsage(&parser, &arena, &.{ "--help", "--foo", "123", "--bar", "--help" });
}

fn expectSuccessfulParse(
    parser: anytype,
    arena: *ArenaAllocator,
    comptime input: []const [:0]const u8,
    expected: std.meta.Child(@TypeOf(parser)).Parsed,
) !void {
    var diagnostics: Flag.Diagnostics = undefined;
    const result: std.meta.Child(@TypeOf(parser)).Parsed = parser.parseComptime(
        input,
        arena,
        &diagnostics,
    ) catch |e| {
        if (e == Flag.ParseError.InvalidCliFlag) {
            std.debug.print("{s}", .{diagnostics.message});
        }

        return e;
    };

    try std.testing.expectEqual(expected, result);
}

test "required" {
    const ExampleArgs = CliArgs(&.{
        Flag.help,
        Flag.parseUnsigned(.{ .long = "bar" }, null, u32),
    });

    var parser = try ExampleArgs.init(std.testing.allocator);
    defer parser.deinit(std.testing.allocator);

    var arena = ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    try expectPrintCliUsage(&parser, &arena, &.{"--help"});
    try expectSuccessfulParse(
        &parser,
        &arena,
        &.{ "--bar", "456" },
        .{ .help = {}, .bar = 456 },
    );
}

const std = @import("std");
const Type = std.builtin.Type;
const builtin = @import("builtin");
const ArenaAllocator = std.heap.ArenaAllocator;
const Oom = std.mem.Allocator.Error;
