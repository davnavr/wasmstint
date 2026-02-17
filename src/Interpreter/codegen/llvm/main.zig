//! Generates an LLVM IR bitcode (`.bc`) file implementing wasmstint's opcode handlers.

pub fn main(init: std.process.Init.Minimal) Oom!void {
    var io_impl = std.Io.Threaded.init_single_threaded;
    const io = io_impl.ioBasic();

    var scratch = ArenaAllocator.init(std.heap.page_allocator);

    var cli_args = try init.args.iterateAllocator(scratch.allocator());
    _ = cli_args.next().?;

    var arena = ArenaAllocator.init(std.heap.page_allocator); // process lifetime

    const options = options: {
        const options_str = cli_args.next().?;
        break :options std.zon.parse.fromSliceAlloc(
            Builder.Options,
            arena.allocator(),
            options_str,
            null,
            .{ .free_on_error = false },
        ) catch |e| switch (e) {
            error.ParseZon => std.debug.panic("invalid options:\n{s}\n", .{options_str}),
            else => |err| return err,
        };
    };

    const cwd = std.Io.Dir.cwd();
    const target_info = target: {
        const path = cli_args.next().?;
        const contents = cwd.readFileAllocOptions(
            io,
            path,
            scratch.allocator(),
            .limited(4096 * 4),
            .@"16",
            0,
        ) catch |e| std.debug.panic("cannot open {s}: {t}", .{ path, e });

        break :target std.zon.parse.fromSliceAlloc(
            Builder.TargetInfo,
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
            std.debug.panic("cannot open {s}: {t}", .{ path, e });
    };

    std.debug.assert(cli_args.next() == null);

    const target_query = std.Target.Query.parse(.{
        .arch_os_abi = options.target.triple,
        .cpu_features = options.target.cpu_features,
    }) catch |e| switch (e) {
        error.UnknownCpuFeature => std.debug.panic(
            "unknown cpu flag in {s}",
            .{options.target.cpu_features},
        ),
        else => |err| std.debug.panic(
            "invalid target triple {s}: {t}",
            .{ options.target.triple, err },
        ),
    };
    const target = std.zig.system.resolveTargetQuery(io, target_query) catch |e| std.debug.panic(
        "{t}: could not resolve target query {s}{s}",
        .{ e, options.target.triple, options.target.cpu_features },
    );

    var gpa = std.heap.DebugAllocator(.{}).init;
    _ = scratch.reset(.retain_capacity);
    var builder: Builder = undefined;
    try builder.init(gpa.allocator(), &scratch, .{
        .options = options,
        .target_info = target_info,
        .target = &target,
    });
    try buildLlvmModule(&builder);

    const bitcode: []const u32 = try builder.module.toBitcode(std.heap.page_allocator, .{
        .name = "wasmstint-codegen-llvm",
        .version = .{ .major = 0, .minor = 0, .patch = 0 },
    });

    bc_file.writeStreamingAll(io, @ptrCast(bitcode)) catch |e| std.debug.panic(
        "cannot write bitcode: {t}",
        .{e},
    );
}

const Builder = struct {
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

    options: Options,
    target: *const std.Target,
    target_info: TargetInfo,
    scratch: *ArenaAllocator,
    module: llvm.Builder,
    ffi_call_conv: CallConv,
    string_constants: struct {
        @"target-cpu": String = .none,
        @"target-features": String = .none,
    } = .{},
    target_cpu: String = .none,
    target_features: String = .none,
    opcode_handler: struct {
        call_conv: CallConv,
        type: Type,
        fn_attrs: FunctionAttributes,
    },
    dispatch_tables: struct {
        byte: Global.Index = .none,
    } = .{},
    byte_opcode_lookup: std.EnumSet(opcodes.ByteOpcode) = .initEmpty(),

    fn init(
        b: *Builder,
        gpa: std.mem.Allocator,
        scratch: *ArenaAllocator,
        config: struct {
            options: Options,
            target: *const std.Target,
            target_info: TargetInfo,
        },
    ) Oom!void {
        b.* = Builder{
            .options = config.options,
            .target = config.target,
            .target_info = config.target_info,
            .scratch = scratch,
            .module = try llvm.Builder.init(.{
                .allocator = gpa,
                .strip = config.options.strip,
                .name = "wasmstint.interpreter",
                .target = config.target,
                .triple = config.target_info.triple,
            }),
            .ffi_call_conv = if (config.target.cpu.arch == .x86_64 and config.options.use_llvm)
                .x86_regcallcc // Zig's x86 backend doesn't support regcall
            else
                .ccc,
            .opcode_handler = undefined,
        };

        inline for (comptime std.meta.fieldNames(@FieldType(Builder, "string_constants"))) |name| {
            @field(b.string_constants, name) = try b.module.string(name);
        }

        if (b.target.cpu.model.llvm_name) |name| {
            b.target_cpu = try b.module.string(name);
        }

        var target_features = try std.ArrayList(u8).initCapacity(
            scratch.allocator(),
            b.options.target.cpu_features.len,
        );

        const all_features = b.target.cpu.arch.allFeaturesList();
        for (all_features) |feat| {
            const idx: std.Target.Cpu.Feature.Set.Index = feat.index;
            const feat_name = feat.llvm_name orelse continue;
            const prefix: u8 = if (b.target.cpu.features.isEnabled(idx))
                '+'
            else
                '-';

            const not_first = target_features.items.len > 0;
            try target_features.ensureUnusedCapacity(
                scratch.allocator(),
                @as(usize, @intFromBool(not_first)) + 1 + feat_name.len,
            );

            if (not_first) {
                try target_features.append(scratch.allocator(), ',');
            }
            target_features.appendAssumeCapacity(prefix);
            target_features.appendSliceAssumeCapacity(feat_name);
        }

        b.target_features = try b.module.string(target_features.items);
        b.opcode_handler = .{
            .call_conv = switch (config.target.cpu.arch) {
                .x86_64, .aarch64, .riscv64 => .ghccc,
                else => .tailcc,
            },
            .type = try b.fnType(.i32, &@as([10]Type, @splat(Type.ptr))),
            .fn_attrs = attrs: {
                var attrs = FunctionAttributes.Wip{};
                defer attrs.deinit(&b.module);
                try b.commonFnAttributes(&attrs);
                try b.fnAttributes(&attrs, .{
                    .function = &.{},
                });
                break :attrs try attrs.finish(&b.module);
            },
        };
    }

    fn strtabStringConcat(b: *Builder, s: []const []const u8) Oom!StrtabString {
        _ = b.scratch.reset(.retain_capacity);
        return try b.module.strtabString(try std.mem.concat(b.scratch.allocator(), u8, s));
    }

    fn strtabStringSymbolPrefixed(b: *Builder, name: []const u8) Oom!StrtabString {
        return try b.strtabStringConcat(&.{ b.options.symbol_prefix, name });
    }

    /// `wasmstint` does not use `varargs`.
    fn fnType(b: *Builder, ret_type: Type, param_types: []const Type) Oom!Type {
        return try b.module.fnType(ret_type, param_types, .normal);
    }

    const FunctionOptions = struct {
        linkage: llvm.Builder.Linkage = .external,
        preemption: llvm.Builder.Preemption = .dso_preemptable,
    };

    fn fnAttributes(
        b: *Builder,
        wip: *FunctionAttributes.Wip,
        attributes: struct {
            function: []const Attribute = &.{},
        },
    ) Oom!void {
        for (attributes.function) |attr| {
            try wip.addFnAttr(attr, &b.module);
        }
    }

    fn setFnAttributes(b: *Builder, func: Function.Index, wip: *FunctionAttributes.Wip) Oom!void {
        func.setAttributes(try wip.finish(&b.module), &b.module);
    }

    fn commonFnAttributes(b: *Builder, wip: *FunctionAttributes.Wip) Oom!void {
        try b.fnAttributes(wip, .{
            .function = &[_]Attribute{ .nounwind, .willreturn },
        });

        // This is what the Zig compiler does
        if (b.options.optimize == .ReleaseSmall) {
            try b.fnAttributes(wip, .{ .function = &[2]Attribute{ .minsize, .optsize } });
        }

        if (b.target_cpu != .none) {
            try b.fnAttributes(wip, .{
                .function = &[1]Attribute{
                    .{
                        .string = .{
                            .kind = b.string_constants.@"target-cpu",
                            .value = b.target_cpu,
                        },
                    },
                },
            });
        }

        if (b.target_features != .empty) {
            try b.fnAttributes(wip, .{
                .function = &[1]Attribute{
                    .{
                        .string = .{
                            .kind = b.string_constants.@"target-features",
                            .value = b.target_features,
                        },
                    },
                },
            });
        }

        // TODO: bool option for uwtable
        // try b.fnAttributes(wip, .{ .function = &[_]Attribute{.uwtable} });
    }

    fn addFunction(
        b: *Builder,
        name: StrtabString,
        param_types: []const Type,
        ret_type: Type,
        call_conv: CallConv,
        options: FunctionOptions,
    ) Oom!Function.Index {
        const func = try b.module.addFunction(
            try b.fnType(ret_type, param_types),
            name,
            .default,
        );
        func.setCallConv(call_conv, &b.module);
        func.setLinkage(options.linkage, &b.module);
        func.ptr(&b.module).global.ptr(&b.module).preemption = options.preemption;
        return func;
    }

    fn addFfiFunction(
        b: *Builder,
        name: []const u8,
        param_types: []const Type,
        ret_type: Type,
    ) Oom!Function.Index {
        return try b.addFunction(
            try b.strtabStringSymbolPrefixed(name),
            param_types,
            ret_type,
            b.ffi_call_conv,
            .{ .preemption = .dso_local },
        );
    }

    fn wipFunction(b: *Builder, func: Function.Index) Oom!WipFunction {
        return try .init(&b.module, .{ .function = func, .strip = b.options.strip });
    }

    fn addDispatchTable(b: *Builder, name: []const u8, len: u16) Oom!Global.Index {
        const name_str = try b.strtabStringSymbolPrefixed(name);
        const ty = try b.module.arrayType(len, .ptr);
        const variable = try b.module.addVariable(name_str, ty, .default);
        return try b.module.addGlobal(name_str, .{
            .preemption = .dso_local,
            .type = ty,
            .kind = .{ .variable = variable },
            .unnamed_addr = .local_unnamed_addr,
        });
    }

    fn setDispatchTableInitializer(b: *Builder, comptime E: type) Oom!void {
        const table_global_idx: Global.Index = switch (E) {
            opcodes.ByteOpcode => b.dispatch_tables.byte,
            else => @compileError(@typeName(E)),
        };

        const table_global = table_global_idx.ptrConst(&b.module);
        const table_var = table_global.kind.variable;
        const len = table_global.type.aggregateLen(&b.module);
        const set: *const std.EnumSet(E) = switch (E) {
            opcodes.ByteOpcode => &b.byte_opcode_lookup,
            else => @compileError(@typeName(E)),
        };

        _ = b.scratch.reset(.retain_capacity);
        const values = try b.scratch.allocator().alloc(Constant, len);
        const undef = try b.module.undefConst(.ptr);
        var name_arena = ArenaAllocator.init(b.scratch.allocator());
        for (values, 0..len) |*v, i| {
            v.* = val: {
                invalid: {
                    const opcode = std.enums.fromInt(E, i) orelse break :invalid;
                    if (!set.contains(opcode)) break :invalid;

                    _ = name_arena.reset(.retain_capacity);
                    const handler_name = try b.module.strtabString(try std.mem.concat(
                        name_arena.allocator(),
                        u8,
                        &.{ b.options.symbol_prefix, @tagName(opcode) },
                    ));

                    break :val b.module.getGlobal(handler_name).?.toConst();
                }

                // TODO: use undef only on ReleaseSmall.
                break :val undef;
            };
        }

        try table_var.setInitializer(
            try b.module.arrayConst(table_global.type, values),
            &b.module,
        );
    }
};

fn enumFieldCount(comptime E: type) comptime_int {
    return @typeInfo(E).@"enum".fields.len;
}

fn buildLlvmModule(b: *Builder) Oom!void {
    b.module.data_layout = try b.module.string(b.target_info.data_layout);
    try b.module.functions.ensureUnusedCapacity(
        b.module.gpa,
        enumFieldCount(opcodes.ByteOpcode) + enumFieldCount(opcodes.FCPrefixOpcode),
    );
    try b.module.globals.ensureUnusedCapacity(b.module.gpa, 3);

    b.dispatch_tables.byte = try b.addDispatchTable("byte_dispatch_table", 256);

    {
        const trampoline = try b.addFfiFunction(
            "opcodeHandlerTrampoline",
            &[10]Type{
                .ptr, // locals
                .ptr, // sp
                .ptr, // module
                .ptr, // fuel
                .ptr, // memories
                .ptr, // interpreter
                .ptr, // ip
                .ptr, // stp
                .ptr, // eip
                .ptr, // handler
            },
            .i32,
        );
        var attributes = FunctionAttributes.Wip{};
        try b.commonFnAttributes(&attributes);
        try b.fnAttributes(&attributes, .{ .function = &[2]Attribute{ .hot, .norecurse } });
        try b.setFnAttributes(trampoline, &attributes);
        var wip = try b.wipFunction(trampoline);
        defer wip.deinit();

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const call_params: [10]Value = params: {
            var params: [10]Value = undefined;
            for (0..9) |i| {
                params[i] = wip.arg(@intCast(i));
            }

            params[9] = b.dispatch_tables.byte.ptrConst(&b.module).kind.variable.toValue(&b.module);
            break :params params;
        };
        const result = try wip.call(
            .tail,
            b.opcode_handler.call_conv,
            .none,
            b.opcode_handler.type,
            wip.arg(9),
            &call_params,
            "",
        );
        _ = try wip.ret(result);
        try wip.finish();

        // try wip.callIntrinsic(.normal, attrs: {
        //     var trap_attrs = FunctionAttributes.Wip{};
        //     defer trap_attrs.deinit(&b.module);
        //     try b.fnAttributes(&trap_attrs, .{
        //         .function = &[2]Attribute{ .cold, .noreturn, .nounwind },
        //     });
        //     break :attrs trap_attrs.finish();
        // }, .trap, &.{}, .{}, "");
    }

    try b.setDispatchTableInitializer(opcodes.ByteOpcode);
}

const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const Oom = std.mem.Allocator.Error;
const opcodes = @import("opcodes");

const llvm = std.zig.llvm;
const Attribute = llvm.Builder.Attribute;
const CallConv = llvm.Builder.CallConv;
const Constant = llvm.Builder.Constant;
const Global = llvm.Builder.Global;
const Function = llvm.Builder.Function;
const FunctionAttributes = llvm.Builder.FunctionAttributes;
const String = llvm.Builder.String;
const StrtabString = llvm.Builder.StrtabString;
const Type = llvm.Builder.Type;
const Value = llvm.Builder.Value;
const Variable = llvm.Builder.Variable;
const WipFunction = llvm.Builder.WipFunction;
