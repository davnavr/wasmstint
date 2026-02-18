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
    cache_line_size: u16,
    size_type: Type = .none,
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

    out_of_fuel_handler: Function.Index = .none,
    decode_uleb_idx: Function.Index = .none,

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
            .cache_line_size = std.atomic.cacheLineForCpu(config.target.cpu),
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
        const ptr_size: u16 = @divExact(b.target.ptrBitWidth(), 8);
        b.size_type = try b.module.intType(ptr_size);
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
                for (std.enums.values(OpcodeHandlerParam)) |param| {
                    const idx = @intFromEnum(param);
                    for (&[3]Attribute{ .nonnull, .nofree, .noundef }) |attr| {
                        try attrs.addParamAttr(idx, attr, &b.module);
                    }

                    const alignment: ?u16 = switch (param) {
                        .locals, .vsp => 16,
                        .module => b.cache_line_size,
                        // TODO: read datalayout to determine alignment of u64 Fuel/STP
                        .memories, .ctx => ptr_size,
                        else => null,
                    };

                    if (alignment) |a| {
                        try attrs.addParamAttr(idx, .{ .@"align" = .fromByteUnits(a) }, &b.module);
                    }

                    switch (param) {
                        .locals, .vsp, .fuel, .stp, .disp => {
                            try attrs.addParamAttr(idx, .@"noalias", &b.module);
                        },
                        else => {},
                    }

                    switch (param) {
                        .fuel => try attrs.addParamAttr(idx, .{ .dereferenceable = 8 }, &b.module),
                        // .module // don't know size of ModuleInst in advance
                        else => {},
                    }

                    switch (param) {
                        .memories, .ctx, .vip, .stp, .eip, .disp => {
                            try attrs.addParamAttr(idx, .readonly, &b.module);
                        },
                        else => {},
                    }
                }
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
        attributes: []const Attribute,
    ) Oom!void {
        for (attributes) |attr| {
            try wip.addFnAttr(attr, &b.module);
        }
    }

    fn setFnAttributes(b: *Builder, func: Function.Index, wip: *FunctionAttributes.Wip) Oom!void {
        func.setAttributes(try wip.finish(&b.module), &b.module);
    }

    fn commonFnAttributes(b: *Builder, wip: *FunctionAttributes.Wip) Oom!void {
        try wip.addFnAttr(.nounwind, &b.module);

        // This is what the Zig compiler does
        if (b.options.optimize == .ReleaseSmall) {
            try b.fnAttributes(wip, &.{ .minsize, .optsize });
        }

        if (b.target_cpu != .none) {
            try b.fnAttributes(wip, &.{
                .{
                    .string = .{
                        .kind = b.string_constants.@"target-cpu",
                        .value = b.target_cpu,
                    },
                },
            });
        }

        if (b.target_features != .empty) {
            try b.fnAttributes(wip, &.{
                .{
                    .string = .{
                        .kind = b.string_constants.@"target-features",
                        .value = b.target_features,
                    },
                },
            });
        }

        // TODO: bool option for uwtable
        if (b.target.cpu.arch == .x86_64 and b.target.os.tag == .linux) {
            try b.fnAttributes(wip, &.{.{ .uwtable = .async }});
        }
    }

    fn addFunction(
        b: *Builder,
        name: StrtabString,
        ty: Type,
        call_conv: CallConv,
        options: FunctionOptions,
    ) Oom!Function.Index {
        const func = try b.module.addFunction(ty, name, .default);
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
            try b.fnType(ret_type, param_types),
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
        variable.setAlignment(.fromByteUnits(b.cache_line_size), &b.module);
        return try b.module.addGlobal(name_str, .{
            .preemption = .dso_local,
            .type = ty,
            .kind = .{ .variable = variable },
            .unnamed_addr = .local_unnamed_addr,
        });
    }

    fn setDispatchTableInitializer(b: *Builder, comptime E: type) Oom!void {
        const invalid_handler: Function.Index = if (b.options.optimize == .ReleaseSmall)
            .none
        else handler: switch (E) {
            opcodes.ByteOpcode => {
                const handler = try b.addFfiFunction(
                    "panicInvalidByteOpcode",
                    &@as([2]Type, @splat(.ptr)),
                    .void,
                );
                var attrs = FunctionAttributes.Wip{};
                try b.commonFnAttributes(&attrs);
                try attrs.addFnAttr(.noreturn, &b.module);
                try b.setFnAttributes(handler, &attrs);

                break :handler handler;
            },
            else => @compileError(@typeName(E)),
        };

        const invalid: Constant = if (invalid_handler == .none)
            try b.module.undefConst(.ptr)
        else
            invalid_handler.toConst(&b.module);

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

                break :val invalid;
            };
        }

        try table_var.setInitializer(
            try b.module.arrayConst(table_global.type, values),
            &b.module,
        );
    }
};

const OpcodeHandlerParam = enum(u4) {
    locals,
    vsp,
    module,
    fuel,
    memories,
    ctx,
    vip,
    stp,
    eip,
    disp,

    fn arg(param: OpcodeHandlerParam, wip: *WipFunction) Value {
        return wip.arg(@intFromEnum(param));
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
        {
            var attributes = FunctionAttributes.Wip{};
            try b.commonFnAttributes(&attributes);
            try attributes.addFnAttr(.norecurse, &b.module);
            try b.setFnAttributes(trampoline, &attributes);
        }
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
    {
        b.out_of_fuel_handler = try b.addFunction(
            try b.strtabStringSymbolPrefixed("outOfFuelHandler"),
            b.opcode_handler.type,
            b.opcode_handler.call_conv,
            .{ .linkage = .external, .preemption = .dso_local },
        );
        {
            var attrs = try b.opcode_handler.fn_attrs.toWip(&b.module);
            try b.fnAttributes(&attrs, &.{ .mustprogress, .willreturn, .cold });
            try b.setFnAttributes(b.out_of_fuel_handler, &attrs);
        }
        var wip = try b.wipFunction(b.out_of_fuel_handler);
        defer wip.deinit();

        const helper = try b.addFunction(
            try b.strtabStringSymbolPrefixed("interruptOutOfFuel"),
            try b.fnType(.i32, &@as([5]Type, @splat(.ptr))),
            b.ffi_call_conv,
            .{ .linkage = .external, .preemption = .dso_local },
        );
        {
            var attrs = FunctionAttributes.Wip{};
            try b.commonFnAttributes(&attrs);
            try b.setFnAttributes(helper, &attrs);
        }

        wip.cursor = .{ .block = try wip.block(0, "Entry") };
        const call_params: [5]Value = params: {
            var params: [5]Value = undefined;
            for (&params, [5]OpcodeHandlerParam{ .vip, .eip, .vsp, .stp, .ctx }) |*p, arg| {
                p.* = wip.arg(@intFromEnum(arg));
            }

            break :params params;
        };
        const result = try wip.call(
            .tail,
            b.ffi_call_conv,
            .none,
            helper.typeOf(&b.module),
            helper.toValue(&b.module),
            &call_params,
            "",
        );
        _ = try wip.ret(result);
        try wip.finish();
    }
    {
        const ret_ty = try b.module.structType(.normal, &.{ .i32, .ptr });
        b.decode_uleb_idx = try b.addFunction(
            try b.strtabStringSymbolPrefixed("decodeUlebIndex"),
            try b.fnType(ret_ty, &.{.ptr}),
            if (b.target.cpu.arch == .x86_64) .preserve_mostcc else .fastcc,
            .{ .linkage = .internal, .preemption = .dso_local },
        );
        const param_attrs = [6]Attribute{
            .readonly,
            .nonnull,
            .noundef,
            .{ .dereferenceable = 1 },
            .@"noalias",
            .nofree,
        };
        {
            var attrs = FunctionAttributes.Wip{};
            try b.commonFnAttributes(&attrs);
            try b.fnAttributes(
                &attrs,
                // TODO: see if LLVM partial inlining works here
                // If this is split across two functions, add .alwaysinline here
                &.{ .mustprogress, .willreturn, .norecurse },
            );
            for (&param_attrs) |a| {
                try attrs.addParamAttr(0, a, &b.module);
            }
            try b.setFnAttributes(b.decode_uleb_idx, &attrs);
        }

        var wip = try b.wipFunction(b.decode_uleb_idx);
        defer wip.deinit();

        const cont_mask = try b.module.intValue(.i8, 0x80);

        const entry_blk = try wip.block(0, "Entry");
        wip.cursor = .{ .block = entry_blk };
        const vip_0 = wip.arg(0);
        const byte_0 = try wip.load(.normal, .i8, vip_0, .default, "");
        const vip_1 = try wip.gep(
            .inbounds,
            .i8,
            vip_0,
            &.{try b.module.intValue(b.size_type, 1)},
            "",
        );
        const ret_single_byte = try wip.block(1, "ReturnSingleByte");
        const loop_body = try wip.block(2, "LoopBody");
        const acc_0 = try wip.cast(.zext, byte_0, .i32, "");
        _ = try wip.brCond(
            try wip.icmp(.ult, byte_0, cont_mask, ""),
            ret_single_byte,
            loop_body,
            .then_likely,
        );

        {
            wip.cursor = .{ .block = ret_single_byte };
            _ = try wip.ret(try wip.buildAggregate(ret_ty, &.{ acc_0, vip_1 }, ""));
        }

        const shift_7 = try b.module.intValue(.i32, 7);

        // Hopefully LLVM loop unrolling can work here
        wip.cursor = .{ .block = loop_body };
        const acc_phi = try wip.phi(.i32, "");
        const shift_phi = try wip.phi(.i32, "");
        const vip_phi = try wip.phi(.ptr, "");
        _ = try wip.callIntrinsicAssumeCold();
        _ = try wip.callIntrinsic(
            .normal,
            .none,
            .assume,
            &.{},
            &.{try wip.icmp(.ule, shift_phi.toValue(), try b.module.intValue(.i32, 28), "")},
            "",
        );

        // TODO: llvm.assume shift_phi to be <= 28 here
        const next_byte = try wip.load(.normal, .i8, vip_0, .default, "");
        const next_acc = try wip.bin(
            .@"or",
            try wip.bin(
                .@"shl nuw",
                try wip.cast(.zext, try wip.bin(.@"and", byte_0, cont_mask, ""), .i32, ""),
                shift_phi.toValue(),
                "",
            ),
            acc_phi.toValue(),
            "",
        );
        // `add nuw nsw` not supported by Zig API?
        const next_shift = try wip.bin(.@"add nsw", shift_phi.toValue(), shift_7, "");
        const next_vip = try wip.gep(
            .inbounds,
            .i8,
            vip_phi.toValue(),
            &.{try b.module.intValue(b.size_type, 1)},
            "",
        );
        const loop_ret = try wip.block(1, "ReturnMultiByte");
        _ = try wip.brCond(
            try wip.icmp(.ult, next_byte, cont_mask, ""),
            loop_ret,
            loop_body,
            .then_likely,
        );

        acc_phi.finish(&.{ acc_0, next_acc }, &.{ entry_blk, loop_body }, &wip);
        shift_phi.finish(&.{ shift_7, next_shift }, &.{ entry_blk, loop_body }, &wip);
        vip_phi.finish(&.{ vip_1, next_vip }, &.{ entry_blk, loop_body }, &wip);

        {
            wip.cursor = .{ .block = loop_ret };
            _ = try wip.ret(try wip.buildAggregate(ret_ty, &.{ next_acc, next_vip }, ""));
        }
        try wip.finish();
    }

    try b.setDispatchTableInitializer(opcodes.ByteOpcode);
}

const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const Oom = std.mem.Allocator.Error;
const opcodes = @import("opcodes");

const llvm = std.zig.llvm;
const Attribute = llvm.Builder.Attribute;
const Block = llvm.Builder.Block;
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
