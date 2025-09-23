pub const TableAddr = extern struct {
    elem_type: Module.ValType,
    table: *@import("table.zig").TableInst,

    pub fn tableType(addr: *const TableAddr) Module.TableType {
        return .{
            .elem_type = addr.elem_type,
            .limits = .{ .min = addr.table.len, .max = addr.table.limit },
        };
    }

    pub fn format(addr: *const TableAddr, writer: *Writer) Writer.Error!void {
        try writer.print("(table {f})", .{addr.tableType()});
    }
};

pub const GlobalAddr = extern struct {
    global_type: Module.GlobalType, // *const GlobalType if it becomes too big
    value: *anyopaque, // TODO: Have it be a pointer to struct containing both value and its size? Need to allow global.get/set to know the operand size

    pub fn Pointee(comptime val_type: Module.ValType) type {
        return switch (val_type) {
            .i32 => i32,
            .f32 => f32,
            .i64 => i64,
            .f64 => f64,
            .funcref => FuncAddr.Nullable,
            .externref => ExternAddr,
            .v128 => unreachable,
        };
    }

    pub fn format(global: GlobalAddr, writer: *Writer) Writer.Error!void {
        try writer.print("(global {f} ", .{global.global_type});
        switch (global.global_type.val_type) {
            inline .i32, .f32, .i64, .f64 => |num| {
                try writer.print(
                    "(" ++ @tagName(num) ++ ".const {})",
                    .{@as(*const Pointee(num), @ptrCast(@alignCast(global.value)))},
                );
            },
            inline .funcref, .externref => |ref| {
                try writer.print(
                    "{f}",
                    .{@as(*const Pointee(ref), @ptrCast(@alignCast(global.value)))},
                );
            },
            .v128 => unreachable,
        }
    }
};

pub const FuncAddr = extern struct {
    /// If the lowest bit is `0`, then this is a `ModuleInst`.
    module_or_host: *anyopaque,
    func: packed union {
        wasm: Module.FuncIdx,
        host_data: ?*anyopaque,
    },

    /// A *host function*, uniquely identified by its address.
    ///
    /// Embedders of *wasmstint* are intended to store the data of a host function in some structure containing a
    /// `HostFunc`, passing the pointer to the `HostFunc` to *wasmstint*.
    pub const Host = extern struct {
        signature: Module.FuncType,
    };

    pub const Expanded = union(enum) {
        host: Expanded.Host,
        wasm: Wasm,

        pub const Host = struct {
            func: *FuncAddr.Host,
            data: ?*anyopaque,
        };

        pub const Wasm = struct {
            module: ModuleInst,
            idx: Module.FuncIdx,

            pub inline fn code(wasm: *const Wasm) *Module.Code {
                return wasm.idx.code(wasm.module.header().module).?;
            }
        };

        pub fn signature(inst: *const Expanded) *const Module.FuncType {
            return switch (inst.*) {
                .host => |*host| &host.func.signature,
                .wasm => |*wasm| wasm.module.header().module.funcTypes()[@intFromEnum(wasm.idx)],
            };
        }

        pub fn format(func: *const Expanded, writer: *Writer) Writer.Error!void {
            try writer.writeAll("(func ");
            switch (func.*) {
                .wasm => |*wasm| {
                    try writer.print("$f{}", .{@intFromEnum(wasm.idx)});

                    const module = wasm.module.header().module;
                    // for (wasm.module.findExportNames(.{ .func = wasm.idx })) |name| {
                    for (module.exports()) |exp| {
                        const desc = exp.descIdx();
                        if (desc == .func and desc.func == wasm.idx) {
                            try writer.print(" (export {f})", .{exp.name(module)});
                        }
                    }

                    try writer.print(" (;module@{X};)", .{@intFromPtr(wasm.module.header())});
                },
                .host => |*host| try writer.print(
                    "(;host@{X};)",
                    .{@intFromPtr(host.func)},
                ),
            }

            const sig = func.signature();
            if (sig.param_count > 0 or sig.result_count > 0) {
                try writer.print(" {f}", .{sig});
            }

            try writer.writeByte(')');
        }
    };

    pub fn init(inst: Expanded) FuncAddr {
        return FuncAddr{
            .module_or_host = switch (inst) {
                .wasm => |*wasm| @ptrCast(@constCast(wasm.module.inner)),
                .host => |*host| @ptrFromInt(@intFromPtr(host.func) | 1),
            },
            .func = switch (inst) {
                .wasm => |*wasm| .{ .wasm = wasm.idx },
                .host => |*host| .{ .host_data = host.data },
            },
        };
    }

    pub fn expanded(inst: FuncAddr) Expanded {
        const module_or_host = @intFromPtr(inst.module_or_host);
        return if (module_or_host & 1 == 0) Expanded{
            .wasm = .{
                .module = ModuleInst{ .inner = @ptrFromInt(module_or_host) },
                .idx = inst.func.wasm,
            },
        } else .{
            .host = .{
                .func = @ptrFromInt(module_or_host & ~@as(usize, 1)),
                .data = inst.func.host_data,
            },
        };
    }

    comptime {
        std.debug.assert(@sizeOf(FuncAddr) == @sizeOf([2]*anyopaque));
        std.debug.assert(std.meta.alignment(@FieldType(ModuleInst, "inner")) >= 2);
        std.debug.assert(@alignOf(Host) >= 2);
    }

    pub fn signature(inst: *const FuncAddr) *const Module.FuncType {
        return inst.expanded().signature();
    }

    pub const Nullable = extern struct {
        module_or_host: ?*anyopaque,
        func: @FieldType(FuncAddr, "func"),

        pub const @"null" = std.mem.zeroes(Nullable);

        pub fn funcInst(inst: Nullable) ?FuncAddr {
            return if (inst.module_or_host) |module_or_host|
                .{ .module_or_host = module_or_host, .func = inst.func }
            else
                null;
        }

        comptime {
            std.debug.assert(@bitSizeOf(FuncAddr) == @bitSizeOf(Nullable));
            std.debug.assert(Nullable.null.funcInst() == null);
        }

        pub fn format(func: Nullable, writer: *Writer) Writer.Error!void {
            if (func.funcInst()) |addr| {
                try addr.format(writer);
            } else {
                try writer.writeAll("(ref.null func)");
            }
        }
    };

    pub fn format(func: FuncAddr, writer: *Writer) Writer.Error!void {
        try func.expanded().format(writer);
    }
};

pub const ExternVal = union(enum) {
    func: FuncAddr,
    mem: *@import("memory.zig").MemInst,
    table: TableAddr,
    global: GlobalAddr,

    // @sizeOf(ExternVal) ~= @sizeOf([3]usize), but this is fine as it is not expected to be stored in slices

    pub fn format(val: *const ExternVal, writer: *Writer) Writer.Error!void {
        switch (val.*) {
            .func => |*func| try func.format(writer),
            .mem => |mem| try mem.format(writer),
            .table => |*table| try table.format(writer),
            .global => |*global| try global.format(writer),
        }
    }
};

pub const ExternAddr = packed union {
    ptr: ?*anyopaque,
    nat: Nat,

    pub const @"null" = ExternAddr{ .ptr = null };

    pub const Nat = enum(usize) {
        null = 0,
        _,

        pub const Size = std.meta.Int(.unsigned, @bitSizeOf(usize) - 1);

        pub fn fromInt(n: Size) Nat {
            const int = @as(usize, n) + 1;
            std.debug.assert(int > 0);
            return @enumFromInt(int);
        }

        pub fn toInt(nat: Nat) ?Size {
            return if (nat == .null) null else @intCast(@as(usize, @intFromEnum(nat)) - 1);
        }

        pub fn eql(a: Nat, b: Nat) bool {
            return @intFromEnum(a) == @intFromEnum(b);
        }

        pub fn format(ref: Nat, writer: *Writer) Writer.Error!void {
            return (ExternAddr{ .nat = ref }).format(writer);
        }
    };

    pub fn eql(a: ExternAddr, b: ExternAddr) bool {
        return a.nat.eql(b.nat);
    }

    comptime {
        std.debug.assert(@sizeOf(ExternAddr) == @sizeOf(?*anyopaque));
        std.debug.assert(
            std.mem.allEqual(
                u8,
                std.mem.asBytes(&ExternAddr.null),
                0,
            ),
        );
    }

    pub fn format(ref: ExternAddr, writer: *Writer) Writer.Error!void {
        if (ref.ptr == null) {
            try writer.writeAll("(ref.null extern)");
        } else {
            try writer.print("(ref.extern 0x{X})", .{@intFromPtr(ref.ptr)});
        }
    }
};

const std = @import("std");
const Writer = std.Io.Writer;
const Module = @import("../Module.zig");
const ModuleInst = @import("module_inst.zig").ModuleInst;
