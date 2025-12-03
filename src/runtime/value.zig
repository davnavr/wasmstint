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

pub const FuncAddr = packed struct(usize) {
    pub const Tag = enum(u1) { wasm = 0, host = 1 };

    const high_bits_size = @bitSizeOf(*anyopaque) - @bitSizeOf(Tag);
    const HighBits = std.meta.Int(.unsigned, high_bits_size);

    tag: Tag,
    high_bits: packed union {
        wasm: Wasm,
        host: HighBits,
    },

    /// A *host function*, uniquely identified by its address.
    ///
    /// Hosts using *wasmstint* are expected to embed a `Host` structure in some allocation
    /// representing a host function in some, passing the pointer to the `Host` to *wasmstint*.
    pub const Host = extern struct {
        /// It is illegal to mutate this value if existing reference to the host function currently
        /// exist.
        signature: Module.FuncType,

        pub fn format(func: *const Host, writer: *Writer) Writer.Error!void {
            try (Expanded{ .host = func }).format(writer);
        }
    };

    pub const Wasm = packed struct(HighBits) {
        // Note that on x86-64, there are technically extra bits that can be used (48-bit pointers?)
        // https://en.wikipedia.org/wiki/X86-64#Canonical_form_addresses
        pub const IdxBits = u3;

        idx_bits: IdxBits,
        block_addr: std.meta.Int(.unsigned, high_bits_size - @bitSizeOf(IdxBits)),

        /// Allows for a compact representation of `FuncAddr`s referring to functions defined
        /// within a `ModuleInst`.
        pub const Block = extern struct {
            module: ModuleInst,
            /// Invariant that this is `>=` the # of function imports in the module.
            starting_idx: u32,

            pub const funcs_per_block = std.math.maxInt(IdxBits) + 1;
        };

        fn block(wasm: Wasm) *align(@sizeOf(Block)) Block {
            const shift_amt = comptime @bitSizeOf(IdxBits) + 1;
            return @ptrFromInt(@as(usize, wasm.block_addr) << shift_amt);
        }

        pub fn module(wasm: Wasm) ModuleInst {
            return wasm.block().module;
        }

        /// Never refers to a function import.
        pub fn funcIdx(wasm: Wasm) Module.FuncIdx {
            return @enumFromInt(wasm.block().starting_idx + wasm.idx_bits);
        }

        pub inline fn code(wasm: Wasm) *Module.Code {
            return wasm.funcIdx().code(wasm.module().header().module).?;
        }

        pub fn signature(wasm: Wasm) *const Module.FuncType {
            return wasm.module().header().module.funcTypes()[@intFromEnum(wasm.funcIdx())];
        }

        pub fn format(func: Wasm, writer: *Writer) Writer.Error!void {
            try (Expanded{ .wasm = func }).format(writer);
        }
    };

    pub const Expanded = union(Tag) {
        wasm: Wasm,
        host: *const Host,

        pub fn signature(inst: *const Expanded) *const Module.FuncType {
            return switch (inst.*) {
                .host => |host| &host.signature,
                .wasm => |*wasm| wasm.signature(),
            };
        }

        pub fn format(func: *const Expanded, writer: *Writer) Writer.Error!void {
            try writer.writeAll("(func ");
            switch (func.*) {
                .wasm => |*wasm| {
                    try writer.print("$f{}", .{@intFromEnum(wasm.funcIdx())});

                    const module = wasm.module().header().module;
                    // for (wasm.module.findExportNames(.{ .func = wasm.idx })) |name| {
                    for (module.exports()) |exp| {
                        const desc = exp.descIdx();
                        if (desc == .func and desc.func == wasm.funcIdx()) {
                            try writer.print(" (export {f})", .{exp.name(module)});
                        }
                    }

                    try writer.print(" (;module@{X};)", .{@intFromPtr(wasm.module().header())});
                },
                .host => |host| try writer.print("(;host@{X};)", .{@intFromPtr(host)}),
            }

            const sig = func.signature();
            if (sig.param_count > 0 or sig.result_count > 0) {
                try writer.print(" {f}", .{sig});
            }

            try writer.writeByte(')');
        }
    };

    pub fn init(inst: Expanded) FuncAddr {
        return switch (inst) {
            .wasm => |wasm| .{ .tag = .wasm, .high_bits = .{ .wasm = wasm } },
            .host => |host| .{
                .tag = .host,
                .high_bits = .{ .host = @intCast(@shrExact(@intFromPtr(host), 1)) },
            },
        };
    }

    pub fn expanded(inst: FuncAddr) Expanded {
        return switch (inst.tag) {
            .wasm => .{ .wasm = inst.high_bits.wasm },
            .host => .{ .host = @ptrFromInt(@shlExact(@as(usize, inst.high_bits.host), 1)) },
        };
    }

    comptime {
        std.debug.assert(@sizeOf(FuncAddr) == @sizeOf(*anyopaque));
        std.debug.assert(std.meta.alignment(@FieldType(ModuleInst, "inner")) >= @sizeOf(Wasm.Block));
        std.debug.assert(@divExact(@sizeOf(Wasm.Block), 2) == Wasm.Block.funcs_per_block);
        std.debug.assert(@alignOf(Host) >= 2);
    }

    pub fn signature(inst: *const FuncAddr) *const Module.FuncType {
        return inst.expanded().signature();
    }

    pub const Nullable = packed struct(usize) {
        bits: usize,

        pub const @"null" = Nullable{ .bits = 0 };

        pub fn funcInst(inst: Nullable) ?FuncAddr {
            return if (inst.bits == 0)
                null
            else
                @as(FuncAddr, @bitCast(inst.bits));
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

    pub fn hash(func: FuncAddr, hasher: anytype) void {
        std.hash.autoHash(hasher, @as(usize, @bitCast(func)));
    }

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
