pub const GlobalAddr = extern struct {
    global_type: Module.GlobalType, // *const GlobalType if it becomes too big
    value: *anyopaque, // TODO: Have it be a pointer to struct containing both value and its size? Need to allow global.get/set to know the operand size

    pub fn Pointee(comptime val_type: Module.ValType) type {
        return switch (val_type) {
            .i32 => i32,
            .f32 => f32,
            .i64 => i64,
            .f64 => f64,
            .funcref => FuncRef.Nullable,
            .externref => ExternAddr,
            .v128 => V128,
        };
    }

    pub fn format(global: GlobalAddr, writer: *Writer) Writer.Error!void {
        try writer.print("(global {f} ", .{global.global_type});
        switch (global.global_type.val_type) {
            inline .i32, .f32, .i64, .f64 => |num| {
                try writer.print(
                    "(" ++ @tagName(num) ++ ".const {})",
                    .{@as(*const Pointee(num), @ptrCast(@alignCast(global.value))).*},
                );
            },
            inline .funcref, .externref => |ref| {
                try writer.print(
                    "{f}",
                    .{@as(*const Pointee(ref), @ptrCast(@alignCast(global.value)))},
                );
            },
            .v128 => {
                try V128.format(@as(*const V128, @ptrCast(@alignCast(global.value))).*, writer);
            },
        }
    }
};

/// A *host function*, uniquely identified by its address.
///
/// Hosts using *wasmstint* are expected to embed a `Host` structure in some allocation
/// representing a host function in some, passing the pointer to the `Host` to *wasmstint*.
pub const HostFunc = extern struct {
    /// It is illegal to mutate this value if existing reference to the host function currently
    /// exist.
    signature: Module.FuncType,

    pub fn format(func: *const HostFunc, writer: *Writer) Writer.Error!void {
        try (FuncInst.Expanded{ .host = func }).format(writer);
    }
};

/// Represents either a WASM function or host function.
pub const FuncInst = extern struct {
    ptr: extern union {
        wasm: ModuleInst,
        host: *const HostFunc,
    },
    payload: packed struct(u32) {
        tag: Tag,
        wasm: Module.FuncIdx,
    },

    pub const Tag = enum(u1) { wasm = 0, host = 1 };

    comptime {
        std.debug.assert(@sizeOf(FuncInst) == @sizeOf([2]usize));
    }

    pub fn init(func: Expanded) FuncInst {
        return switch (func) {
            .wasm => |wasm| .{
                .ptr = .{ .wasm = wasm.module },
                .payload = .{ .tag = .wasm, .wasm = wasm.idx },
            },
            .host => |host| .{
                .ptr = .{ .host = host },
                .payload = .{ .tag = .host, .wasm = undefined },
            },
        };
    }

    pub const Expanded = union(Tag) {
        wasm: Wasm,
        host: *const HostFunc,

        pub fn signature(func: Expanded) *const Module.FuncType {
            return switch (func) {
                .wasm => |wasm| wasm.signature(),
                .host => |host| &host.signature,
            };
        }

        pub fn format(func: *const Expanded, writer: *Writer) Writer.Error!void {
            try writer.writeAll("(func ");
            switch (func.*) {
                .wasm => |wasm| {
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
                .host => |host| try writer.print("(;host@{X};)", .{@intFromPtr(host)}),
            }

            const sig = func.signature();
            if (sig.param_count > 0 or sig.result_count > 0) {
                try writer.print(" {f}", .{sig});
            }

            try writer.writeByte(')');
        }
    };

    pub fn expanded(func: FuncInst) Expanded {
        return switch (func.payload.tag) {
            .wasm => .{ .wasm = .{ .module = func.ptr.wasm, .idx = func.payload.wasm } },
            .host => .{ .host = func.ptr.host },
        };
    }

    /// Refers to a function instance by index into a given `ModuleInst`.
    pub const Wasm = struct {
        module: ModuleInst,
        /// Must never refer to a function import.
        idx: Module.FuncIdx,

        /// Asserts that `idx` does **not** refer to a function import.
        pub fn init(module: ModuleInst, idx: Module.FuncIdx) Wasm {
            std.debug.assert( // function import not allowed
                module.header().module.inner.raw.func_import_count <= @intFromEnum(idx),
            );

            return Wasm{ .module = module, .idx = idx };
        }

        pub fn code(wasm: Wasm) *Module.Code {
            return wasm.idx.code(wasm.module.header().module).?;
        }

        pub fn signature(wasm: Wasm) *const Module.FuncType {
            return wasm.module.header().module.funcTypes()[@intFromEnum(wasm.idx)];
        }

        pub fn format(func: Wasm, writer: *Writer) Writer.Error!void {
            try (Expanded{ .wasm = func }).format(writer);
        }
    };

    // /// This is currently only used to support stack frame checksums in debug mode.
    // pub fn hash(func: FuncRef, hasher: anytype) void {
    // }

    pub fn signature(func: FuncInst) *const Module.FuncType {
        return func.expanded().signature();
    }

    pub fn format(func: FuncInst, writer: *Writer) Writer.Error!void {
        try func.expanded().format(writer);
    }
};

/// More compact version of a `FuncInst`, used to implement function references.
///
/// A `FuncRef` referring to a WASM function cannot refer to any function within the module, it
/// can only be created from the set of referencable functions. In contrast, a `FuncInst` can
/// refer to any function.
pub const FuncRef = packed struct(usize) {
    pub const Tag = enum(u1) { wasm = 0, host = 1 };

    const high_bits_size = @bitSizeOf(*anyopaque) - @bitSizeOf(Tag);
    const HighBits = std.meta.Int(.unsigned, high_bits_size);

    tag: Tag,
    high_bits: packed union {
        wasm: Wasm,
        host: HighBits,
    },

    /// A reference to WASM function.
    pub const Wasm = packed struct(HighBits) {
        // Note that on x86-64, there are technically extra bits that can be used (48-bit pointers?)
        // https://en.wikipedia.org/wiki/X86-64#Canonical_form_addresses
        pub const IdxBits = u3;

        idx_bits: IdxBits,
        block_addr: std.meta.Int(.unsigned, high_bits_size - @bitSizeOf(IdxBits)),

        /// Allows for a compact representation of `FuncRef`s referring to functions defined
        /// within a `ModuleInst`.
        pub const Block = extern struct {
            module: ModuleInst,
            /// Invariant that this is `>=` the # of function imports in the module.
            starting_idx: u32,

            pub const funcs_per_block = std.math.maxInt(IdxBits) + 1;
        };

        pub fn block(wasm: Wasm) *align(@sizeOf(Block)) Block {
            const shift_amt = comptime @bitSizeOf(IdxBits) + 1;
            return @ptrFromInt(@as(usize, wasm.block_addr) << shift_amt);
        }

        pub fn module(wasm: Wasm) ModuleInst {
            return wasm.block().module;
        }

        fn lookupIdx(wasm: Wasm) u32 {
            if (builtin.mode == .Debug) {
                std.debug.assert( // corrupted module pointer
                    @intFromPtr(wasm.module().inner) % std.atomic.cache_line == 0,
                );
            }

            return wasm.block().starting_idx + wasm.idx_bits;
        }

        /// Never refers to a function import.
        pub fn funcIdx(wasm: Wasm) Module.FuncIdx {
            const wasm_module = wasm.module().header().module.inner;
            const lookup_idx = wasm.lookupIdx();
            const import_count = wasm_module.raw.func_import_count;
            const idx: Module.FuncIdx = wasm_module.func_refs.keys()[lookup_idx];

            if (builtin.mode == .Debug) {
                std.debug.assert(import_count <= lookup_idx);
                std.debug.assert(import_count <= @intFromEnum(idx));
            }
            return idx;
        }

        pub inline fn code(wasm: Wasm) *Module.Code {
            return wasm.funcIdx().code(wasm.module().header().module).?;
        }

        pub fn signature(wasm: Wasm) *const Module.FuncType {
            const idx = @intFromEnum(wasm.funcIdx());
            return wasm.module().header().module.funcTypes()[idx];
        }

        pub fn format(func: Wasm, writer: *Writer) Writer.Error!void {
            try (Expanded{ .wasm = func }).format(writer);
        }
    };

    pub const Expanded = union(Tag) {
        wasm: Wasm,
        host: *const HostFunc,

        pub fn signature(func: Expanded) *const Module.FuncType {
            return switch (func) {
                .host => |host| &host.signature,
                .wasm => |wasm| wasm.signature(),
            };
        }

        pub fn funcInst(func: Expanded) FuncInst.Expanded {
            return switch (func) {
                .wasm => |wasm| .{ .wasm = .init(wasm.module(), wasm.funcIdx()) },
                .host => |host| .{ .host = host },
            };
        }

        pub fn format(func: *const Expanded, writer: *Writer) Writer.Error!void {
            try func.funcInst().format(writer);
        }
    };

    pub fn init(func: Expanded) FuncRef {
        return switch (func) {
            .wasm => |wasm| .{ .tag = .wasm, .high_bits = .{ .wasm = wasm } },
            .host => |host| .{
                .tag = .host,
                .high_bits = .{ .host = @intCast(@shrExact(@intFromPtr(host), 1)) },
            },
        };
    }

    pub fn expanded(func: FuncRef) Expanded {
        return switch (func.tag) {
            .wasm => .{ .wasm = func.high_bits.wasm },
            .host => .{ .host = @ptrFromInt(@shlExact(@as(usize, func.high_bits.host), 1)) },
        };
    }

    pub fn funcInst(func: FuncRef) FuncInst {
        return FuncInst.init(func.expanded().funcInst());
    }

    comptime {
        std.debug.assert(@sizeOf(FuncRef) == @sizeOf(*anyopaque));
        std.debug.assert(std.meta.alignment(@FieldType(ModuleInst, "inner")) >= @sizeOf(Wasm.Block));
        std.debug.assert(@divExact(@sizeOf(Wasm.Block), 2) == Wasm.Block.funcs_per_block);
        std.debug.assert(@alignOf(HostFunc) >= 2);
    }

    pub fn signature(inst: *const FuncRef) *const Module.FuncType {
        return inst.expanded().signature();
    }

    pub const Nullable = packed struct(usize) {
        bits: usize,

        pub const @"null" = Nullable{ .bits = 0 };

        pub fn get(inst: Nullable) ?FuncRef {
            return if (inst.bits == 0)
                null
            else
                @as(FuncRef, @bitCast(inst.bits));
        }

        comptime {
            std.debug.assert(@bitSizeOf(FuncRef) == @bitSizeOf(Nullable));
            std.debug.assert(Nullable.null.get() == null);
        }

        pub fn format(func: Nullable, writer: *Writer) Writer.Error!void {
            if (func.get()) |addr| {
                try addr.format(writer);
            } else {
                try writer.writeAll("(ref.null func)");
            }
        }
    };

    pub fn format(func: FuncRef, writer: *Writer) Writer.Error!void {
        try func.expanded().format(writer);
    }
};

pub const ExternVal = union(enum) {
    func: FuncRef,
    mem: *@import("memory.zig").MemInst,
    table: *@import("table.zig").TableInst,
    global: GlobalAddr,

    // @sizeOf(ExternVal) ~= @sizeOf([3]usize), but this is fine as it is not expected to be stored in slices
    // If GlobalAddr could be made to be @sizeOf(usize), then @sizeOf(ExternVal) would be @sizeOf([2]usize)

    pub fn format(val: *const ExternVal, writer: *Writer) Writer.Error!void {
        switch (val.*) {
            .func => |*func| try func.format(writer),
            .mem => |mem| try mem.format(writer),
            .table => |table| try table.format(writer),
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
const builtin = @import("builtin");
const Writer = std.Io.Writer;
const Module = @import("../Module.zig");
const ModuleInst = @import("module_inst.zig").ModuleInst;
const V128 = @import("../v128.zig").V128;
