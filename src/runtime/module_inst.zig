/// "The runtime representation of a *module*."
///
/// To obtain a `ModuleInst`, a `Module` must first be passed to `ModuleAlloc.allocate`, which is
/// then passed to `Interpreter.instantiateModule`.
pub const ModuleInst = packed struct(usize) {
    // Packed struct to workaround a codegen bug in Zig 0.15.1
    // ^ ModuleInst parameter's lower 16-bits get cloberred in `i32/64.const` handler

    /// Internal API.
    ///
    /// Makes calculating the layout of a `ModuleInst` a single cost when a `Module` is parsed,
    /// rather than recalculating it every time a module is instantiated.
    pub const Shape = struct {
        size: reservation_allocator.ReservationAllocator,
        // /// Stores the offsets of the values of defined globals.
        // ///
        // /// These offsets are relative to the address of the value of the first defined global.
        // global_value_offsets: [*]const u16,

        /// Returns an error if an overflow occurred while calculating the module layout.
        pub fn calculate(
            /// Pointer to where the calculated shape is written to.
            shape: *Shape,
            /// As this function is used in `Module.parse()`, it must make sure not to access
            /// uninitialized data.
            module: Module,
            // /// Allocated in the `module`'s arena.
            // global_value_offsets: []u16,
        ) std.mem.Allocator.Error!void {
            const info = &module.inner.raw;

            var size = reservation_allocator.ReservationAllocator{ .bytes = @sizeOf(Header) };
            try size.reserve(FuncAddr, info.func_import_count);
            try size.reserve(*TableInst, info.table_count);
            try size.reserve(TableInst, info.table_count - info.table_import_count);
            try size.reserve(*MemInst, info.mem_count);
            try size.reserve(MemInst, info.mem_count - info.mem_import_count);
            try size.reserve(*anyopaque, info.global_count);

            // More efficient packing of global values is possible
            // TODO: figure out why allocation failure occurs for global values
            // const defined_global_types = module.globalTypes()[0..module.globalInitializers().len];
            // if (defined_global_types.len > 0) {
            //     try size.alignUpTo(.fromByteUnits(@alignOf(u64)));
            // }

            // for (defined_global_types) |*global_type| {
            //     switch (global_type.val_type) {
            //         .v128 => unreachable,
            //         inline else => |ty| try size.reserve(GlobalAddr.Pointee(ty), 1),
            //     }
            // }
            try size.reserve(FuncAddr, module.globalInitializers().len);

            try size.reserve(u32, std.math.divCeil(u32, info.datas_count, 32) catch unreachable);
            try size.reserve(u32, std.math.divCeil(u32, info.elems_count, 32) catch unreachable);

            shape.* = .{ .size = size };
        }
    };

    /// Internal API.
    pub const Header = struct { // extern
        buffer_len: usize,
        module: Module,
        // /// Used to detect multi-threaded usage of a module instance.
        // ///
        // /// Currently, the WASM specification focuses only on single-threaded usage, with
        // /// *shared* memories currently being the sole exception.
        // acquired_flag: std.atomic.Value(bool) = .{ .raw = false },
        func_imports: [*]const FuncAddr,
        mems: [*]const *MemInst, // TODO: Could use comptime config to have specialized [1]MemInst (same for TableInst)
        tables: [*]const *TableInst,
        globals: [*]const *anyopaque,
        /// Indicates which data segments have not been dropped.
        ///
        /// After instantiation, only passive data segments have not been dropped.
        datas_drop_mask: [*]u32,
        /// Indicates which element segments have not been dropped.
        ///
        /// Before instantiation, both active and passive element segments have not yet been dropped.
        elems_drop_mask: [*]u32,

        pub inline fn moduleInst(inst: *const Header) ModuleInst {
            return ModuleInst{ .inner = @alignCast(inst) };
        }

        pub fn funcAddr(inst: *const Header, idx: Module.FuncIdx) FuncAddr {
            const i: usize = @intFromEnum(idx);
            std.debug.assert(i < inst.module.funcCount());
            return if (i < inst.module.inner.raw.func_import_count)
                inst.func_imports[i]
            else
                FuncAddr.init(.{
                    .wasm = .{
                        .module = inst.moduleInst(),
                        .idx = idx,
                    },
                });
        }

        pub inline fn tableInsts(inst: *const Header) []const *TableInst {
            return inst.tables[0..inst.module.inner.raw.table_count];
        }

        pub inline fn definedTableInsts(inst: *const Header) []const *TableInst {
            return inst.tableInsts()[inst.module.inner.raw.table_import_count..];
        }

        pub fn tableAddr(inst: *const Header, idx: Module.TableIdx) TableAddr {
            const i: usize = @intFromEnum(idx);
            return TableAddr{
                .elem_type = inst.module.tableTypes()[i].elem_type,
                .table = inst.tableInsts()[i],
            };
        }

        pub inline fn memInsts(inst: *const Header) []const *MemInst {
            return inst.mems[0..inst.module.inner.raw.mem_count];
        }

        pub inline fn definedMemInsts(inst: *const Header) []const *MemInst {
            return inst.memInsts()[inst.module.inner.raw.mem_import_count..];
        }

        /// Internal API.
        ///
        /// TODO: Add a note here about how some `wasm32-wasip1` applications don't export memory.
        pub fn memAddr(inst: *const Header, idx: Module.MemIdx) *MemInst {
            return inst.memInsts()[@intFromEnum(idx)];
        }

        pub inline fn globalValues(inst: *const Header) []const *anyopaque {
            return inst.globals[0..inst.module.inner.raw.global_count];
        }

        pub inline fn definedGlobalValues(inst: *const Header) []const *anyopaque {
            return inst.globalValues()[inst.module.inner.raw.global_import_count..];
        }

        pub fn globalAddr(inst: *const Header, idx: Module.GlobalIdx) GlobalAddr {
            const i: usize = @intFromEnum(idx);
            return GlobalAddr{
                .global_type = inst.module.globalTypes()[i],
                .value = inst.globalValues()[i],
            };
        }

        pub const DropFlag = struct {
            word: *u32,
            bit: u5,

            inline fn init(drop_mask: []u32, i: u16) DropFlag {
                return .{
                    .word = &drop_mask[i / 32],
                    .bit = @intCast(i % 32),
                };
            }

            pub inline fn get(flag: DropFlag) u1 {
                return @truncate(flag.word.* >> flag.bit);
            }

            pub inline fn drop(flag: DropFlag) void {
                flag.word.* &= (~(@as(u32, 1) << flag.bit));
            }

            /// Used to perform a bitwise-AND with the length of a data or element segment.
            pub fn lengthMask(flag: DropFlag) usize {
                // This has the effect of making the length zero when the data/element segment is "dropped"
                const len_move = @bitSizeOf(usize) - 1;
                const len_mask: usize = @bitCast(@as(isize, @bitCast(@as(usize, flag.get()) << len_move)) >> len_move);
                std.debug.assert(@popCount(len_mask) == 0 or @popCount(len_mask) == @bitSizeOf(usize));
                return len_mask;
            }
        };

        pub fn dataSegmentDropFlag(inst: *const Header, idx: Module.DataIdx) DropFlag {
            const drop_mask_len = std.math.divCeil(
                u32,
                inst.module.inner.raw.datas_count,
                32,
            ) catch unreachable;

            return DropFlag.init(inst.datas_drop_mask[0..drop_mask_len], @intFromEnum(idx));
        }

        pub fn dataSegment(inst: *const Header, idx: Module.DataIdx) []const u8 {
            var data = inst.module.dataSegmentContents(idx);
            data.len &= inst.dataSegmentDropFlag(idx).lengthMask();
            return data;
        }

        pub fn elemSegmentDropFlag(inst: *const Header, idx: Module.ElemIdx) DropFlag {
            const drop_mask_len = std.math.divCeil(
                u32,
                inst.module.inner.raw.elems_count,
                32,
            ) catch unreachable;

            return DropFlag.init(inst.elems_drop_mask[0..drop_mask_len], @intFromEnum(idx));
        }

        pub fn elemSegment(inst: *const Header, idx: Module.ElemIdx) Module.ElemSegment {
            // Make a "copy", and mask away the length if the segment was already dropped
            var elem = inst.module.elementSegments()[@intFromEnum(idx)];
            elem.len &= @truncate(inst.elemSegmentDropFlag(idx).lengthMask());
            return elem;
        }
    };

    inner: *align(std.atomic.cache_line) const Header,

    /// Internal API used to obtain the functions, tables, memories, globals, etc.
    /// that are defined or imported by the module.
    pub inline fn header(inst: ModuleInst) *const Header {
        return inst.inner; // might become &inst.inner.header in the future
    }

    pub const FindExportError = error{
        /// A function, table, memory, or global with the given name could not be found.
        ExportNotFound,
    };

    fn exportVal(inst: ModuleInst, exp: *align(4) const Module.Export) ExternVal {
        const instance = inst.header();
        return switch (exp.desc_tag) {
            .func => .{ .func = instance.funcAddr(exp.desc.func) },
            .table => .{ .table = instance.tableAddr(exp.desc.table) },
            .mem => .{ .mem = instance.memAddr(exp.desc.mem) },
            .global => .{ .global = instance.globalAddr(exp.desc.global) },
        };
    }

    pub fn findExport(inst: ModuleInst, name: []const u8) FindExportError!ExternVal {
        const instance = inst.header();

        for (instance.module.exports()) |*exp| {
            if (!std.mem.eql(u8, name, exp.name(instance.module).bytes))
                continue;

            return inst.exportVal(exp);
        }

        return error.ExportNotFound;
    }

    // pub fn findExportNames(inst: ModuleInst, idx: Module.Export.DescIdx) []const Module.Export.Id {}

    pub const ExportVals = struct {
        inst: ModuleInst,
        len: u32,

        pub const Export = struct {
            name: []const u8,
            val: ExternVal,
        };

        pub fn at(self: ExportVals, i: usize) Export {
            const module = self.inst.header().module;
            const exp = &module.exports()[i];
            return .{
                .val = self.inst.exportVal(exp),
                .name = exp.name(module).bytes,
            };
        }
    };

    pub fn exports(inst: ModuleInst) ExportVals {
        return .{
            .inst = inst,
            .len = @intCast(inst.header().module.exports().len),
        };
    }

    /// Callers must ensure that there are no dangling references to this module's functions,
    /// memories, globals, and tables.
    ///
    /// Additionally, callers are responsible for freeing any imported functions, memories, globals
    /// used by this module.
    pub fn deinit(inst: *ModuleInst) ModuleDeallocation {
        return .{
            .inst = inst,
            .mems = inst.header().definedMemInsts(),
            .tables = inst.header().definedTableInsts(),
        };
    }
};

const std = @import("std");
const reservation_allocator = @import("../reservation_allocator.zig");
const Module = @import("../Module.zig");
const MemInst = @import("memory.zig").MemInst;
const TableInst = @import("table.zig").TableInst;
const FuncAddr = @import("value.zig").FuncAddr;
const TableAddr = @import("value.zig").TableAddr;
const GlobalAddr = @import("value.zig").GlobalAddr;
const ExternVal = @import("value.zig").ExternVal;
const ModuleDeallocation = @import("ModuleDeallocation.zig");
