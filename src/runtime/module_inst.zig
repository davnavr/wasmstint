/// "The runtime representation of a *module*."
///
/// To obtain a `ModuleInst`, a `Module` must first be passed to `ModuleAlloc.allocate`, which is
/// then passed to `Interpreter.instantiateModule`.
pub const ModuleInst = extern struct {
    /// Internal API.
    pub const Header = struct {
        data_len: usize,
        module: Module,
        // /// Used to detect multi-threaded usage of a module instance.
        // ///
        // /// Currently, the WASM specification focuses only on single-threaded usage, with
        // /// *shared* memories currently being the sole exception.
        // acquired_flag: std.atomic.Value(bool) = .{ .raw = false },
        func_import_count: u32,
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

        pub const index = IndexedArena.Idx(Header).fromInt(0);

        pub fn moduleInst(inst: *const Header) ModuleInst {
            const module = ModuleInst{ .data = @constCast(@ptrCast(@alignCast(inst))) };
            std.debug.assert(@intFromPtr(inst) == @intFromPtr(module.header()));
            return module;
        }

        pub fn funcAddr(inst: *const Header, idx: Module.FuncIdx) FuncAddr {
            const i: usize = @intFromEnum(idx);
            std.debug.assert(i < inst.module.funcCount());
            return if (i < inst.func_import_count)
                inst.func_imports[i]
            else
                FuncAddr.init(.{
                    .wasm = .{
                        .module = inst.moduleInst(),
                        .idx = idx,
                    },
                });
        }

        inline fn tableInsts(inst: *const Header) []const *TableInst {
            return inst.tables[0..inst.module.inner.raw.table_count];
        }

        inline fn definedTableInsts(inst: *const Header) []const *TableInst {
            return inst.tableInsts()[inst.module.inner.raw.table_import_count..];
        }

        pub fn tableAddr(inst: *const Header, idx: Module.TableIdx) TableAddr {
            const i: usize = @intFromEnum(idx);
            return TableAddr{
                .elem_type = inst.module.tableTypes()[i].elem_type,
                .table = inst.tableInsts()[i],
            };
        }

        inline fn memInsts(inst: *const Header) []const *MemInst {
            return inst.mems[0..inst.module.inner.raw.mem_count];
        }

        inline fn definedMemInsts(inst: *const Header) []const *MemInst {
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

    data: [*]align(IndexedArena.max_alignment) IndexedArena.Word,

    /// Internal API used to obtain the functions, tables, memories, globals, etc.
    /// that are defined or imported by the module.
    pub fn header(inst: ModuleInst) *const Header {
        const header_ptr: *Header = @ptrCast(inst.data);
        std.debug.assert(
            @intFromPtr(Header.index.getPtr(inst.data[0..header_ptr.data_len])) == @intFromPtr(header_ptr),
        );
        return header_ptr;
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
    pub fn deinit(inst: *ModuleInst, gpa: std.mem.Allocator, store: ModuleAllocator) void {
        const instance = inst.header();
        store.free(ModuleAllocator.Free{
            .mems = instance.definedMemInsts(),
            .tables = instance.definedTableInsts(),
        });

        gpa.free(inst.data[0..instance.data_len]);
        inst.data = undefined;
    }
};

const std = @import("std");
const IndexedArena = @import("../IndexedArena.zig");
const Module = @import("../Module.zig");
const MemInst = @import("memory.zig").MemInst;
const TableInst = @import("table.zig").TableInst;
const FuncAddr = @import("value.zig").FuncAddr;
const TableAddr = @import("value.zig").TableAddr;
const GlobalAddr = @import("value.zig").GlobalAddr;
const ExternVal = @import("value.zig").ExternVal;
const ModuleAllocator = @import("ModuleAllocator.zig");
