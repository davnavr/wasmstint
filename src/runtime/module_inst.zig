/// "The runtime representation of a *module*."
///
/// To obtain a `ModuleInst`, a `Module` must first be passed to `ModuleAlloc.allocate`, which is
/// then passed to `Interpreter.instantiateModule`.
///
/// Marked `extern`, as it is intended to have the same ABI as a pointer.
pub const ModuleInst = extern struct {
    /// Internal API.
    ///
    /// Allows calculating the layout of a `ModuleInst` once when a `Module` is parsed, rather than
    /// recalculating it every time a module is instantiated.
    pub const Shape = struct {
        size: allocators.Reservation,
        // /// Stores the offsets of the values of defined globals.
        // ///
        // /// These offsets are relative to the address of the value of the first defined global.
        // global_value_offsets: [*]const u16,

        /// Returns an error if an overflow occurred while calculating the module layout.
        pub fn calculate(
            /// Pointer to where the calculated shape is written to.
            shape: *Shape,
            mod: *const Module,
            // /// Allocated in the `module`'s arena.
            // global_value_offsets: []u16,
        ) std.mem.Allocator.Error!void {
            var size = allocators.Reservation{
                .size = @sizeOf(Header),
                .alignment = .fromByteUnits(std.atomic.cache_line),
            };
            try size.reserveAligned(
                FuncRef.Wasm.Block,
                .fromByteUnits(@sizeOf(FuncRef.Wasm.Block)),
                Header.funcBlockCount(mod),
            );
            try size.reserve(FuncRef, mod.funcImportCount());
            try size.reserve(*TableInst, mod.tableCount());
            try size.reserve(*MemInst, mod.memCount());
            try size.reserve(*anyopaque, mod.globalCount());

            try size.reserve(
                u32,
                std.math.divCeil(u32, mod.dataSegmentCount(), 32) catch unreachable,
            );
            try size.reserve(
                u32,
                std.math.divCeil(u32, mod.elementSegmentCount(), 32) catch unreachable,
            );

            try size.reserve(u64, mod.globalInitializers().len);

            // More efficient packing of global values is possible
            const defined_global_types = mod.globalTypes()[mod.globalImportCount()..];
            for (defined_global_types) |*global_type| {
                switch (global_type.val_type) {
                    inline else => |ty| try size.reserve(GlobalAddr.Pointee(ty), 1),
                }
            }

            shape.* = .{ .size = size };
        }
    };

    /// Internal API.
    ///
    /// Contains fields accessed from assembly or LLVM IR code. Deleting or reordering fields
    /// requires updating the code generation for the x86-64 assembly and LLVM IR interpreter
    /// backends.
    pub const Header = extern struct {
        buffer_size: usize,
        module: *Module,
        // /// Used to detect multi-threaded usage of a module instance.
        // ///
        // /// Currently, the WASM specification focuses only on single-threaded usage, with
        // /// *shared* memories currently being the sole exception.
        // acquired_flag: std.atomic.Value(bool) = .{ .raw = false },
        func_imports: [*]const FuncRef,
        func_blocks: [*]align(@sizeOf(FuncRef.Wasm.Block)) const FuncRef.Wasm.Block,
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

        pub inline fn funcBlockCount(mod: *const Module) u32 {
            return std.math.divCeil(
                u32,
                @as(u32, @intCast(module.Inner.ofModule(mod).func_refs.count())) -
                    mod.funcImportCount(),
                FuncRef.Wasm.Block.funcs_per_block,
            ) catch unreachable;
        }

        fn funcBlocks(
            inst: *const Header,
        ) []align(@sizeOf(FuncRef.Wasm.Block)) const FuncRef.Wasm.Block {
            return inst.func_blocks[0..funcBlockCount(inst.module)];
        }

        /// Asserts that `idx` refers to a valid function within this module.
        pub fn funcInst(
            inst: *align(std.atomic.cache_line) const Header,
            idx: Module.FuncIdx,
        ) FuncInst {
            const i: u32 = @intFromEnum(idx);
            const import_count = inst.module.funcImportCount();
            std.debug.assert(i < inst.module.funcCount());
            return if (i < import_count)
                inst.func_imports[i].funcInst()
            else
                FuncInst.init(.{ .wasm = .init(.{ .inner = inst }, idx) });
        }

        /// Asserts that `idx` refers to a valid function within this module, and is either
        /// a function import, or is referencable.
        pub fn funcRef(inst: *const Header, idx: Module.FuncIdx) FuncRef {
            const idx_as_int: u32 = @intFromEnum(idx);
            const import_count = inst.module.funcImportCount();
            std.debug.assert(idx_as_int < inst.module.funcCount());
            if (idx_as_int < import_count) {
                return inst.func_imports[idx_as_int];
            } else {
                const entry_idx: u32 =
                    @intCast(
                        module.Inner.ofModule(inst.module).func_refs.getIndexContext(idx, .{}).?,
                    );
                const rounded_idx: u32 =
                    // entries in [0..import_count] are imports
                    @divFloor(entry_idx - import_count, FuncRef.Wasm.Block.funcs_per_block);

                const block: *align(@sizeOf(FuncRef.Wasm.Block)) const FuncRef.Wasm.Block =
                    &inst.funcBlocks()[rounded_idx];

                const index_bits: FuncRef.Wasm.IdxBits =
                    @intCast((entry_idx - import_count) % FuncRef.Wasm.Block.funcs_per_block);

                std.debug.assert(entry_idx == block.starting_idx + index_bits);

                const wasm = FuncRef.Wasm{
                    .idx_bits = index_bits,
                    .block_addr = @intCast(@shrExact(
                        @intFromPtr(block),
                        comptime @bitSizeOf(FuncRef.Wasm.IdxBits) + 1,
                    )),
                };

                if (builtin.mode == .Debug) {
                    std.debug.assert(@intFromPtr(wasm.block()) == @intFromPtr(block));
                    std.debug.assert(@intFromPtr(wasm.module().inner) == @intFromPtr(inst));
                    std.debug.assert(wasm.funcIdx() == idx);
                }

                return FuncRef.init(.{ .wasm = wasm });
            }
        }

        pub fn startFuncInst(inst: *align(std.atomic.cache_line) const Header) ?FuncInst {
            return if (module.Inner.ofModule(inst.module).start.get()) |start_idx|
                inst.funcInst(start_idx)
            else
                null;
        }

        pub inline fn tableInsts(inst: *const Header) []const *TableInst {
            return inst.tables[0..inst.module.tableCount()];
        }

        pub inline fn definedTableInsts(inst: *const Header) []const *TableInst {
            return inst.tableInsts()[inst.module.tableImportCount()..];
        }

        /// Internal API.
        pub fn tableAddr(inst: *const Header, idx: Module.TableIdx) *TableInst {
            return inst.tableInsts()[@intFromEnum(idx)];
        }

        pub inline fn memInsts(inst: *const Header) []const *MemInst {
            return inst.mems[0..inst.module.memCount()];
        }

        pub inline fn definedMemInsts(inst: *const Header) []const *MemInst {
            return inst.memInsts()[inst.module.memImportCount()..];
        }

        /// Internal API.
        pub fn memAddr(inst: *const Header, idx: Module.MemIdx) *MemInst {
            return inst.memInsts()[@intFromEnum(idx)];
        }

        pub inline fn globalValues(inst: *const Header) []const *anyopaque {
            return inst.globals[0..inst.module.globalCount()];
        }

        pub inline fn definedGlobalValues(inst: *const Header) []const *anyopaque {
            return inst.globalValues()[inst.module.globalImportCount()..];
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
            const drop_mask_len = std.math.divCeil(u32, inst.module.dataSegmentCount(), 32) catch
                unreachable;

            return DropFlag.init(inst.datas_drop_mask[0..drop_mask_len], @intFromEnum(idx));
        }

        pub fn dataSegment(inst: *const Header, idx: Module.DataIdx) []const u8 {
            var data = idx.contents(inst.module);
            data.len &= inst.dataSegmentDropFlag(idx).lengthMask();
            return data;
        }

        pub fn elemSegmentDropFlag(inst: *const Header, idx: Module.ElemIdx) DropFlag {
            const drop_mask_len = std.math.divCeil(u32, inst.module.elementSegmentCount(), 32) catch
                unreachable;

            return DropFlag.init(inst.elems_drop_mask[0..drop_mask_len], @intFromEnum(idx));
        }

        pub fn elemSegment(inst: *const Header, idx: Module.ElemIdx) Module.ElemSegment {
            // Make a "copy", and mask away the length if the segment was already dropped
            var elem = inst.module.elementSegments()[@intFromEnum(idx)];
            elem.len &= @truncate(inst.elemSegmentDropFlag(idx).lengthMask());
            return elem;
        }
    };

    /// Internal API.
    pub const Inner = *align(std.atomic.cache_line) const Header;

    inner: Inner,

    /// Internal API used to obtain the functions, tables, memories, globals, etc.
    /// that are defined or imported by the module.
    pub inline fn header(inst: ModuleInst) *const Header {
        return inst.inner; // might become &inst.inner.header in the future
    }

    fn exportVal(inst: ModuleInst, exp: Module.Export) ExternVal {
        const instance = inst.header();
        return switch (exp.desc_tag) {
            .func => .{ .func = inst.inner.funcRef(exp.desc.func.idx) },
            .table => .{ .table = instance.tableAddr(exp.desc.table.idx) },
            .mem => .{ .mem = instance.memAddr(exp.desc.mem.idx) },
            .global => .{ .global = instance.globalAddr(exp.desc.global.idx) },
        };
    }

    pub const FindExportError = error{
        /// A function, table, memory, or global with the given name could not be found.
        ExportNotFound,
    };

    pub fn findExport(inst: ModuleInst, name: []const u8) FindExportError!ExternVal {
        const instance = inst.header();

        return if (instance.module.findExport(name)) |exp|
            inst.exportVal(exp)
        else
            error.ExportNotFound;
    }

    // pub fn findExportNames(inst: ModuleInst, idx: Module.Export.DescIdx) []const Module.Export.Id {}

    /// A value exported by a `ModuleInst`.
    pub const Export = struct {
        name: Module.Name,
        val: ExternVal,

        pub fn format(self: *const Export, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.print("(export {f} ", .{self.name});
            try self.val.format(writer);
            try writer.writeByte(')');
        }

        pub const List = struct {
            inst: ModuleInst,
            len: u32,

            /// Retrieves the module's *i*th exported value.
            pub fn at(list: List, i: usize) Export {
                const mod = list.inst.header().module;
                const exp = mod.exports()[i];
                return Export{
                    .val = list.inst.exportVal(exp),
                    .name = exp.name(mod),
                };
            }
        };
    };

    pub fn exports(inst: ModuleInst) Export.List {
        return Export.List{
            .inst = inst,
            .len = @intCast(inst.header().module.exports().len),
        };
    }

    /// Frees the allocation backing the `ModuleInst`, and deinitializes its defined memories
    /// and tables.
    ///
    /// Callers must ensure that there are no dangling references to this module's functions,
    /// memories, globals, and tables.
    ///
    /// Additionally, callers are responsible for freeing any imported functions, memories, globals
    /// used by this module.
    ///
    /// TODO: Allow caller of deinit to reuse defined memories/tables
    pub fn deinit(inst: *ModuleInst, allocator: std.mem.Allocator) void {
        for (inst.inner.definedMemInsts()) |mem| {
            mem.free();
        }

        for (inst.inner.definedTableInsts()) |table| {
            table.free();
        }

        const buffer: []align(std.atomic.cache_line) u8 = @as(
            [*]align(std.atomic.cache_line) u8,
            @ptrCast(@constCast(inst.inner)),
        )[0..inst.inner.buffer_size];

        allocator.free(buffer);
        inst.* = undefined;
    }
};

const std = @import("std");
const builtin = @import("builtin");
const allocators = @import("allocators");
const module = @import("module");
const Module = module.Module;
const MemInst = @import("memory.zig").MemInst;
const TableInst = @import("table.zig").TableInst;
const FuncRef = @import("value.zig").FuncRef;
const FuncInst = @import("value.zig").FuncInst;
const GlobalAddr = @import("value.zig").GlobalAddr;
const ExternVal = @import("value.zig").ExternVal;
