const std = @import("std");
const Allocator = std.mem.Allocator;
const IndexedArena = @import("IndexedArena.zig");
const Module = @import("Module.zig");

const ModuleAllocator = *const fn (
    ctx: *anyopaque,
    request: *const ModuleAllocateRequest,
) Allocator.Error!void;

pub const ModuleAllocateRequest = struct {
    table_types: []const Module.TableType,
    // tables: []TableInst,
    memory_types: []const Module.MemType,
    // memories: []MemoryInst,
};

const memory_alignment = 16; // Enough to store aligned `v128` values.

pub const ModuleInst = struct {
    module: *const Module,
    /// Used to detect multi-threaded usage of a module instance.
    ///
    /// Currently, the WASM specification focuses only on single-threaded usage, with
    /// *shared* memories currently being the sole exception.
    acquired_flag: std.atomic.Value(bool) = .{ .raw = false },
    instantiated: bool = false,
    // func_imports,
    // memories
    // tables
    data: IndexedArena.ConstData = &[0]IndexedArena.Word{},

    pub const AllocateError = error{
        ImportTypeMismatch,
        // OutOfMemory
    };

    // TODO: Either take a Store interface struct, or a struct providing { tables: [][]const u8, memories: [][]const u8 }
    // - Store either provides a function for each kind of definition (table, memory, globals),
    //   or a single function to do one big allocation (they have to fill a struct { tables, memories })

    pub fn allocate(
        module: *const Module,
        imports: []const ExternVal,
        gpa: Allocator,
        store_ctx: *anyopaque,
        store: ModuleAllocator,
        scratch: Allocator,
    ) AllocateError!ModuleInst {
        // TODO: Check types of imports
        _ = imports;
        _ = gpa;
        _ = store_ctx;
        _ = store;
        _ = scratch;
        return .{
            .module = module,
        };
    }

    pub const FindExportError = error{ ModuleNotInstantiated, ExportNotFound };

    pub fn findExport(inst: *const ModuleInst, name: []const u8) FindExportError!ExternVal {
        if (!inst.instantiated) return error.ModuleNotInstantiated;
        _ = name;
        unreachable; // TODO
    }
};

// pub const MemoryInst = struct {};

pub const ExternVal = union(enum) {
    func: FuncInst,

    // Could be compacted so that @sizeOf(ExternVal) == @sizeOf([2]usize), but its extra complexity for something
    // that won't be stored in memory for long.
};

pub const FuncInst = extern struct {
    /// If the lowest bit is `0`, then this is a `*const ModuleInst`.
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
        host: struct {
            func: *Host,
            data: ?*anyopaque,
        },
        wasm: struct {
            module: *const ModuleInst,
            code: Module.FuncIdx,
        },
    };

    pub fn expanded(inst: FuncInst) Expanded {
        const module_or_host = @intFromPtr(inst.module_or_host);
        return if (module_or_host & 1 == 0) Expanded{
            .wasm = .{
                .module = @ptrFromInt(module_or_host),
                .code = inst.func.wasm,
            },
        } else .{
            .host = .{
                .func = @ptrFromInt(module_or_host & @as(usize, !1)),
                .data = inst.func.host_data,
            },
        };
    }

    comptime {
        std.debug.assert(@sizeOf(FuncInst) == @sizeOf([2]*anyopaque));
        std.debug.assert(@alignOf(ModuleInst) >= 2);
        std.debug.assert(@alignOf(Host) >= 2);
    }
};
