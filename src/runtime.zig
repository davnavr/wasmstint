const std = @import("std");
const IndexedArena = @import("IndexedArena.zig");
const Module = @import("Module.zig");

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

    pub fn allocate(module: *const Module, imports: []const ExternVal) ModuleInst {
        // TODO: Check types of imports
        _ = imports;
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

pub const FuncType = extern struct {
    types: [*]const Module.ValType,
    param_count: u32,
    result_count: u32,
};

pub const FuncInst = extern struct {
    /// If the lowest bit is `0`, then this is a `*const ModuleInst`.
    module_or_host: *anyopaque,
    func: packed union {
        wasm: Wasm,
        host_data: ?*anyopaque,
    },

    /// A *host function*, uniquely identified by its address.
    ///
    /// Embedders of *wasmstint* are intended to store the data of a host function in some structure containing a
    /// `HostFunc`, passing the pointer to the `HostFunc` to *wasmstint*.
    pub const Host = extern struct {
        signature: FuncType,
    };

    pub const Wasm = packed struct(usize) {
        // TODO: Maybe make it an invariant that this does *not* refer to a function import?
        idx: Module.FuncIdx,
        signature: if (@sizeOf(usize) > 4)
            IndexedArena.Idx(Module.FuncType)
        else
            void,
        padding: if (@sizeOf(usize) > 4) u2 else u1 = 0,
    };

    pub const Expanded = union(enum) {
        host: struct {
            func: *Host,
            data: ?*anyopaque,
        },
        wasm: struct {
            module: *const ModuleInst,
            code: Wasm,
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
