//! WASM runtime structures.

pub const TableStride = @import("runtime/table.zig").TableStride;
pub const TableInst = @import("runtime/table.zig").TableInst;

pub const MemInst = @import("runtime/memory.zig").MemInst;

const value = @import("runtime/value.zig");
pub const FuncInst = value.FuncInst;
pub const FuncRef = value.FuncRef;
pub const HostFunc = value.HostFunc;
pub const GlobalAddr = value.GlobalAddr;
pub const ExternAddr = value.ExternAddr;
pub const ExternVal = value.ExternVal;

pub const ImportProvider = @import("runtime/ImportProvider.zig");
pub const ModuleAlloc = @import("runtime/ModuleAlloc.zig");
pub const ModuleInst = @import("runtime/module_inst.zig").ModuleInst;
