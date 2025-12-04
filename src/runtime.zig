//! WASM runtime structures.

pub const TableStride = @import("runtime/table.zig").TableStride;
pub const TableInst = @import("runtime/table.zig").TableInst;
pub const MemInst = @import("runtime/memory.zig").MemInst;
pub const TableAddr = @import("runtime/value.zig").TableAddr;
pub const FuncAddr = @import("runtime/value.zig").FuncAddr;
pub const GlobalAddr = @import("runtime/value.zig").GlobalAddr;
pub const ExternAddr = @import("runtime/value.zig").ExternAddr;
pub const ExternVal = @import("runtime/value.zig").ExternVal;
pub const ImportProvider = @import("runtime/ImportProvider.zig");
pub const ModuleAlloc = @import("runtime/ModuleAlloc.zig");
pub const ModuleInst = @import("runtime/module_inst.zig").ModuleInst;
