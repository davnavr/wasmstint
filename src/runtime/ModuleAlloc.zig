//! A `ModuleInst` that has been *allocated*, but not *instantiated*.

const ModuleAlloc = @This();

/// Accessing the module instance before instantiation has occurred violates
/// the semantics of WebAssembly, even if the module does *not* contain
/// a *start* function.
requiring_instantiation: ModuleInst,
/// `true` if module instantiation is complete and the `start` function, if it exists, has
/// already been run.
instantiated: bool = false,

pub fn assumeInstantiated(alloc: ModuleAlloc) ModuleInst {
    std.debug.assert(alloc.instantiated);
    return alloc.requiring_instantiation;
}

pub fn deinit(alloc: ModuleAlloc) ModuleDeallocation {
    return alloc.requiring_instantiation.deinit();
}

const std = @import("std");
const ModuleInst = @import("module_inst.zig").ModuleInst;
const ModuleDeallocation = @import("ModuleDeallocation.zig");
