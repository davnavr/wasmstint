//! The offsets of structs, as assumed by the generated X86-64 assembly.

pub const module_inst = struct {
    pub const module = 8;
    pub const tables = 40;
    pub const globals = 48;
    pub const datas_drop_mask = 56;
};

pub const module = struct {
    pub const types = 0;
    pub const global_types = 8;
    pub const datas_ptrs = 16;
    pub const datas_lens = 24;
};

pub const mem_inst = struct {
    pub const size = 8;
    pub const capacity = 16;
    pub const limit = 24;
};

pub const table_inst = struct {
    pub const len = 12;
    pub const capacity = 16;
    pub const limit = 20;
};

pub const global_type = struct {
    // currently not explicitly used in generated ASM, just an assumption
    pub const val_type = 0;
};
