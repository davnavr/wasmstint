//! Thin wrapper over the Rust [`wasm-smith`] crate.
//!
//! [`wasm-smith`]: https://docs.rs/wasm-smith/latest/wasm_smith/

pub const Configuration = extern struct {
    pub const Flag = enum(u8) {
        disabled = 0,
        enabled = 1,
        randomized = 2,
    };

    pub const AllowedInstructionsMask = packed struct(u32) {
        padding: u32,

        pub const all: AllowedInstructionsMask = @bitCast(@as(u32, std.math.maxInt(u32)));
    };

    pub const MemoryOffsetChoices = extern struct {
        a: u32,
        b: u32,
        c: u32,

        pub fn init(a: u32, b: u32, c: u32) MemoryOffsetChoices {
            std.debug.assert(@max(a, b, c) != 0);
            return MemoryOffsetChoices{ .a = a, .b = b, .c = c };
        }

        pub const default = MemoryOffsetChoices.init(90, 9, 1);
    };

    available_imports: ByteSlice = .empty,
    exports: ByteSlice = .empty,
    module_shape: ByteSlice = .empty,
    max_max_memory_bytes: u128 = 65536 * 4096,
    max_max_table_elements: u64 = 1_000_000,
    allowed_instructions_mask: AllowedInstructionsMask = .all,
    memory_offset_choices: MemoryOffsetChoices = .default,
    allow_start_export: Flag = .randomized,
    allow_floats: Flag = .randomized,
    bulk_memory_enabled: Flag = .randomized,
    canonicalize_nans: Flag = .randomized,
    disallow_traps: Flag = .randomized,
    exceptions_enabled: Flag = .disabled,
    export_everything: Flag = .randomized,
    gc_enabled: Flag = .disabled,
    custom_page_sizes_enabled: Flag = .disabled,
    generate_custom_sections: Flag = .randomized,
    memory64_enabled: Flag = .disabled,
    memory_max_size_required: Flag = .randomized,
    multi_value_enabled: Flag = .randomized,
    reference_types_enabled: Flag = .randomized,
    relaxed_simd_enabled: Flag = .disabled,
    saturating_float_to_int_enabled: Flag = .randomized,
    sign_extension_ops_enabled: Flag = .randomized,
    shared_everything_threads_enabled: Flag = .disabled,
    simd_enabled: Flag = .disabled,
    tail_call_enabled: Flag = .randomized,
    table_max_size_required: Flag = .randomized,
    threads_enabled: Flag = .disabled,
    allow_invalid_funcs: Flag = .disabled,
    wide_arithmetic_enabled: Flag = .disabled,
    extended_const_enabled: Flag = .randomized,
    multi_memory_enabled: Flag = .disabled,

    pub fn fromTarget(comptime Container: type) Configuration {
        return if (@hasDecl(Container, "wasm_smith_config"))
            Container.wasm_smith_config
        else
            Configuration{};
    }
};

pub const ModuleBuffer = extern struct {
    ptr: [*]const u8,
    len: usize,
    cap: usize,

    pub fn bytes(buffer: *const ModuleBuffer) []const u8 {
        std.debug.assert(buffer.len <= buffer.cap);
        return buffer.ptr[0..buffer.len];
    }

    pub fn generate(
        module: *ModuleBuffer,
        input: *Input,
        config: *const Configuration,
    ) Input.Error!void {
        const generateModule = @extern(
            *const fn (
                input: *Input,
                config: *const Configuration,
                buffer: *ModuleBuffer,
            ) callconv(.c) bool,
            .{ .is_dll_import = true, .name = "wasmstint_fuzz_generate_module" },
        );

        if (!generateModule(input, config, module)) {
            return error.BadInput;
        }
    }

    pub fn deinit(module: *ModuleBuffer) void {
        const freeModule = @extern(
            *const fn (buffer: *ModuleBuffer) callconv(.c) void,
            .{ .is_dll_import = true, .name = "wasmstint_fuzz_free_module" },
        );

        freeModule(module);
    }
};

const std = @import("std");
const ByteSlice = @import("ffi.zig").ByteSlice;
const Input = @import("input.zig").Input;
