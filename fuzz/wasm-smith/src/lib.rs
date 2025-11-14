//! Thin wrapper over [`wasm-smith`].
//!
//! # Safety
//!
//! The Zig callers of these functions must ensure they do not violate Rust's aliasing rules.

#![deny(clippy::wildcard_imports)]
#![deny(missing_unsafe_on_extern)]

use std::mem::MaybeUninit;
use std::ptr::NonNull;

// Could try to use Zig `SmpAllocator` as the global allocator here, but how does that work when the
// Rust side is a shared object?

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Flag {
    Disabled = 0,
    Enabled = 1,
    Randomized = 2,
}

impl Flag {
    fn try_to_bool(self, u: &mut arbitrary::Unstructured) -> arbitrary::Result<bool> {
        match self {
            Self::Disabled => Ok(false),
            Self::Enabled => Ok(true),
            Self::Randomized => u.arbitrary(),
        }
    }
}

#[repr(C)]
pub struct ByteSlice<'a> {
    pub ptr: NonNull<u8>,
    pub len: usize,
    _marker: std::marker::PhantomData<&'a [u8]>,
}

impl<'a> ByteSlice<'a> {
    /// If `slice.len != 0`, copies the contents to a newly allocated [`Vec<u8>`].
    fn try_to_non_empty_vec(&self) -> Option<Vec<u8>> {
        if self.len == 0 {
            return None;
        }

        let mut dst = Vec::with_capacity(self.len);
        let ptr = NonNull::<[MaybeUninit<u8>]>::slice_from_raw_parts(self.ptr.cast(), self.len);

        // Safety: caller ensures `slice` is valid.
        let src: &'a [MaybeUninit<u8>] = unsafe { ptr.as_ref() };
        dst.spare_capacity_mut()[0..self.len].copy_from_slice(src);

        // Safety: `dst` has capacity of at least `slice.len`.
        unsafe {
            dst.set_len(self.len);
        }

        Some(dst)
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct MemoryOffsetChoices {
    pub a: u32,
    pub b: u32,
    pub c: u32,
}

#[repr(C)]
pub struct Configuration<'a> {
    pub available_imports: ByteSlice<'a>,
    pub exports: ByteSlice<'a>,
    pub module_shape: ByteSlice<'a>,
    pub allowed_instructions_mask: u32,
    pub memory_offset_choices: MemoryOffsetChoices,
    pub allow_start_export: Flag,
    pub allow_floats: Flag,
    pub bulk_memory_enabled: Flag,
    pub canonicalize_nans: Flag,
    pub disallow_traps: Flag,
    pub exceptions_enabled: Flag,
    pub export_everything: Flag,
    pub gc_enabled: Flag,
    pub custom_page_sizes_enabled: Flag,
    pub generate_custom_sections: Flag,
    pub memory64_enabled: Flag,
    pub multi_value_enabled: Flag,
    pub reference_types_enabled: Flag,
    pub relaxed_simd_enabled: Flag,
    pub saturating_float_to_int_enabled: Flag,
    pub sign_extension_ops_enabled: Flag,
    pub shared_everything_threads_enabled: Flag,
    pub simd_enabled: Flag,
    pub tail_call_enabled: Flag,
    pub table_max_size_required: Flag,
    pub threads_enabled: Flag,
    pub allow_invalid_funcs: Flag,
    pub wide_arithmetic_enabled: Flag,
    pub extended_const_enabled: Flag,
    /// Sets [`wasm_smith::Config.max_memories`].
    pub multi_memory_enabled: Flag,
}

#[repr(C)]
pub struct ModuleBuffer {
    pub base: NonNull<u8>,
    pub len: usize,
    pub cap: usize,
}

fn generate_module(input: &[u8], config: &Configuration) -> arbitrary::Result<Vec<u8>> {
    let mut u = arbitrary::Unstructured::new(input);

    const MAX_MAXIMUM: usize = 1000;

    // Slightly different from `<wasm_smith::Config as arbitrary::Arbitrary>::arbitrary()`
    let config = wasm_smith::Config {
        available_imports: config.available_imports.try_to_non_empty_vec(),
        exports: config.exports.try_to_non_empty_vec(),
        module_shape: config.module_shape.try_to_non_empty_vec(),
        allow_start_export: config.allow_start_export.try_to_bool(&mut u)?,
        allowed_instructions: {
            use wasm_smith::InstructionKind;

            const ALLOWED_INSTRUCTION_KINDS: [InstructionKind; 9] = [
                InstructionKind::NumericInt,
                InstructionKind::Numeric,
                InstructionKind::Reference,
                InstructionKind::Parametric,
                InstructionKind::Variable,
                InstructionKind::Table,
                InstructionKind::MemoryInt,
                InstructionKind::Memory,
                InstructionKind::Control,
                // InstructionKind::VectorInt,
                // InstructionKind::Vector,
                // InstructionKind::Aggregate,
            ];

            let mut allowed_mask = config.allowed_instructions_mask;
            assert!(allowed_mask != 0, "allowed instructions was empty");

            // We have `ArrayVec` at home:
            let mut selected = [InstructionKind::NumericInt; ALLOWED_INSTRUCTION_KINDS.len()];
            let mut selected_len = 0;

            for kind in ALLOWED_INSTRUCTION_KINDS {
                if allowed_mask & 1 != 0 {
                    selected[selected_len] = kind;
                    selected_len += 1;
                }

                allowed_mask >>= 1;
            }

            wasm_smith::InstructionKinds::new(&selected[0..selected_len])
        },
        allow_floats: config.allow_floats.try_to_bool(&mut u)?,
        bulk_memory_enabled: config.bulk_memory_enabled.try_to_bool(&mut u)?,
        canonicalize_nans: config.canonicalize_nans.try_to_bool(&mut u)?,
        disallow_traps: config.disallow_traps.try_to_bool(&mut u)?,
        exceptions_enabled: config.exceptions_enabled.try_to_bool(&mut u)?,
        export_everything: config.export_everything.try_to_bool(&mut u)?,
        gc_enabled: config.gc_enabled.try_to_bool(&mut u)?,
        custom_page_sizes_enabled: config.custom_page_sizes_enabled.try_to_bool(&mut u)?,
        generate_custom_sections: config.generate_custom_sections.try_to_bool(&mut u)?,
        max_aliases: u.int_in_range(0..=MAX_MAXIMUM)?,
        max_components: 0,
        max_data_segments: u.int_in_range(0..=MAX_MAXIMUM)?,
        max_element_segments: u.int_in_range(0..=MAX_MAXIMUM)?,
        max_elements: u.int_in_range(0..=MAX_MAXIMUM)?,
        max_exports: u.int_in_range(0..=MAX_MAXIMUM)?,
        max_funcs: u.int_in_range(0..=MAX_MAXIMUM)?,
        max_globals: u.int_in_range(0..=MAX_MAXIMUM)?,
        max_imports: u.int_in_range(0..=MAX_MAXIMUM)?,
        max_instances: 0,
        max_instructions: u.int_in_range(0..=MAX_MAXIMUM)?,
        max_memories: {
            let max_max_memory = if config.multi_memory_enabled.try_to_bool(&mut u)? {
                100
            } else {
                1
            };

            u.int_in_range(0..=max_max_memory)
        }?,
        max_memory32_bytes: u.int_in_range(0..=u32::MAX as u64 + 1)?,
        max_memory64_bytes: u.int_in_range(0..=u64::MAX as u128 + 1)?,
        max_modules: 0,
        max_nesting_depth: u.int_in_range(0..=10)?,
        max_table_elements: u.int_in_range(0..=1_000_000)?,
        max_tables: u.int_in_range(0..=100)?,
        max_tags: u.int_in_range(0..=MAX_MAXIMUM)?,
        max_type_size: 1000,
        max_types: u.int_in_range(0..=MAX_MAXIMUM)?,
        max_values: 0,
        memory64_enabled: config.memory64_enabled.try_to_bool(&mut u)?,
        memory_offset_choices: wasm_smith::MemoryOffsetChoices(
            config.memory_offset_choices.a,
            config.memory_offset_choices.b,
            config.memory_offset_choices.c,
        ),
        memory_max_size_required: false,
        min_data_segments: 0,
        min_element_segments: 0,
        min_elements: 0,
        min_exports: 0,
        min_funcs: 0,
        min_globals: 0,
        min_imports: 0,
        min_memories: 0,
        min_tables: 0,
        min_tags: 0,
        min_types: 0,
        min_uleb_size: u8::saturating_sub(u.int_in_range(0..=10)?, 5),
        multi_value_enabled: config.multi_value_enabled.try_to_bool(&mut u)?,
        reference_types_enabled: config.reference_types_enabled.try_to_bool(&mut u)?,
        relaxed_simd_enabled: config.relaxed_simd_enabled.try_to_bool(&mut u)?,
        saturating_float_to_int_enabled: config
            .saturating_float_to_int_enabled
            .try_to_bool(&mut u)?,
        sign_extension_ops_enabled: config.sign_extension_ops_enabled.try_to_bool(&mut u)?,
        shared_everything_threads_enabled: config
            .shared_everything_threads_enabled
            .try_to_bool(&mut u)?,
        simd_enabled: config.simd_enabled.try_to_bool(&mut u)?,
        tail_call_enabled: config.tail_call_enabled.try_to_bool(&mut u)?,
        table_max_size_required: config.table_max_size_required.try_to_bool(&mut u)?,
        threads_enabled: config.threads_enabled.try_to_bool(&mut u)?,
        allow_invalid_funcs: config.allow_invalid_funcs.try_to_bool(&mut u)?,
        wide_arithmetic_enabled: config.wide_arithmetic_enabled.try_to_bool(&mut u)?,
        extended_const_enabled: config.extended_const_enabled.try_to_bool(&mut u)?,
    };

    Ok(wasm_smith::Module::new(config, &mut u)?.to_bytes())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasmstint_fuzz_generate_module(
    input_ptr: NonNull<u8>,
    input_len: usize,
    config: &Configuration,
    buffer: &mut MaybeUninit<ModuleBuffer>,
) -> bool {
    let input: &[u8] =
        unsafe { NonNull::<[u8]>::slice_from_raw_parts(input_ptr, input_len).as_ref() };

    match generate_module(input, config) {
        Ok(bytes) => {
            let mut bytes = std::mem::ManuallyDrop::<Vec<u8>>::new(bytes);
            let cap = bytes.capacity();
            buffer.write(ModuleBuffer {
                len: bytes.len(),
                base: NonNull::<u8>::new(bytes.as_mut_ptr()).unwrap(),
                cap,
            });

            true
        }
        Err(err) => match err {
            arbitrary::Error::NotEnoughData | arbitrary::Error::IncorrectFormat => false,
            arbitrary::Error::EmptyChoose | _ => unreachable!(),
        },
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wasmstint_fuzz_free_module(buffer: &mut ModuleBuffer) {
    unsafe {
        _ = Vec::<u8>::from_raw_parts(buffer.base.as_ptr(), buffer.len, buffer.cap);
    }

    buffer.base = NonNull::<u8>::dangling();
    buffer.len = 0;
    buffer.cap = 0;
}
