use std::ptr::NonNull;

pub mod hash;
pub mod wasmi_differential;

use ffi::{FfiSlice, FfiUnstructured, FfiVec};

fn arbitrary_instruction_kinds(
    u: &mut arbitrary::Unstructured,
) -> arbitrary::Result<wasm_smith::InstructionKinds> {
    use wasm_smith::InstructionKind;

    const ALLOWED: [InstructionKind; 9] = [
        InstructionKind::NumericInt,
        InstructionKind::Numeric,
        InstructionKind::Reference,
        InstructionKind::Parametric,
        InstructionKind::Variable,
        InstructionKind::Table,
        InstructionKind::MemoryInt,
        InstructionKind::Memory,
        InstructionKind::Control,
    ];

    let mut selected = arrayvec::ArrayVec::<InstructionKind, { ALLOWED.len() }>::new();
    // let random_bits = u.arbitrary::<u16>()?;

    for kind in ALLOWED.into_iter() {
        if u.arbitrary()? {
            selected.push(kind);
        }
    }

    Ok(wasm_smith::InstructionKinds::new(&selected))
}

fn arbitrary_module(u: &mut arbitrary::Unstructured) -> arbitrary::Result<wasm_smith::Module> {
    const MAX_SMALL: usize = 5;
    const MAX_MEDIUM: usize = 50;
    const MAX_LARGE: usize = 100;
    const MAX_HUGE: usize = 500;

    const MIN_FUNCS: usize = 5;

    let config = wasm_smith::Config {
        allow_start_export: true,
        allowed_instructions: arbitrary_instruction_kinds(u)?,
        allow_floats: u.arbitrary()?,
        bulk_memory_enabled: u.arbitrary()?,
        canonicalize_nans: u.arbitrary()?,
        disallow_traps: u.arbitrary()?,
        exceptions_enabled: false,
        export_everything: false,
        gc_enabled: false,
        custom_page_sizes_enabled: false,
        generate_custom_sections: true,
        max_data_segments: u.int_in_range(0..=MAX_MEDIUM)?,
        max_element_segments: u.int_in_range(0..=MAX_MEDIUM)?,
        max_elements: u.int_in_range(0..=MAX_HUGE)?,
        max_funcs: u.int_in_range(MIN_FUNCS..=MAX_LARGE)?,
        max_globals: u.int_in_range(0..=MAX_LARGE)?,
        max_imports: u.int_in_range(0..=MAX_SMALL)?,
        max_instructions: u.int_in_range(0..=MAX_LARGE)?,
        max_memories: 1,
        max_memory32_bytes: u.int_in_range(0..=0x1_0000_0000)?,
        max_table_elements: u.int_in_range(0..=16_777_216)?,
        max_tables: u.int_in_range(0..=MAX_SMALL)?,
        max_types: u.int_in_range(0..=MAX_LARGE)?,
        memory64_enabled: false,
        // Around half the time, use the minimum LEB encoding
        min_uleb_size: u8::saturating_sub(u.int_in_range(0..=9)?, 5) + 1,
        multi_value_enabled: u.arbitrary()?,
        reference_types_enabled: u.arbitrary()?,
        relaxed_simd_enabled: false,
        saturating_float_to_int_enabled: u.arbitrary()?,
        sign_extension_ops_enabled: u.arbitrary()?,
        shared_everything_threads_enabled: false,
        simd_enabled: false,      // u.arbitrary()?,
        tail_call_enabled: false, // u.arbitrary()?,
        threads_enabled: false,
        allow_invalid_funcs: u.arbitrary()?,
        wide_arithmetic_enabled: false,
        extended_const_enabled: false,
        ..Default::default()
    };

    wasm_smith::Module::new(config, u)
}

#[unsafe(no_mangle)]
extern "C" fn wasmstint_fuzz_arbitrary_module(
    input: NonNull<FfiSlice<u8>>,
    output: NonNull<std::mem::MaybeUninit<FfiVec<u8>>>,
) -> bool {
    let mut output = unsafe { ffi::WritebackPtr::new(output) };
    let mut u = unsafe { FfiUnstructured::new(input) };
    match arbitrary_module(&mut u) {
        Ok(module) => {
            output.write(FfiVec::new(module.to_bytes()));
            true
        }
        Err(_) => false,
    }
}

#[unsafe(no_mangle)]
extern "C" fn wasmstint_fuzz_free_bytes(bytes: NonNull<FfiVec<u8>>) {
    let mut to_drop = FfiVec::new(Vec::new());
    unsafe {
        bytes.swap(NonNull::from(&mut to_drop));
    }

    _ = to_drop;
}
