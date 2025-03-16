use ffi::{FfiSlice, FfiVec};
use std::ptr::NonNull;

fn arbitrary_module(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Vec<u8>> {
    const MAX_SMALL: u16 = 5;
    const MAX_MEDIUM: u16 = 20;
    const MAX_LARGE: u16 = 50;
    const MAX_HUGE: u16 = 100;

    let mut random_bits =
        bitvec::array::BitArray::<[u8; 1]>::new([u.arbitrary::<u8>()?]).into_iter();

    let config = wasm_smith::Config {
        allow_start_export: false,
        allowed_instructions: crate::arbitrary_instruction_kinds(u)?,
        allow_floats: random_bits.next().unwrap(),
        bulk_memory_enabled: random_bits.next().unwrap(),
        canonicalize_nans: true, // Ensures both wasmi and wasmsmith use the same NaNs
        disallow_traps: false,
        exceptions_enabled: false,
        export_everything: true,
        gc_enabled: false,
        custom_page_sizes_enabled: false,
        generate_custom_sections: false,
        max_data_segments: u.int_in_range(0..=MAX_MEDIUM)?.into(),
        max_element_segments: u.int_in_range(0..=MAX_MEDIUM)?.into(),
        max_elements: u.int_in_range(0..=MAX_HUGE)?.into(),
        max_funcs: u.int_in_range(1..=MAX_MEDIUM)?.into(),
        max_globals: u.int_in_range(0..=MAX_MEDIUM)?.into(),
        // Currently, imports are not sgenerated to simplify testing
        max_imports: 0, // u.int_in_range(0..=MAX_SMALL)?.into(),
        max_instructions: u.int_in_range(0..=MAX_LARGE)?.into(),
        max_memories: 1,
        max_memory32_bytes: u.int_in_range(0u32..=0x1000_0000)?.into(),
        max_table_elements: u.int_in_range(0u32..=16_777_216)?.into(),
        max_tables: u.int_in_range(0..=MAX_SMALL)?.into(),
        max_types: u.int_in_range(0..=MAX_LARGE)?.into(),
        memory64_enabled: false,
        // Around half the time, use the minimum LEB encoding
        min_uleb_size: u8::saturating_sub(u.int_in_range(0u8..=9)?, 5) + 1,
        multi_value_enabled: random_bits.next().unwrap(),
        reference_types_enabled: random_bits.next().unwrap(),
        relaxed_simd_enabled: false,
        saturating_float_to_int_enabled: random_bits.next().unwrap(),
        sign_extension_ops_enabled: random_bits.next().unwrap(),
        shared_everything_threads_enabled: false,
        simd_enabled: false,      // random_bits.next().unwrap(),
        tail_call_enabled: false, // random_bits.next().unwrap(),
        threads_enabled: false,
        allow_invalid_funcs: false, // random_bits.next().unwrap(),
        wide_arithmetic_enabled: false,
        extended_const_enabled: false,
        ..Default::default()
    };

    Ok(wasm_smith::Module::new(config, u)?.to_bytes())
}

#[repr(transparent)]
pub struct EntityRef<T> {
    idx: u32,
    _marker: std::marker::PhantomData<T>,
}

impl<T> EntityRef<T> {
    fn from_raw(idx: u32) -> Self {
        assert_ne!(idx, u32::MAX, "reserved value");
        Self {
            idx,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T> Copy for EntityRef<T> {}

impl<T> Clone for EntityRef<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> PartialEq for EntityRef<T> {
    fn eq(&self, other: &Self) -> bool {
        self.idx == other.idx
    }
}

impl<T> Eq for EntityRef<T> {}

impl<T> std::fmt::Debug for EntityRef<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.idx, f)
    }
}

impl<T> cranelift_entity::EntityRef for EntityRef<T> {
    fn new(idx: usize) -> Self {
        Self::from_raw(u32::try_from(idx).unwrap())
    }

    fn index(self) -> usize {
        self.idx as usize
    }
}

impl<T> cranelift_entity::packed_option::ReservedValue for EntityRef<T> {
    fn reserved_value() -> Self {
        Self {
            idx: u32::MAX,
            _marker: std::marker::PhantomData,
        }
    }

    fn is_reserved_value(&self) -> bool {
        self.idx == u32::MAX
    }
}

// type EntityList<T> = cranelift_entity::EntityList<EntityRef<T>>;
// type EntityListPool<T> = cranelift_entity::ListPool<EntityRef<T>>;
type EntityPrimaryMap<T> = cranelift_entity::PrimaryMap<EntityRef<T>, T>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct StringRef(u32);

impl StringRef {
    fn intern_with_hint(
        pool: &mut wasmi_collections::StringInterner,
        s: &str,
        hint: wasmi_collections::string_interner::InternHint,
    ) -> Self {
        Self(pool.get_or_intern_with_hint(s, hint).into_u32())
    }

    fn intern(pool: &mut wasmi_collections::StringInterner, s: &str) -> Self {
        Self::intern_with_hint(
            pool,
            s,
            wasmi_collections::string_interner::InternHint::None,
        )
    }

    fn to_str(self, pool: &wasmi_collections::StringInterner) -> &str {
        pool.resolve(wasmi_collections::string_interner::Sym::from_u32(self.0))
            .unwrap()
    }
}

#[unsafe(no_mangle)]
extern "C" fn wasmstint_fuzz_differential_wasmi_string_contents(
    exec: &Execution,
    str: StringRef,
) -> FfiSlice<u8> {
    FfiSlice::from_slice(str.to_str(&exec.pools.strings).as_bytes())
}

macro_rules! u32_wrapper {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
        pub struct $name(u32);
    };
}

u32_wrapper!(ExternRef);

impl ExternRef {
    const NULL: Self = Self(0);
}

impl arbitrary::Arbitrary<'_> for ExternRef {
    fn arbitrary(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Self> {
        Ok(if u.arbitrary::<u8>()? <= 31 {
            Self::NULL
        } else {
            Self(u.int_in_range(1..=u32::MAX)?)
        })
    }
}

// #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
// struct HostFunc {
//     param_count: u16,
//     result_count: u16,
//     types: u32,
// }

// impl HostFunc {
//     fn types<'a>(&self, pools: &'a ExecutionPools) -> &'a [ValType] {
//         return &pools.types.as_slice()[usize::try_from(self.types).unwrap()..]
//             [0..usize::from(self.param_count) + usize::from(self.result_count)];
//     }

//     fn result_types<'a>(&self, pools: &'a ExecutionPools) -> &'a [ValType] {
//         return &self.types(pools)[self.param_count.into()..];
//     }
// }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ZigUndefinedByte {
    Undefined = 0xAA,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ArgumentVal {
    I32(i32) = 0,
    I64(i64) = 1,
    F32(u32) = 2,
    F64(u64) = 3,
    NullFuncRef = 4,
    FuncRef(StringRef) = 5,
    ExternRef(ExternRef) = 7,
    #[doc(hidden)]
    Invalid([ZigUndefinedByte; 12]) = 0xAAAA_AAAA,
}

impl cranelift_entity::EntityRef for ArgumentVal {
    fn new(len: usize) -> Self {
        Self::I32(u32::try_from(len).unwrap() as i32)
    }

    fn index(self) -> usize {
        match self {
            Self::I32(len) => usize::try_from(len as u32).unwrap(),
            _ => unreachable!("invalid length value {:?}", self),
        }
    }
}

impl cranelift_entity::packed_option::ReservedValue for ArgumentVal {
    fn reserved_value() -> Self {
        Self::Invalid([ZigUndefinedByte::Undefined; 12])
    }

    fn is_reserved_value(&self) -> bool {
        matches!(self, Self::Invalid(_))
    }
}

type ArgumentList = cranelift_entity::EntityList<ArgumentVal>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ResultVal {
    I32(i32) = 0,
    I64(i64) = 1,
    F32(u32) = 2,
    F64(u64) = 3,
    NullFuncRef = 4,
    FuncRef = 5,
    ExternRef(ExternRef) = 7,
    #[doc(hidden)]
    Invalid([ZigUndefinedByte; 12]) = 0xAAAA_AAAA,
}

impl cranelift_entity::EntityRef for ResultVal {
    fn new(len: usize) -> Self {
        Self::I32(u32::try_from(len).unwrap() as i32)
    }

    fn index(self) -> usize {
        match self {
            Self::I32(len) => usize::try_from(len as u32).unwrap(),
            _ => unreachable!("invalid length value {:?}", self),
        }
    }
}

impl cranelift_entity::packed_option::ReservedValue for ResultVal {
    fn reserved_value() -> Self {
        Self::Invalid([ZigUndefinedByte::Undefined; 12])
    }

    fn is_reserved_value(&self) -> bool {
        matches!(self, Self::Invalid(_))
    }
}

type ResultList = cranelift_entity::EntityList<ResultVal>;

macro_rules! trap_codes {
    {$($name:ident = $value:literal,)*} => {

/// FFI type representing both a `wasmstint` Zig `Trap.Code` and a [`wasmi::TrapCode`].
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(i32)]
pub enum TrapCode {
    $($name = $value,)*
}

impl TrapCode {
    fn new(code: wasmi::core::TrapCode) -> Option<Self> {
        match (code) {
            $(wasmi::core::TrapCode::$name => Some(Self::$name),)*
            _ => None,
        }
    }
}

    };
}

trap_codes! {
    UnreachableCodeReached = 0,
    MemoryOutOfBounds = 5,
    TableOutOfBounds = 6,
    IndirectCallToNull = 7,
    IntegerDivisionByZero = 2,
    IntegerOverflow = 3,
    BadConversionToInteger = 4,
    BadSignature = 8,
}

macro_rules! val_type {
    {$($name:ident = $value:literal,)*} => {
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
enum ValType {
    $($name = $value,)*
}

impl From<wasmi::core::ValType> for ValType {
    fn from(val_type: wasmi::core::ValType) -> Self {
        match val_type {
            $(wasmi::core::ValType::$name => Self::$name,)*
        }
    }
}

impl From<ValType> for wasmi::core::ValType {
    fn from(val_type: ValType) -> Self {
        match val_type {
            $(ValType::$name => Self::$name,)*
        }
    }
}

    };
}

val_type! {
    I32 = 0x7F,
    I64 = 0x7E,
    F32 = 0x7D,
    F64 = 0x7C,
    FuncRef = 0x70,
    ExternRef = 0x6F,
    V128 = 0x7B,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct CheckMemoryContents {
    hash: crate::hash::Hash,
    length: usize,
    memory: StringRef,
}

impl CheckMemoryContents {
    fn from_exported_memory(
        ctx: StoreContext,
        module: &wasmi::Instance,
        hasher: crate::hash::Seed,
        name: StringRef,
    ) -> Self {
        let mem = module
            .get_memory(&ctx, name.to_str(&ctx.data().pools.strings))
            .unwrap();

        Self {
            hash: hasher.hash(mem.data(&ctx)),
            length: mem.data_size(ctx),
            memory: name,
        }
    }
}

// Can't hash a table, so this simply compares an element
#[derive(Clone, Copy)]
#[repr(C)]
pub struct CheckTableElement {
    table: StringRef,
    index: u32,
    expected: ResultVal,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct CheckGlobalValue {
    name: StringRef,
    expected: ResultVal,
}

#[derive(Clone, Copy)]
#[repr(u32)]
pub enum InvokeResult<Results = ResultList> {
    Values(Results) = 0,
    Trap(TrapCode) = 1,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Invoke {
    name: StringRef,
    arguments: ArgumentList,
    results: InvokeResult,
}

// #[derive(Clone, Copy)]
// #[repr(C)]
// struct ImportedGlobal {
//     value: ArgumentVal,
//     expected_type: ValType,
//     mutable: bool,
// }

// #[derive(Clone, Copy)]
// #[repr(C)]
// struct ImportedMem {
//     size: u32,
//     minimum: u32,
//     maximum: u32,
// }

// #[derive(Clone, Copy)]
// #[repr(C)]
// struct ImportedTable {
//     length: u32,
//     minimum: u32,
//     maximum: u32,
//     expected_type: ValType,
// }

// #[derive(Clone, Copy)]
// #[repr(u32)]
// enum ProvidedImportKind {
//     Func(EntityRef<HostFunc>) = 0,
//     Table(ImportedTable) = 1,
//     Mem(ImportedMem) = 2,
//     Global(ImportedGlobal) = 3,
// }

// #[derive(Clone, Copy)]
// #[repr(C)]
// struct ProvidedImport {
//     module: StringRef,
//     name: StringRef,
//     kind: ProvidedImportKind,
// }

#[derive(Clone, Copy)]
#[repr(u32)]
pub enum Action {
    Invoke(EntityRef<Invoke>) = 0,
    CheckMemoryContents(EntityRef<CheckMemoryContents>) = 1,
    CheckTableElement(EntityRef<CheckTableElement>) = 2,
    CheckGlobalValue(EntityRef<CheckGlobalValue>) = 3,
    // WriteToMemory
    // WriteToTable
    // MutateGlobal
}

/// # Safety
///
/// `exec` must be a valid reference.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasmstint_fuzz_differential_wasmi_get_invoke(
    exec: &Execution,
    invoke: EntityRef<Invoke>,
) -> &Invoke {
    exec.pools.invokes.get(invoke).unwrap()
}

// #[derive(Clone, Copy)]
// #[repr(C)]
// struct RecordedHostCall {
//     func: EntityRef<HostFunc>,
//     arguments: ResultList,
//     results: InvokeResult<ArgumentList>,
// }

#[derive(Default)]
struct ExecutionPools {
    argument_vals: cranelift_entity::ListPool<ArgumentVal>,
    result_vals: cranelift_entity::ListPool<ResultVal>,

    strings: wasmi_collections::StringInterner,
    invokes: EntityPrimaryMap<Invoke>,
    // host_funcs: EntityPrimaryMap<HostFunc>,
    check_memory_contents: EntityPrimaryMap<CheckMemoryContents>,
    check_table_elements: EntityPrimaryMap<CheckTableElement>,
    check_global_values: EntityPrimaryMap<CheckGlobalValue>,
}

// #[derive(Clone, Copy)]
// #[repr(C)]
// struct Counts {
//     // host_funcs: u32,
//     // funcs: u32,
// }

#[repr(C)]
pub struct Execution {
    wasm: FfiVec<u8>,
    // counts: Counts,
    // provided_imports: ffi::OwnedSlice<ProvidedImport>,
    instantiation: ExecutionInstantiateResult,
    // recorded_host_calls: FfiVec<RecordedHostCall>,

    // This field is not accessed in Zig
    pools: ExecutionPools,
}

#[repr(u32)]
pub enum ExecutionInstantiateResult {
    Trapped(TrapCode) = 0,
    Instantiated(FfiVec<Action>) = 1,
}

struct ExecutionState<'u, 'a> {
    u: &'u mut arbitrary::Unstructured<'a>,
    pools: ExecutionPools,
    funcs: Vec<StringRef>,
    /// Corresponds to the `funcs` vector, and avoids having to perform a lookup by name every time
    /// a `funcref` is required.
    funcrefs: Vec<wasmi::Func>,
    globals: Vec<StringRef>,
    tables: Vec<StringRef>,
    mems: Vec<StringRef>,
    // recorded_host_calls: Vec<RecordedHostCall>,
}

// TODO: Tell the folks at wasmi that StoreContext should manually implement Copy and Clone
type StoreContext<'s, 'u, 'a> = wasmi::StoreContext<'s, ExecutionState<'u, 'a>>;
type StoreContextMut<'s, 'u, 'a> = wasmi::StoreContextMut<'s, ExecutionState<'u, 'a>>;

impl ExternRef {
    fn to_wasmi(self, ctx: StoreContextMut) -> wasmi::ExternRef {
        wasmi::ExternRef::new::<std::num::NonZeroU32>(ctx, std::num::NonZeroU32::new(self.0))
    }

    fn from_wasmi(ctx: StoreContext, extern_ref: wasmi::ExternRef) -> Self {
        Self(
            extern_ref
                .data(ctx)
                .map(|any_ref| {
                    any_ref
                        .downcast_ref::<std::num::NonZeroU32>()
                        .unwrap()
                        .get()
                })
                .unwrap_or(0),
        )
    }
}

// trait WasmiExporter {
//     fn get_export(&self, name: &str) -> Option<wasmi::Export>;
// }
//
// impl WasmiExporter for wasmi::Instance {
//     fn get_export(&self, name: &str) -> Option<wasmi::Export> {
//         Self::get_export(&self, store, name)
//     }
// }

impl ArgumentVal {
    fn to_wasmi(self, ctx: StoreContextMut, module: &wasmi::Instance) -> wasmi::Val {
        match self {
            Self::I32(i) => wasmi::Val::I32(i),
            Self::I64(i) => wasmi::Val::I64(i),
            Self::F32(i) => wasmi::Val::F32(wasmi::core::F32::from_bits(i)),
            Self::F64(i) => wasmi::Val::F64(wasmi::core::F64::from_bits(i)),
            Self::NullFuncRef => wasmi::Val::FuncRef(wasmi::FuncRef::null()),
            Self::FuncRef(name) => wasmi::Val::FuncRef(
                module
                    .get_func(&ctx, name.to_str(&ctx.data().pools.strings))
                    .unwrap()
                    .into(),
            ),
            Self::ExternRef(n) => wasmi::Val::ExternRef(n.to_wasmi(ctx)),
            Self::Invalid(_) => unreachable!(),
        }
    }

    // fn default(val_type: ValType) -> Self {
    //     match val_type {
    //         ValType::I32 => Self::I32(0),
    //         ValType::I64 => Self::I64(0),
    //         ValType::F32 => Self::F32(0),
    //         ValType::F64 => Self::F64(0),
    //         ValType::FuncRef => Self::NullFuncRef,
    //         ValType::ExternRef => Self::ExternRef(ExternRef::NULL),
    //         ValType::V128 => todo!(),
    //     }
    // }

    fn arbitrary_of_type(val_type: ValType, mut ctx: StoreContextMut) -> arbitrary::Result<Self> {
        let ExecutionState { u, funcs, .. } = ctx.data_mut();
        Ok(match val_type {
            ValType::I32 => Self::I32(u.arbitrary()?),
            ValType::I64 => Self::I64(u.arbitrary()?),
            ValType::F32 => Self::F32(u.arbitrary::<f32>()?.to_bits()),
            ValType::F64 => Self::F64(u.arbitrary::<f64>()?.to_bits()),
            ValType::FuncRef => {
                if funcs.is_empty() || u.arbitrary::<u8>()? <= 31 {
                    Self::NullFuncRef
                } else {
                    Self::FuncRef(*u.choose(funcs.as_slice())?)
                }
            }
            ValType::ExternRef => Self::ExternRef(u.arbitrary()?),
            ValType::V128 => todo!(),
        })
    }
}

impl ResultVal {
    fn from_wasmi(val: wasmi::Val, ctx: StoreContext) -> Self {
        match val {
            wasmi::Val::I32(i) => Self::I32(i),
            wasmi::Val::I64(i) => Self::I64(i),
            wasmi::Val::F32(f) => Self::F32(f.to_bits()),
            wasmi::Val::F64(f) => Self::F64(f.to_bits()),
            wasmi::Val::FuncRef(r) => {
                if r.is_null() {
                    Self::NullFuncRef
                } else {
                    Self::FuncRef
                }
            }
            wasmi::Val::ExternRef(r) => Self::ExternRef(ExternRef::from_wasmi(ctx, r)),
            wasmi::Val::V128(_) => todo!(),
        }
    }
}

// #[derive(Debug)]
// #[repr(transparent)]
// struct ArbitraryErrorWrapper(arbitrary::Error);
//
// impl ArbitraryErrorWrapper {
//     fn wrap_result<T>(result: arbitrary::Result<T>) -> Result<T, ArbitraryErrorWrapper> {
//         result.map_err(ArbitraryErrorWrapper)
//     }
// }
//
// impl std::fmt::Display for ArbitraryErrorWrapper {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         std::fmt::Display::fmt(&self.0, f)
//     }
// }
//
// impl wasmi::core::HostError for ArbitraryErrorWrapper {}
//
// impl From<ArbitraryErrorWrapper> for wasmi::Error {
//     fn from(err: ArbitraryErrorWrapper) -> Self {
//         Self::host(err)
//     }
// }

// fn host_func_closure(
//     host_func: EntityRef<HostFunc>,
// ) -> impl Fn(
//     wasmi::Caller<'_, ExecutionState>,
//     &[wasmi::Val],
//     &mut [wasmi::Val],
// ) -> Result<(), wasmi::Error> {
//     move |mut caller, _, results| {
//         let mut call = RecordedHostCall {
//             func: host_func,
//             arguments: ResultList::new(),
//             results: InvokeResult::Values(ArgumentList::new()),
//         };
//
//         let ExecutionState { u, pools, .. } = caller.data_mut();
//         if ArbitraryErrorWrapper::wrap_result(u.arbitrary::<u8>())? <= 31 {
//             return Err(wasmi::core::TrapCode::UnreachableCodeReached.into());
//         }
//
//         // Record the arguments received from WASM
//         //call.arguments
//
//         let mut recorded_results = ResultList::new();
//         recorded_results.grow_at(0, results.len(), &mut caller.data_mut().pools.result_vals);
//
//         let result_types = pools.host_funcs.get(host_func).unwrap().result_types(pools);
//         assert!(result_types.len() == results.len());
//         for (ty, dst) in result_types.iter().zip(results) {
//             let ctx = wasmi::AsContextMut::as_context_mut(&mut caller);
//             let result = ArbitraryErrorWrapper::wrap_result(ArgumentVal::arbitrary_of_type(
//                 (*ty).into(),
//                 ctx,
//             ))?;
//
//             //recorded_results.get_mut()
//
//             // TODONT: Can't get exports and context at the same time, store a wasmi::Instance in the state?
//             *dst = result.to_wasmi(ctx, caller);
//         }
//
//         Ok(())
//     }
// }

// struct Imports {
//     ffi: Box<[ProvidedImport]>,
//     wasmi: Box<[wasmi::Extern]>,
// }
//
// fn arbitrary_imports(
//     mut ctx: StoreContextMut,
//     module: &wasmi::Module,
// ) -> arbitrary::Result<Imports> {
//     let mut func_type_dedupe = std::collections::HashMap::<wasmi::FuncType, HostFunc>::new();
//     let mut provided_globals = Vec::<usize>::new();
//
//     let mut provided_imports = Vec::<ProvidedImport>::new();
//     let mut import_values = Vec::<wasmi::Extern>::new();
//     let imports_iter = module.imports();
//     provided_imports.reserve_exact(imports_iter.len());
//     import_values.reserve_exact(imports_iter.len());
//
//     for import in imports_iter {
//         let (kind, val) = match import.ty() {
//             wasmi::ExternType::Global(global_type) => {
//                 let val_type = global_type.content();
//
//                 // Placeholder value, filled once all functions are known (after instantiation)
//                 let global = wasmi::Global::new(
//                     &mut ctx,
//                     wasmi::Val::default(val_type),
//                     global_type.mutability(),
//                 );
//
//                 provided_globals.push(import_values.len());
//
//                 (
//                     ProvidedImportKind::Global(ImportedGlobal {
//                         value: ArgumentVal::default(val_type.into()),
//                         expected_type: val_type.into(),
//                         mutable: global_type.mutability().is_mut(),
//                     }),
//                     global.into(),
//                 )
//             }
//             wasmi::ExternType::Memory(mem_type) => {
//                 let minimum: u32 = mem_type.minimum().try_into().unwrap();
//                 let maximum = if let Some(maximum) = mem_type.maximum() {
//                     u32::try_from(maximum).unwrap()
//                 } else {
//                     minimum.saturating_add(ctx.data_mut().u.int_in_range(0u16..=64)?.into())
//                 };
//
//                 let mem = wasmi::Memory::new(
//                     &mut ctx,
//                     wasmi::MemoryType::new(minimum, Some(maximum)).unwrap(),
//                 )
//                 .unwrap();
//
//                 if 1 < maximum - minimum {
//                     let delta = ctx.data_mut().u.int_in_range(0u32..=(maximum - minimum))?;
//                     mem.grow(&mut ctx, delta.into()).unwrap();
//                 }
//
//                 (
//                     ProvidedImportKind::Mem(ImportedMem {
//                         size: mem.size(&mut ctx).try_into().unwrap(),
//                         minimum,
//                         maximum,
//                     }),
//                     mem.into(),
//                 )
//             }
//             wasmi::ExternType::Func(func_type) => {
//                 use std::collections::hash_map::Entry;
//
//                 let pools = &mut ctx.data_mut().pools;
//                 let signature = match func_type_dedupe.entry(func_type.clone()) {
//                     Entry::Vacant(vacant) => {
//                         let types_idx = u32::try_from(pools.types.len()).unwrap();
//                         pools.types.reserve(
//                             usize::from(func_type.len_params())
//                                 + usize::from(func_type.len_results()),
//                         );
//
//                         pools
//                             .types
//                             .extend(func_type.params().iter().copied().map(ValType::from));
//                         pools
//                             .types
//                             .extend(func_type.results().iter().copied().map(ValType::from));
//
//                         *vacant.insert(HostFunc {
//                             param_count: func_type.len_params(),
//                             result_count: func_type.len_results(),
//                             types: types_idx,
//                         })
//                     }
//                     Entry::Occupied(existing) => *existing.get(),
//                 };
//
//                 let host_func = pools.host_funcs.push(signature);
//                 (
//                     ProvidedImportKind::Func(host_func),
//                     wasmi::Func::new(&mut ctx, func_type.clone(), host_func_closure(host_func))
//                         .into(),
//                 )
//             }
//             wasmi::ExternType::Table(table_type) => {
//                 let init = wasmi::Val::default(table_type.element());
//                 let minimum: u32 = table_type.minimum().try_into().unwrap();
//                 let maximum = if let Some(maximum) = table_type.maximum() {
//                     u32::try_from(maximum).unwrap()
//                 } else {
//                     minimum.saturating_add(ctx.data_mut().u.int_in_range(0u16..=1024)?.into())
//                 };
//
//                 let table = wasmi::Table::new(
//                     &mut ctx,
//                     wasmi::TableType::new(table_type.element(), minimum, Some(maximum)),
//                     init.clone(),
//                 )
//                 .unwrap();
//
//                 if 1 < maximum - minimum {
//                     let delta = ctx.data_mut().u.int_in_range(0u32..=(maximum - minimum))?;
//                     table.grow(&mut ctx, delta.into(), init).unwrap();
//                 }
//
//                 (
//                     ProvidedImportKind::Table(ImportedTable {
//                         length: table.size(&mut ctx).try_into().unwrap(),
//                         minimum,
//                         maximum,
//                         expected_type: table_type.element().into(),
//                     }),
//                     table.into(),
//                 )
//             }
//         };
//
//         provided_imports.push(ProvidedImport {
//             module: StringRef::intern_with_hint(
//                 &mut ctx.data_mut().pools.strings,
//                 import.module(),
//                 wasmi_collections::string_interner::InternHint::LikelyExists,
//             ),
//             name: StringRef::intern_with_hint(
//                 &mut ctx.data_mut().pools.strings,
//                 import.name(),
//                 wasmi_collections::string_interner::InternHint::LikelyNew,
//             ),
//             kind,
//         });
//         import_values.push(val);
//     }
//
//     debug_assert!(provided_imports.len() == import_values.len());
//
//     Ok(Imports {
//         ffi: provided_imports.into_boxed_slice(),
//         wasmi: import_values.into_boxed_slice(),
//     })
// }

impl Action {
    fn generate(
        store: &mut wasmi::Store<ExecutionState>,
        instance: &wasmi::Instance,
        hasher: crate::hash::Seed,
        wasmi_val_buf: &mut Vec<wasmi::Val>,
    ) -> arbitrary::Result<Self> {
        Ok(match store.data_mut().u.int_in_range(0u8..=9u8)? {
            0..=4 => {
                let func_name = {
                    let ExecutionState { u, funcs, .. } = store.data_mut();
                    *u.choose(funcs)?
                };

                let func = instance
                    .get_func(&store, func_name.to_str(&store.data().pools.strings))
                    .unwrap();

                let func_type = func.ty(&store);
                let param_count = usize::from(func_type.len_params());
                let param_and_result_count = param_count + usize::from(func_type.len_results());
                wasmi_val_buf.clear();
                wasmi_val_buf.reserve(param_and_result_count);

                let mut arguments = ArgumentList::new();
                arguments.grow_at(0, param_count, &mut store.data_mut().pools.argument_vals);
                for (i, ty) in func_type.params().iter().enumerate() {
                    let arg = ArgumentVal::arbitrary_of_type(
                        ValType::from(*ty),
                        wasmi::AsContextMut::as_context_mut(&mut *store),
                    )?;

                    wasmi_val_buf.push(
                        arg.to_wasmi(wasmi::AsContextMut::as_context_mut(&mut *store), instance),
                    );

                    *arguments
                        .get_mut(i, &mut store.data_mut().pools.argument_vals)
                        .unwrap() = arg;
                }

                wasmi_val_buf.resize(
                    param_and_result_count,
                    wasmi::Val::I32(0xAAAA_AAAAu32 as i32),
                );
                let (wasmi_args, wasmi_results) =
                    wasmi_val_buf.as_mut_slice().split_at_mut(param_count);

                let wasmi_result = func.call(
                    wasmi::AsContextMut::as_context_mut(&mut *store),
                    wasmi_args,
                    wasmi_results,
                );

                let results = match wasmi_result {
                    Ok(()) => {
                        let mut results = ResultList::new();
                        results.grow_at(
                            0,
                            usize::from(func_type.len_results()),
                            &mut store.data_mut().pools.result_vals,
                        );

                        for (i, val) in wasmi_val_buf.drain(param_count..).enumerate() {
                            let r =
                                ResultVal::from_wasmi(val, wasmi::AsContext::as_context(&*store));

                            *results
                                .get_mut(i, &mut store.data_mut().pools.result_vals)
                                .unwrap() = r;
                        }

                        InvokeResult::Values(results)
                    }
                    Err(err) => match err.kind() {
                        wasmi::errors::ErrorKind::TrapCode(code) => InvokeResult::Trap(
                            TrapCode::new(*code).ok_or(arbitrary::Error::NotEnoughData)?,
                        ),
                        bad => unreachable!("unexpected invoke error {bad:?}"),
                    },
                };

                Self::Invoke(store.data_mut().pools.invokes.push(Invoke {
                    name: func_name,
                    arguments,
                    results,
                }))
            }
            5..=6 => {
                let mem_name = {
                    let ExecutionState { u, mems, .. } = store.data_mut();
                    *u.choose(mems)?
                };

                let check = CheckMemoryContents::from_exported_memory(
                    wasmi::AsContext::as_context(&*store),
                    instance,
                    hasher,
                    mem_name,
                );

                Self::CheckMemoryContents(store.data_mut().pools.check_memory_contents.push(check))
            }
            7 => {
                let table_name = {
                    let ExecutionState { u, tables, .. } = store.data_mut();
                    *u.choose(tables)?
                };

                let table = instance
                    .get_table(&store, table_name.to_str(&store.data().pools.strings))
                    .unwrap();

                let table_size = table.size(wasmi::AsContext::as_context(&*store));
                if table_size == 0 {
                    return Err(arbitrary::Error::NotEnoughData);
                }

                let index =
                    u32::try_from(store.data_mut().u.int_in_range(0..=table_size - 1)?).unwrap();

                let elem = table
                    .get(wasmi::AsContext::as_context(&*store), index.into())
                    .unwrap();

                let check = CheckTableElement {
                    table: table_name,
                    index,
                    expected: ResultVal::from_wasmi(elem, wasmi::AsContext::as_context(&*store)),
                };

                Self::CheckTableElement(store.data_mut().pools.check_table_elements.push(check))
            }
            8 => {
                let global_name = {
                    let ExecutionState { u, globals, .. } = store.data_mut();
                    *u.choose(globals)?
                };

                let global = instance
                    .get_global(&store, global_name.to_str(&store.data().pools.strings))
                    .unwrap();

                let value = global.get(wasmi::AsContext::as_context(&*store));

                let check = CheckGlobalValue {
                    name: global_name,
                    expected: ResultVal::from_wasmi(value, wasmi::AsContext::as_context(&*store)),
                };

                Self::CheckGlobalValue(store.data_mut().pools.check_global_values.push(check))
            }
            _ => unreachable!(),
        })
    }
}

fn execute(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Option<Box<Execution>>> {
    use wasmi::errors::ErrorKind;

    let hasher: crate::hash::Seed = u.arbitrary()?;
    let wasm = FfiVec::new(arbitrary_module(u)?);

    let engine = {
        let mut config = wasmi::Config::default();
        config
            .wasm_mutable_global(true)
            .wasm_sign_extension(true)
            .wasm_saturating_float_to_int(true)
            .wasm_multi_value(true)
            .wasm_multi_memory(false)
            .wasm_bulk_memory(true)
            .wasm_reference_types(true)
            .wasm_tail_call(false)
            .wasm_extended_const(false)
            .wasm_memory64(false)
            .wasm_wide_arithmetic(false)
            .consume_fuel(true)
            .compilation_mode(wasmi::CompilationMode::Lazy);

        wasmi::Engine::new(&config)
    };

    let module = match wasmi::Module::new(&engine, &wasm) {
        Ok(module) => module,
        Err(error) => match error.kind() {
            ErrorKind::Limits(_) => return Ok(None),
            _ => unreachable!(
                "unexpected module instantiation error {:?}: {}",
                error.kind(),
                error,
            ),
        },
    };

    let mut store = wasmi::Store::new(
        &engine,
        ExecutionState {
            u,
            pools: Default::default(),
            funcs: Vec::new(),
            funcrefs: Vec::new(),
            globals: Vec::new(),
            tables: Vec::new(),
            mems: Vec::new(),
            // recorded_host_calls: Vec::new(),
        },
    );

    // store.limiter(|exec_state| todo!());

    // let imports = arbitrary_imports((&mut store).into(), &module)?;

    let instance = match wasmi::Instance::new(&mut store, &module, &[]) {
        Ok(instance) => instance,
        Err(err) => match err.kind() {
            ErrorKind::TrapCode(trap) => {
                let exec_state = store.into_data();
                return Ok(match TrapCode::new(*trap) {
                    Some(code) => Some(Box::new(Execution {
                        wasm,
                        // counts,
                        instantiation: ExecutionInstantiateResult::Trapped(code),
                        // provided_imports: ffi::OwnedSlice::new(imports.ffi),
                        // recorded_host_calls: FfiVec::new(exec_state.recorded_host_calls),
                        pools: exec_state.pools,
                    })),
                    None => None,
                });
            }
            _ => unreachable!(
                "unexpected error while calling start function {:?}: {}",
                err.kind(),
                err,
            ),
        },
    };

    // Can't use instance.exports() due to borrowing problems.
    let exports_len = instance.exports(&store).len();

    // Assume most exports are functions
    store.data_mut().funcs.reserve(exports_len / 2);
    store.data_mut().funcrefs.reserve(exports_len / 2);

    for export in module.exports() {
        let name = StringRef::intern(&mut store.data_mut().pools.strings, export.name());
        match instance.get_export(&store, export.name()).unwrap() {
            wasmi::Extern::Func(f) => {
                store.data_mut().funcs.push(name);
                store.data_mut().funcrefs.push(f);
            }
            wasmi::Extern::Global(_) => store.data_mut().globals.push(name),
            wasmi::Extern::Table(_) => store.data_mut().tables.push(name),
            wasmi::Extern::Memory(_) => {
                store.data_mut().mems.reserve_exact(1);
                store.data_mut().mems.push(name);
            }
        }
    }

    let has_memory = !store.data().mems.is_empty();

    let action_count = if exports_len == 0 {
        0
    } else {
        // Might be better to measure the average number of bytes per generated Action
        store.data_mut().u.arbitrary_len::<[u8; 32]>()?
    };

    let mut actions = Vec::<Action>::with_capacity(action_count + usize::from(has_memory));
    let mut wasmi_val_buf = Vec::<wasmi::Val>::new();

    // TODO: If arbitrary error occurs here, just end the loop early
    for _ in 0..action_count {
        actions.push(
            match Action::generate(&mut store, &instance, hasher, &mut wasmi_val_buf) {
                Ok(action) => action,
                Err(arbitrary::Error::NotEnoughData) => break,
                Err(err) => return Err(err),
            },
        );
    }

    // Always include a memory hash check if a memory is present
    if let Some(memory) = store.data().mems.first().copied() {
        store
            .data_mut()
            .pools
            .check_memory_contents
            .reserve_exact(1);

        let check = CheckMemoryContents::from_exported_memory(
            wasmi::AsContext::as_context(&store),
            &instance,
            hasher,
            memory,
        );

        actions.push(Action::CheckMemoryContents(
            store.data_mut().pools.check_memory_contents.push(check),
        ));
    }

    let exec_state = store.into_data();

    Ok(Some(Box::new(Execution {
        wasm,
        // counts: Counts {
        //     funcs: exec_state.funcs.len().try_into().unwrap(),
        //     ..counts
        // },
        instantiation: ExecutionInstantiateResult::Instantiated(FfiVec::new(actions)),
        // provided_imports: ffi::OwnedSlice::new(imports.ffi),
        // recorded_host_calls: FfiVec::new(exec_state.recorded_host_calls),
        pools: exec_state.pools,
    })))
}

/// # Safety
///
/// `input` must refer to a valid slice of bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasmstint_fuzz_differential_wasmi_execute(
    input: NonNull<FfiSlice<u8>>,
) -> Option<Box<Execution>> {
    let mut u = unsafe { ffi::FfiUnstructured::new(input) };
    execute(&mut u).ok().flatten()
}

/// # Safety
///
/// `execution` must be the only existing reference, and must be valid.
#[unsafe(no_mangle)]
pub extern "C" fn wasmstint_fuzz_differential_wasmi_deinit(execution: Box<Execution>) {
    _ = execution;
}
