//! Differential fuzz testing against [`wasmi`].

use std::ptr::NonNull;

#[repr(C)]
pub struct Execution {
    /// Only set when [`actions_ptr`] is not `None`.
    pub trap: Trap,
    pub func_export_count: u16,

    pub actions_len: u32,
    /// Set to [`None`] if a [`Trap`] occurred during module instantiation.
    ///
    /// If [`Some`], this contains [`actions_len`] entries.
    pub actions_ptr: *const Action,

    /// Contains [`func_export_count`] entries.
    pub func_export_arities: NonNull<FuncArities>,

    /// Contains [`func_import_count`] entries.
    pub func_import_arities: NonNull<FuncArities>,
    pub func_import_count: u32,

    pub global_import_count: u32,
    /// Contains [`global_import_count`] entries.
    pub global_import_values: NonNull<ArgumentVal>,

    pub host_calls_len: usize,
    /// Contains [`host_calls_len`] entries.
    pub host_calls_ptr: NonNull<HostCall>,

    pub memory_growths_len: usize,
    pub memory_growths_ptr: NonNull<Growth>,

    pub table_growths_len: usize,
    pub table_growths_ptr: NonNull<Growth>,

    pub arena: NonNull<bumpalo::Bump>,
}

// #[repr(C)]
// pub struct Name {
//     ptr: NonNull<u8>,
//     len: u32,
// }

/// Refers to linear memory exported from the module.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct MemoryId(u16);

/// Refers to a function exported from the module.
///
/// `0` refers to the first function exported from the module.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct FuncId(u16);

/// Refers to a host function passed as an import to the module.
///
/// `0` refers to the first function imported by the module.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct HostFuncId(u16);

#[derive(Clone, Copy)]
#[repr(C)]
pub struct FuncArities {
    pub param_count: u16,
    // Is there a word for arity, but for the results?
    pub result_count: u16,
}

impl FuncArities {
    fn from_wasmi_func_type(func_type: &wasmi::FuncType) -> Self {
        Self {
            param_count: u16::try_from(func_type.params().len()).unwrap(),
            result_count: u16::try_from(func_type.results().len()).unwrap(),
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C, u16)]
pub enum FuncRef {
    Null = 0,
    Ref(FuncId) = 1,
}

impl FuncRef {
    fn to_wasmi_func(self, func_imports: &[wasmi::Func]) -> wasmi::Ref<wasmi::Func> {
        match self {
            Self::Null => wasmi::Ref::Null,
            Self::Ref(id) => wasmi::Ref::Val(func_imports[usize::from(id.0)]),
        }
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct ExternRef(Option<std::num::NonZero<usize>>);

impl ExternRef {
    fn to_wasmi_ref(
        self,
        ctx: wasmi::StoreContextMut<'_, Context>,
    ) -> wasmi::Ref<wasmi::ExternRef> {
        match self.0 {
            Some(n) => wasmi::Ref::Val(wasmi::ExternRef::new(ctx, n)),
            None => wasmi::Ref::Null,
        }
    }

    fn from_wasmi_ref(
        extern_ref: &wasmi::Ref<wasmi::ExternRef>,
        ctx: wasmi::StoreContext<'_, Context>,
    ) -> Self {
        Self(match extern_ref {
            wasmi::Ref::Null => None,
            wasmi::Ref::Val(r) => Some(
                *r.data(ctx)
                    .downcast_ref::<std::num::NonZero<usize>>()
                    .unwrap(),
            ),
        })
    }
}

/// An action for the host to take.
#[repr(u16)]
pub enum Action {
    /// The number of arguments and results is implied by the [`FuncId`], by indexing into
    /// [`Execution.func_export_arities`].
    Call {
        func: FuncId,
        action: CallAction,
    } = 0,
    HashMemory {
        memory: MemoryId,
        hash: u64,
    } = 1,
    // No need for a `LoadGlobal` action, function calls could generate a `global.get`
    // No need for a `Memory/TableSize` action, `memory/table.size` could be generated
}

#[repr(C)]
pub struct CallAction {
    /// Only set when [`results_ptr`] is not null.
    trap: Trap,
    args_ptr: NonNull<ArgumentVal>,
    results_ptr: *const ResultVal,
}

#[derive(Clone, Copy)]
#[repr(C, u64)]
pub enum ArgumentVal {
    I32(i32) = 0,
    I64(i64) = 1,
    F32(f32) = 2,
    F64(f64) = 3,
    FuncRef(FuncRef) = 4,
    ExternRef(ExternRef) = 5,
}

impl ArgumentVal {
    fn generate(
        u: &mut arbitrary::Unstructured,
        func_imports: &[wasmi::Func],
        val_type: wasmi::ValType,
    ) -> arbitrary::Result<Self> {
        Ok(match val_type {
            wasmi::ValType::I32 => Self::I32(u.arbitrary::<i32>()?),
            wasmi::ValType::I64 => Self::I64(u.arbitrary::<i64>()?),
            wasmi::ValType::F32 => Self::F32(u.arbitrary::<f32>()?),
            wasmi::ValType::F64 => Self::F64(u.arbitrary::<f64>()?),
            wasmi::ValType::FuncRef => {
                let bound: u16 = u16::try_from(func_imports.len()).unwrap_or(u16::MAX);
                let chosen = u.int_in_range(0u32..=u32::from(bound) + 1)?;
                Self::FuncRef(match u16::try_from(chosen) {
                    Ok(i) if i < bound => FuncRef::Ref(FuncId(i)),
                    _ => FuncRef::Null,
                })
            }
            wasmi::ValType::ExternRef => {
                Self::ExternRef(ExternRef(std::num::NonZero::<usize>::new(u.arbitrary()?)))
            }
            _ => panic!("could not generate argument for {val_type:?}",),
        })
    }

    fn to_wasmi_val(self, ctx: wasmi::StoreContextMut<'_, Context>) -> wasmi::Val {
        match self {
            Self::I32(i) => wasmi::Val::I32(i),
            Self::I64(i) => wasmi::Val::I64(i),
            Self::F32(f) => wasmi::Val::F32(wasmi::F32::from_float(f)),
            Self::F64(f) => wasmi::Val::F64(wasmi::F64::from_float(f)),
            Self::FuncRef(f) => wasmi::Val::FuncRef(f.to_wasmi_func(ctx.data().func_imports)),
            Self::ExternRef(e) => wasmi::Val::ExternRef(e.to_wasmi_ref(ctx)),
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C, u32)]
pub enum ResultFuncRef {
    Null = 0,
    NonNull(FuncArities) = 1,
}

impl ResultFuncRef {
    fn from_wasmi_func(f: &wasmi::Ref<wasmi::Func>, ctx: wasmi::StoreContext<'_, Context>) -> Self {
        match f {
            wasmi::Ref::Null => Self::Null,
            wasmi::Ref::Val(f) => Self::NonNull(FuncArities::from_wasmi_func_type(&f.ty(ctx))),
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C, u64)]
pub enum ResultVal {
    I32(i32) = 0,
    I64(i64) = 1,
    F32(f32) = 2,
    F64(f64) = 3,
    FuncRef(ResultFuncRef) = 4,
    ExternRef(ExternRef) = 5,
}

impl ResultVal {
    fn from_wasmi_val(val: &wasmi::Val, ctx: wasmi::StoreContext<'_, Context>) -> Self {
        match val {
            wasmi::Val::I32(i) => Self::I32(*i),
            wasmi::Val::I64(i) => Self::I64(*i),
            wasmi::Val::F32(f) => Self::F32(f.to_float()),
            wasmi::Val::F64(f) => Self::F64(f.to_float()),
            wasmi::Val::FuncRef(f) => Self::FuncRef(ResultFuncRef::from_wasmi_func(f, ctx)),
            wasmi::Val::ExternRef(e) => Self::ExternRef(ExternRef::from_wasmi_ref(e, ctx)),
            _ => panic!("bad result {val:?}"),
        }
    }
}

#[repr(C)]
pub struct HostCall {
    func: HostFuncId,
    // TODO: Allow host to trap (requires wasmstint to implement it)
    ///// Only set when `arguments` is not null.
    //trap: Trap,
    arguments: NonNull<ResultVal>,
    results: NonNull<ArgumentVal>,
}

macro_rules! trap {
    {$($name:ident = $($value:expr)?,)+} => {
        /// Mostly equivalent to [`wasmi::TrapCode`].
        #[derive(Clone, Copy)]
        #[repr(u8)]
        pub enum Trap {
            $($name $(= $value)?,)+
            Invalid = 0xCC,
        }

        impl Trap {
            fn from_wasmi_trap(trap: wasmi::TrapCode) -> Self {
                match trap {
                    $(wasmi::TrapCode::$name => Self::$name,)+
                    wasmi::TrapCode::GrowthOperationLimited => unreachable!(),
                }
            }
        }
    };
}

trap! {
    UnreachableCodeReached = 0,
    MemoryOutOfBounds = 1,
    TableOutOfBounds = 2,
    IndirectCallToNull = 3,
    IntegerDivisionByZero = 4,
    IntegerOverflow = 5,
    BadConversionToInteger = 6,
    StackOverflow = 7,
    BadSignature = 8,
    OutOfFuel = 9,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Limits {
    pub max_memory_bytes: usize,
    pub max_table_elements: usize,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Growth {
    pub current: usize,
    pub desired: usize,
    pub allowed: bool,
}

struct Context<'a, 'rt, 'u, 'b> {
    u: &'u mut arbitrary::Unstructured<'b>,
    func_imports: &'rt [wasmi::Func],
    func_exports: &'rt [wasmi::Func],
    mem_exports: &'rt [wasmi::Memory],
    arena: &'a bumpalo::Bump,
    host_calls: Vec<HostCall>,
    memory_growths: Vec<Growth>,
    table_growths: Vec<Growth>,
    actions: bumpalo::collections::Vec<'rt, Action>,
    func_export_arities: &'a [FuncArities],
    func_import_arities: &'a [FuncArities],
    execution: &'a mut Execution,
    limits: Limits,
}

impl<'a> Context<'a, '_, '_, '_> {
    #[inline]
    fn arena(&self) -> &'a bumpalo::Bump {
        self.arena
    }

    fn record_execution_state(&mut self) {
        {
            let host_calls: &'a [HostCall] =
                self.arena.alloc_slice_fill_iter(self.host_calls.drain(..));
            self.execution.host_calls_len = host_calls.len();
            self.execution.host_calls_ptr = non_null_slice_to_ptr(NonNull::from(host_calls));
        }
        {
            let memory_growths: &'a [Growth] = self.arena.alloc_slice_copy(&self.memory_growths);
            self.execution.memory_growths_len = memory_growths.len();
            self.execution.memory_growths_ptr =
                non_null_slice_to_ptr(NonNull::from(memory_growths));
        }
        {
            let table_growths: &'a [Growth] = self.arena.alloc_slice_copy(&self.table_growths);
            self.execution.table_growths_len = table_growths.len();
            self.execution.table_growths_ptr = non_null_slice_to_ptr(NonNull::from(table_growths));
        }
    }

    fn trap(mut self, trap: Trap) -> &'a mut Execution {
        self.execution.trap = trap;
        self.record_execution_state();
        self.execution
    }
}

impl Growth {
    fn from_request(
        current: usize,
        desired: usize,
        maximum: Option<usize>,
        bound: usize,
        allow: bool,
    ) -> Self {
        let maximum = maximum.unwrap_or(bound).min(bound);
        Self {
            current,
            desired,
            allowed: (desired > maximum) && allow,
        }
    }
}

impl wasmi::ResourceLimiter for Context<'_, '_, '_, '_> {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, wasmi_core::LimiterError> {
        let grow = Growth::from_request(
            current,
            desired,
            maximum,
            self.limits.max_memory_bytes,
            self.u.arbitrary::<bool>().unwrap_or(false),
        );
        self.memory_growths.push(grow);
        Ok(grow.allowed)
    }

    fn memory_grow_failed(&mut self, _error: &wasmi_core::LimiterError) {
        let len = self.memory_growths.len();
        self.memory_growths[len - 1].allowed = false;
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, wasmi_core::LimiterError> {
        let grow = Growth::from_request(
            current,
            desired,
            maximum,
            self.limits.max_table_elements,
            self.u.arbitrary::<bool>().unwrap_or(false),
        );
        self.table_growths.push(grow);
        Ok(grow.allowed)
    }

    fn table_grow_failed(&mut self, _error: &wasmi_core::LimiterError) {
        let len = self.table_growths.len();
        self.table_growths[len - 1].allowed = false;
    }

    fn instances(&self) -> usize {
        1
    }

    fn memories(&self) -> usize {
        100
    }

    fn tables(&self) -> usize {
        100
    }
}

pub type HasherCallback = unsafe extern "C" fn(data_ptr: NonNull<u8>, data_len: usize) -> u64;

fn create_global_import<'a>(
    store: &mut wasmi::Store<Context<'a, '_, '_, '_>>,
    global_type: &wasmi::GlobalType,
    global_import_values: &mut bumpalo::collections::Vec<'a, ArgumentVal>,
) -> arbitrary::Result<wasmi::Global> {
    let func_imports = store.data().func_imports;
    let arg = ArgumentVal::generate(store.data_mut().u, func_imports, global_type.content())?;
    let global_value = arg.to_wasmi_val(wasmi::AsContextMut::as_context_mut(store));
    let global = wasmi::Global::new(store, global_value, global_type.mutability());
    global_import_values.push(arg);
    Ok(global)
}

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
struct HostError<T>(T);

impl<T: std::fmt::Display> std::fmt::Display for HostError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <T as std::fmt::Display>::fmt(&self.0, f)
    }
}

impl<T> wasmi::errors::HostError for HostError<T> where
    T: 'static
        + std::fmt::Display
        + std::fmt::Debug
        + std::any::Any
        + std::marker::Send
        + std::marker::Sync
{
}

fn create_func_import<'a>(
    store: &mut wasmi::Store<Context<'a, '_, '_, '_>>,
    num: usize,
    func_type: wasmi::FuncType,
) -> wasmi::Func {
    let id = HostFuncId(u16::try_from(num).unwrap());
    wasmi::Func::new(store, func_type, move |mut caller, args, results| {
        let host_args = {
            let mut host_args = bumpalo::collections::Vec::<'_, ResultVal>::with_capacity_in(
                args.len(),
                caller.data().arena(),
            );
            for a in args {
                host_args.push(ResultVal::from_wasmi_val(
                    a,
                    wasmi::AsContext::as_context(&caller),
                ));
            }

            NonNull::from(host_args.into_bump_slice())
        };

        let host_results = {
            let host_results = caller
                .data()
                .arena()
                .alloc_slice_fill_copy(results.len(), ArgumentVal::I32(0));

            for (r, val) in results.iter_mut().zip(host_results.iter_mut()) {
                let ctx = caller.data_mut();
                *val = ArgumentVal::generate(ctx.u, ctx.func_imports, r.ty())
                    .map_err(|e| wasmi::Error::host(HostError(e)))?;
                *r = val.to_wasmi_val(wasmi::AsContextMut::as_context_mut(&mut caller));
            }

            NonNull::from(host_results)
        };

        caller.data_mut().host_calls.push(HostCall {
            func: id,
            arguments: host_args.cast::<ResultVal>(),
            results: host_results.cast::<ArgumentVal>(),
        });
        Ok(())
    })
}

/// Waiting on [`NonNull::<T>::as_non_null_ptr()`] to be stable.
fn non_null_slice_to_ptr<T>(slice: NonNull<[T]>) -> NonNull<T> {
    slice.cast()
}

fn instantiate_wasmi_module<'a, 'rt>(
    store: &mut wasmi::Store<Context<'a, 'rt, '_, '_>>,
    alloca: &'rt bumpalo::Bump,
    module: &wasmi::Module,
    scratch: &mut bumpalo::Bump,
) -> arbitrary::Result<Result<wasmi::Instance, wasmi::Error>> {
    scratch.reset();
    let imports_iter = module.imports();
    let mut provided_imports = bumpalo::collections::Vec::<'_, wasmi::Extern>::with_capacity_in(
        imports_iter.len(),
        scratch,
    );
    let mut func_imports = bumpalo::collections::Vec::<'rt, wasmi::Func>::with_capacity_in(
        imports_iter.len() / 2,
        alloca,
    );
    let mut func_import_arities = bumpalo::collections::Vec::<'a, FuncArities>::with_capacity_in(
        func_imports.capacity(),
        store.data().arena(),
    );
    let mut global_import_values =
        bumpalo::collections::Vec::<'a, ArgumentVal>::new_in(store.data().arena());

    let max_memory_bytes = u32::try_from(store.data().limits.max_memory_bytes).unwrap();
    let max_table_elems = u32::try_from(store.data().limits.max_table_elements).unwrap();
    for import in imports_iter {
        provided_imports.push(match import.ty() {
            wasmi::ExternType::Global(global_type) => wasmi::Extern::Global(create_global_import(
                store,
                global_type,
                &mut global_import_values,
            )?),
            wasmi::ExternType::Func(func_type) => {
                let func = create_func_import(store, func_imports.len(), func_type.clone());
                func_import_arities.push(FuncArities::from_wasmi_func_type(func_type));
                func_imports.push(func);
                wasmi::Extern::Func(func)
            }
            wasmi::ExternType::Memory(mem_type) => {
                if mem_type.minimum() > u64::from(max_memory_bytes) {
                    return Err(arbitrary::Error::IncorrectFormat);
                }

                wasmi::Extern::Memory(
                    match wasmi::Memory::new(
                        &mut *store,
                        wasmi::MemoryType::new(
                            mem_type.minimum().try_into().unwrap(),
                            Some(
                                mem_type
                                    .maximum()
                                    .unwrap_or(max_memory_bytes.into())
                                    .min(max_memory_bytes.into())
                                    .try_into()
                                    .unwrap(),
                            ),
                        ),
                    ) {
                        Ok(memory) => memory,
                        Err(err) => return Ok(Err(err)),
                    },
                )
            }
            wasmi::ExternType::Table(table_type) => {
                if table_type.minimum() > u64::from(max_table_elems) {
                    return Err(arbitrary::Error::IncorrectFormat);
                }

                let table_type = wasmi::TableType::new(
                    table_type.element(),
                    table_type.minimum().try_into().unwrap(),
                    Some(
                        table_type
                            .maximum()
                            .unwrap_or(max_table_elems.into())
                            .min(max_table_elems.into())
                            .try_into()
                            .unwrap(),
                    ),
                );

                let init_elem = wasmi::Val::default(table_type.element());

                wasmi::Extern::Table(
                    match wasmi::Table::new(&mut *store, table_type, init_elem) {
                        Ok(table) => table,
                        Err(err) => return Ok(Err(err)),
                    },
                )
            }
        });
    }

    let ctx = store.data_mut();

    ctx.func_imports = func_imports.into_bump_slice();
    let func_import_arities = func_import_arities.into_bump_slice();
    ctx.execution.func_import_count = u32::try_from(func_import_arities.len()).unwrap();
    ctx.execution.func_import_arities = non_null_slice_to_ptr(NonNull::from(func_import_arities));
    ctx.func_import_arities = func_import_arities;

    let global_import_values = global_import_values.into_bump_slice();
    ctx.execution.global_import_count = u32::try_from(global_import_values.len()).unwrap();
    ctx.execution.global_import_values = non_null_slice_to_ptr(NonNull::from(global_import_values));

    Ok(wasmi::Instance::new(store, module, &provided_imports))
}

fn perform_host_action<'a>(
    store: &mut wasmi::Store<Context<'a, '_, '_, '_>>,
    hasher: HasherCallback,
    scratch: &mut bumpalo::Bump,
) -> arbitrary::Result<()> {
    scratch.reset();
    let action = if store.data_mut().u.ratio(7, 8)? {
        // Mostly generate calls to exported functions
        let max_func_id = u16::try_from(store.data().func_exports.len()).unwrap();
        if max_func_id == 0 {
            return Err(arbitrary::Error::EmptyChoose);
        }
        let id = FuncId(store.data_mut().u.int_in_range(0u16..=max_func_id - 1)?);
        let func: wasmi::Func = store.data().func_exports[usize::from(id.0)];
        let func_type = func.ty(&*store);
        let param_count = u16::try_from(func_type.params().len()).unwrap();
        let mut generated_args = bumpalo::collections::Vec::<'a, ArgumentVal>::with_capacity_in(
            param_count.into(),
            store.data().arena(),
        );

        let result_count = u16::try_from(func_type.results().len()).unwrap();
        let vals_buf = scratch.alloc_slice_fill_clone(
            usize::from(param_count) + usize::from(result_count),
            &wasmi::Val::I32(0),
        );
        let (args_buf, results_buf) = vals_buf.split_at_mut(usize::from(param_count));
        for (arg_dst, arg_type) in args_buf.iter_mut().zip(func_type.params()) {
            let ctx = store.data_mut();
            let generated = ArgumentVal::generate(ctx.u, ctx.func_imports, *arg_type)?;
            *arg_dst = generated.to_wasmi_val(wasmi::AsContextMut::as_context_mut(&mut *store));
            generated_args.push(generated);
        }

        let generated_args = generated_args.into_bump_slice();
        let args_ptr = non_null_slice_to_ptr(NonNull::from(generated_args));
        Action::Call {
            func: id,
            action: match func.call(&mut *store, args_buf, results_buf) {
                Ok(()) => {
                    let converted_results: &'a [ResultVal] = store
                        .data()
                        .arena
                        .alloc_slice_fill_iter(results_buf.iter().map(|result| {
                            ResultVal::from_wasmi_val(result, wasmi::AsContext::as_context(store))
                        }));

                    CallAction {
                        trap: Trap::Invalid,
                        args_ptr,
                        results_ptr: converted_results.as_ptr(),
                    }
                }
                Err(e) => match e.kind() {
                    wasmi::errors::ErrorKind::TrapCode(trap) => CallAction {
                        trap: Trap::from_wasmi_trap(*trap),
                        args_ptr,
                        results_ptr: std::ptr::null(),
                    },
                    wasmi::errors::ErrorKind::Host(e) => {
                        return Err(e.downcast_ref::<HostError<arbitrary::Error>>().unwrap().0);
                    }
                    _ => panic!("unexpected error during call action: {e}"),
                },
            },
        }
    } else {
        let max_mem_id = u16::try_from(store.data().mem_exports.len()).unwrap();
        if max_mem_id == 0 {
            return Err(arbitrary::Error::EmptyChoose);
        }
        let id = MemoryId(store.data_mut().u.int_in_range(0u16..=max_mem_id - 1)?);
        let mem: wasmi::Memory = store.data().mem_exports[usize::from(id.0)];
        let bytes = mem.data(&*store);
        let hash = unsafe { hasher(non_null_slice_to_ptr(NonNull::from(bytes)), bytes.len()) };
        Action::HashMemory { memory: id, hash }
    };

    store.data_mut().actions.push(action);
    Ok(())
}

fn collect_exports<'a, 'rt>(
    store: &mut wasmi::Store<Context<'a, 'rt, '_, '_>>,
    alloca: &'rt bumpalo::Bump,
    inst: &wasmi::Instance,
    scratch: &mut bumpalo::Bump,
) {
    scratch.reset();
    // `wasmi` does not specify a consistent ordering for exports, so both the Zig and Rust
    // sides must sort the names lexicographically.
    let mut sorted_exports =
        bumpalo::collections::Vec::from_iter_in(inst.exports(&*store), scratch);
    // No stable sort needed, WASM spec ensures all exports have unique names.
    sorted_exports.sort_unstable_by_key(|val| val.name());

    let mut func_exports = bumpalo::collections::Vec::<'rt, wasmi::Func>::new_in(alloca);
    let mut func_export_arities =
        bumpalo::collections::Vec::<'a, FuncArities>::new_in(store.data().arena());
    let mut mem_exports = bumpalo::collections::Vec::<'rt, wasmi::Memory>::new_in(alloca);

    for val in sorted_exports.drain(..) {
        match val.into_extern() {
            wasmi::Extern::Func(func) => {
                let pushed = FuncArities::from_wasmi_func_type(&func.ty(&*store));
                func_export_arities.push(pushed);
                func_exports.push(func);
            }
            wasmi::Extern::Memory(mem) => mem_exports.push(mem),
            _ => continue,
        }
    }
    std::mem::drop(sorted_exports);

    let func_export_arities: &'a [FuncArities] = store
        .data()
        .arena()
        .alloc_slice_copy::<FuncArities>(func_export_arities.into_bump_slice());
    let ctx = store.data_mut();
    ctx.execution.func_export_count = u16::try_from(func_export_arities.len()).unwrap();
    ctx.execution.func_export_arities = non_null_slice_to_ptr(NonNull::from(func_export_arities));
    ctx.func_exports = func_exports.into_bump_slice();
    ctx.func_export_arities = func_export_arities;
    ctx.mem_exports = mem_exports.into_bump_slice();
}

unsafe fn execute(
    wasm_bytes: &[u8],
    u: &mut arbitrary::Unstructured,
    fuel: u64,
    hasher: HasherCallback,
    limits: Limits,
) -> arbitrary::Result<NonNull<Execution>> {
    // Just use a normal box, since a `Bump` can't be allocated in itself.
    let arena = Box::new(bumpalo::Bump::new());
    let execution = arena.alloc(Execution {
        trap: Trap::Invalid,
        actions_len: 0,
        actions_ptr: std::ptr::null(),

        func_export_count: 0,
        func_export_arities: NonNull::<FuncArities>::dangling(),

        global_import_values: NonNull::<ArgumentVal>::dangling(),
        global_import_count: 0,

        func_import_count: 0,
        func_import_arities: NonNull::<FuncArities>::dangling(),

        host_calls_len: 0,
        host_calls_ptr: NonNull::<HostCall>::dangling(),

        memory_growths_len: 0,
        memory_growths_ptr: NonNull::<Growth>::dangling(),

        table_growths_len: 0,
        table_growths_ptr: NonNull::<Growth>::dangling(),

        arena: NonNull::from(&*arena),
    });

    let engine = wasmi::Engine::new(&{
        let mut config = wasmi::Config::default();
        // Should match the features supported by `wasmstint`.
        config.wasm_multi_memory(false);
        config.wasm_tail_call(true);
        config.wasm_extended_const(true);
        //config.wasm_simd(false); // enabled by feature flag in `wasmi`
        //config.wasm_relaxed_simd(false);
        config.consume_fuel(true);
        config
    });
    let module = wasmi::Module::new(&engine, wasm_bytes).unwrap();
    let execution = 'exec: {
        let alloca = bumpalo::Bump::new(); // allocations that last for this whole function call
        let mut scratch = bumpalo::Bump::new();
        let mut store = wasmi::Store::new(
            &engine,
            Context {
                u,
                host_calls: Vec::<HostCall>::new(),
                actions: bumpalo::collections::Vec::<'_, Action>::new_in(&alloca),
                arena: &arena,
                func_imports: &[],
                func_import_arities: &[],
                func_exports: &[],
                func_export_arities: &[],
                mem_exports: &[],
                memory_growths: Vec::new(),
                table_growths: Vec::new(),
                execution,
                limits,
            },
        );
        store.set_fuel(fuel).unwrap();
        store.limiter(|a| a);

        let inst = match instantiate_wasmi_module(&mut store, &alloca, &module, &mut scratch)? {
            Ok(init) => init,
            Err(e) => {
                use wasmi::errors::{ErrorKind, InstantiationError, MemoryError, TableError};
                match e.kind() {
                    ErrorKind::TrapCode(trap) => {
                        break 'exec store.into_data().trap(Trap::from_wasmi_trap(*trap));
                    }
                    ErrorKind::Instantiation(InstantiationError::ElementSegmentDoesNotFit {
                        ..
                    })
                    | ErrorKind::Table(
                        TableError::InitOutOfBounds
                        | TableError::FillOutOfBounds
                        | TableError::SetOutOfBounds
                        | TableError::CopyOutOfBounds,
                    ) => {
                        break 'exec store.into_data().trap(Trap::TableOutOfBounds);
                    }
                    ErrorKind::Memory(MemoryError::OutOfBoundsAccess) => {
                        break 'exec store.into_data().trap(Trap::MemoryOutOfBounds);
                    }
                    ErrorKind::Host(e) => {
                        return Err(e.downcast_ref::<HostError<arbitrary::Error>>().unwrap().0);
                    }
                    ErrorKind::Table(TableError::ResourceLimiterDeniedAllocation)
                    | ErrorKind::Memory(MemoryError::ResourceLimiterDeniedAllocation)
                    | ErrorKind::Instantiation(
                        InstantiationError::FailedToInstantiateMemory(
                            MemoryError::ResourceLimiterDeniedAllocation,
                        )
                        | InstantiationError::FailedToInstantiateTable(
                            TableError::ResourceLimiterDeniedAllocation,
                        ),
                    ) => {
                        // make fuzz target reject this input
                        return Err(arbitrary::Error::IncorrectFormat);
                    }
                    unexpected => panic!("unexpected error during instantation: {unexpected:?}"),
                }
            }
        };

        collect_exports(&mut store, &alloca, &inst, &mut scratch);

        while store.data_mut().u.arbitrary::<bool>() == Ok(true) {
            match perform_host_action(&mut store, hasher, &mut scratch) {
                Ok(()) | Err(arbitrary::Error::EmptyChoose) => {}
                Err(arbitrary::Error::NotEnoughData | arbitrary::Error::IncorrectFormat | _) => {
                    break;
                }
            };
        }

        {
            let ctx = store.data_mut();

            ctx.record_execution_state();

            let actions: &[Action] = ctx.arena.alloc_slice_fill_iter(ctx.actions.drain(..));
            ctx.execution.actions_len = u32::try_from(actions.len()).unwrap();
            ctx.execution.actions_ptr = actions.as_ptr();
        }

        store.into_data().execution
    };

    let execution = NonNull::<Execution>::from(execution);
    Box::leak(arena);
    Ok(execution)
}

#[unsafe(no_mangle)]
pub extern "C" fn wasmstint_fuzz_wasmi_diff(
    input: &mut crate::InputSlice,
    wasm_ptr: NonNull<u8>,
    wasm_len: usize,
    fuel: u64,
    out: &mut std::mem::MaybeUninit<NonNull<Execution>>,
    hasher: HasherCallback,
    limits: &Limits,
) -> bool {
    let mut input = crate::Input {
        u: arbitrary::Unstructured::new(unsafe {
            NonNull::<[u8]>::slice_from_raw_parts(input.ptr, input.len).as_mut()
        }),
        ffi: input,
    };

    let wasm_bytes = NonNull::<[u8]>::slice_from_raw_parts(wasm_ptr, wasm_len);
    let wasm_bytes: &[u8] = unsafe { wasm_bytes.as_ref() };

    match unsafe { execute(wasm_bytes, &mut input.u, fuel, hasher, *limits) } {
        Ok(exec) => {
            out.write(exec);
            true
        }
        Err(err) => match err {
            arbitrary::Error::NotEnoughData | arbitrary::Error::IncorrectFormat => false,
            arbitrary::Error::EmptyChoose | _ => unreachable!(),
        },
    }
}

/// # Safety
///
/// `execution` has not been freed yet, and is a valid mutable reference.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasmstint_fuzz_wasmi_free(mut execution: NonNull<Execution>) {
    let bump = {
        let execution = unsafe { execution.as_mut() };
        unsafe { Box::from_raw(execution.arena.as_ptr()) }
    };
    std::mem::drop(bump);
}
