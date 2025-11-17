#[repr(C)]
pub struct Execution {
    actions_ptr: std::ptr::NonNull<Action>,
    actions_len: u32,
    instantiation: Instantiation,
    // TODO: Record of host function calls and their parameters
}

#[repr(C)]
pub enum Action {
    HashMemory { memory: u16, hash: u64 },
    // Call { name: SomeStringType }
    // LoadGlobal { name: SomeStringType, type: SomeValTypeEnum, value: SomeValueUnion },
}

macro_rules! trap {
    {$($name:ident $($value:expr)?,)+} => {
        #[derive(Clone, Copy)]
        #[repr(u8)]
        pub enum Trap {
            $($name $(= $value)?,)+
        }

        #[derive(Clone, Copy)]
        #[repr(u8)]
        pub enum Instantiation {
            Success = 0,
            $($name $(= $value)?,)+
        }
    };
}

trap! {
    UnreachableCodeReached = 1,
    MemoryOutOfBounds,
    TableOutOfBounds,
    IndirectCallToNull,
    IntegerDivisionByZero,
    IntegerOverflow,
    BadConversionToInteger,
    StackOverflow,
    BadSignature,
    OutOfFuel,
    GrowthOperationLimited,
}
