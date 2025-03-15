unsafe extern "C" {
    fn wasmstint_fuzz_rust_hash_bytes(
        seed: u64,
        bytes_ptr: std::ptr::NonNull<u8>,
        bytes_len: usize,
    ) -> u64;
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct Hash {
    value: u64,
}

impl Hash {
    pub(crate) fn new(seed: u64, bytes: &[u8]) -> Self {
        Self {
            value: unsafe {
                wasmstint_fuzz_rust_hash_bytes(
                    seed,
                    std::ptr::NonNull::from(bytes).cast(),
                    bytes.len(),
                )
            },
        }
    }
}
