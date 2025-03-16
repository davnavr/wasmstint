unsafe extern "C" {
    fn wasmstint_fuzz_rust_hash_bytes(
        seed: u64,
        bytes_ptr: std::ptr::NonNull<u8>,
        bytes_len: usize,
    ) -> u64;
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Hash {
    value: u64,
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Seed {
    seed: u64,
}

impl Seed {
    pub(crate) fn hash(self, bytes: &[u8]) -> Hash {
        Hash {
            value: unsafe {
                wasmstint_fuzz_rust_hash_bytes(
                    self.seed,
                    std::ptr::NonNull::from(bytes).cast(),
                    bytes.len(),
                )
            },
        }
    }
}

impl arbitrary::Arbitrary<'_> for Seed {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            seed: u.arbitrary()?,
        })
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        <u64 as arbitrary::Arbitrary>::size_hint(depth)
    }
}
