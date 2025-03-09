use std::alloc::Layout;

pub struct ZigSmpAllocator {}

#[global_allocator]
static GLOBAL: ZigSmpAllocator = ZigSmpAllocator {};

#[derive(Clone, Copy)]
#[repr(transparent)]
struct AlignPow(u8);

impl AlignPow {
    fn from_layout(layout: Layout) -> Option<Self> {
        layout.align().trailing_zeros().try_into().ok().map(Self)
    }
}

unsafe extern "C" {
    fn wasmstint_fuzz_rust_heap_alloc(size: usize, align: AlignPow) -> *mut u8;

    fn wasmstint_fuzz_rust_heap_dealloc(ptr: *mut u8, size: usize, align: AlignPow);

    fn wasmstint_fuzz_rust_heap_realloc(
        ptr: *mut u8,
        old_size: usize,
        align: AlignPow,
        new_size: usize,
    ) -> *mut u8;
}

unsafe impl std::alloc::GlobalAlloc for ZigSmpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if let Some(align) = AlignPow::from_layout(layout) {
            // SAFETY: caller ensures non-zero size.
            unsafe { wasmstint_fuzz_rust_heap_alloc(layout.size(), align) }
        } else {
            std::ptr::null_mut()
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let align = AlignPow::from_layout(layout).unwrap();
        // SAFETY: caller ensures same allocation.
        unsafe {
            wasmstint_fuzz_rust_heap_dealloc(ptr, layout.size(), align);
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let align = AlignPow::from_layout(layout).unwrap();
        // SAFETY: ensured by caller.
        unsafe { wasmstint_fuzz_rust_heap_realloc(ptr, layout.size(), align, new_size) }
    }
}
