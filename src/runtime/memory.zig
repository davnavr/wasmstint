pub const MemInst = extern struct {
    base: [*]align(buffer_align) u8,
    // shared: bool,
    /// The current size, in bytes.
    size: usize,
    /// Indicates the amount that the memory's size, in bytes, can grow without reallocating.
    ///
    /// It is an invariant that `base[size..capacity]` must always be filled with zeroes.
    capacity: usize,
    /// The maximum size, in bytes.
    limit: usize,
    vtable: *const VTable,

    /// The amount memory buffers should be aligned by.
    ///
    /// Currently, this is enough to store aligned `v128` values.
    pub const buffer_align = 16;

    /// The size of a WebAssembly page, in bytes.
    pub const page_size = 65536;

    comptime {
        if (builtin.cpu.arch.endian() != .little) {
            @compileError("wasmstint is not supported on big-endian systems");
        }
    }

    pub fn checkInvariants(mem: *const MemInst) void {
        std.debug.assert(mem.size <= mem.capacity);
        std.debug.assert(mem.size <= mem.limit);
        std.debug.assert(mem.size % page_size == 0);
        std.debug.assert(mem.capacity % page_size == 0);
        std.debug.assert(mem.limit % page_size == 0);
    }

    pub const VTable = struct {
        /// Implements the logic for performing a resize when there is no more capacity remaining.
        ///
        /// New memory after the old `mem.size` must be filled with zero bytes.
        ///
        /// After a successful resize, `mem.size == new_size`.
        grow: *const fn (
            mem: *MemInst,
            /// Must be a multiple of the `page_size`, `> mem.size`, `> mem.capacity` and
            /// `<= mem.limit`.
            new_size: usize,
        ) Oom!void,
        free: *const fn (*MemInst) void,
    };

    fn checkEndingZeroBytes(inst: *MemInst) void {
        if (builtin.mode == .Debug) {
            for (inst.allocated()[inst.size..], inst.size..inst.capacity) |*b, i| {
                if (b.* != 0) {
                    std.debug.panic(
                        "encountered non-zero byte 0x{X:0>2} at index {d} (0x{X})",
                        .{ b.*, i, @intFromPtr(b) },
                    );
                }
            }
        }
    }

    /// Asserts that `new_size` is a multiple of the `page_size`.
    pub fn grow(inst: *MemInst, new_size: usize) Oom!void {
        std.debug.assert(new_size % page_size == 0);
        inst.checkInvariants();
        if (inst.limit < new_size) {
            return Oom.OutOfMemory;
        } else if (new_size <= inst.size) {
            return;
        }

        if (new_size <= inst.capacity) {
            // Memory is already zeroed.
            inst.size = new_size;
        } else {
            try inst.vtable.grow(inst, new_size);
        }
        std.debug.assert(inst.size == new_size);
        std.debug.assert(new_size <= inst.capacity);
        inst.checkInvariants();
        inst.checkEndingZeroBytes();
    }

    pub fn free(inst: *MemInst) void {
        inst.checkInvariants();
        inst.checkEndingZeroBytes();
        inst.vtable.free(inst);
        inst.* = undefined;
    }

    pub const Mapped = @import("memory/mapped.zig").Mapped;

    /// A linear memory of size `0`, that cannot grow.
    pub const empty = MemInst{
        .base = &.{},
        .size = 0,
        .capacity = 0,
        .limit = 0,
        .vtable = &VTable{
            .grow = noGrow,
            .free = emptyFree,
        },
    };

    /// Does not check that the buffer is all zeroes.
    fn fromStaticBufferUnchecked(buffer: []align(buffer_align) u8, size: usize) MemInst {
        std.debug.assert(buffer.len % page_size == 0);
        std.debug.assert(size <= buffer.len);
        std.debug.assert(size % page_size == 0);
        return MemInst{
            .base = buffer.ptr,
            .size = size,
            .capacity = buffer.len,
            .limit = buffer.len,
            .vtable = &VTable{
                .grow = noGrow,
                .free = emptyFree,
            },
        };
    }

    /// Like `fromStaticBuffer()`, but instead only asserts that `buffer` contains only zero bytes.
    pub fn fromStaticBufferAssumeZeroed(
        buffer: []align(buffer_align) u8,
        size: usize,
    ) MemInst {
        const actual_buf = buffer[0..std.mem.alignBackward(usize, buffer.len, page_size)];
        const actual_size = std.mem.alignBackward(usize, size, page_size);
        std.debug.assert(actual_size <= actual_buf.len);
        if (@inComptime()) {
            comptime {
                for (actual_buf, 0..) |b, i| {
                    if (b != 0) {
                        @compileError(
                            std.fmt.comptimePrint(
                                "non-zero byte in linear memory buffer at index {d}",
                                .{i},
                            ),
                        );
                    }
                }
            }
        } else if (builtin.mode == .Debug) {
            for (actual_buf, 0..) |*b, i| {
                if (b.* != 0) {
                    std.debug.panic(
                        "buffer must be zeroed: non-zero byte 0x{X:0>2} at index {d} (0x{X})",
                        .{ b.*, i, @intFromPtr(b) },
                    );
                }
            }
        }

        return .fromStaticBufferUnchecked(actual_buf, actual_size);
    }

    /// Creates a `MemInst` from a static buffer, setting all bytes to zero.
    ///
    /// Rounds the buffer size down to the nearest multiple of the `page_size`.
    pub fn fromStaticBuffer(
        buffer: []align(buffer_align) u8,
        /// The initial size of the linear memory, rounded down to the nearest multiple of the page
        /// size.
        size: usize,
    ) MemInst {
        const actual_buf = buffer[0..std.mem.alignBackward(usize, buffer.len, page_size)];
        const actual_size = std.mem.alignBackward(usize, size, page_size);
        std.debug.assert(actual_size <= actual_buf.len);
        @memset(actual_buf, 0);
        return .fromStaticBufferUnchecked(actual_buf, actual_size);
    }

    pub fn noGrow(_: *MemInst, new_size: usize) Oom!void {
        _ = new_size;
        return error.OutOfMemory;
    }

    fn emptyFree(inst: *MemInst) void {
        std.debug.assert(inst.size == 0);
        std.debug.assert(inst.capacity == 0);
    }

    /// Returns a memory type matching the current memory instance.
    ///
    /// This does not use any original minimum limit as part of the memory type. For more information, see
    /// <https://webassembly.github.io/spec/core/appendix/properties.html#store-validity>.
    pub fn memType(inst: *const MemInst) @import("../Module.zig").MemType {
        inst.checkInvariants();
        return .{
            .limits = .{
                .min = @divExact(inst.size, page_size),
                .max = @divExact(inst.limit, page_size),
            },
        };
    }

    /// Gets a slice of the linear memory's allocation.
    ///
    /// The region within `inst.size..inst.capacity` must always be filled with zero bytes.
    ///
    /// This function is only intended to be used within the implementation of a `MemInst`.
    pub inline fn allocated(inst: *const MemInst) []align(buffer_align) u8 {
        inst.checkInvariants();
        return inst.base[0..inst.capacity];
    }

    /// Gets a slice of the contents of this linear memory.
    pub inline fn bytes(inst: *const MemInst) []align(buffer_align) u8 {
        return inst.allocated()[0..inst.size];
    }

    pub const OobError = error{MemoryAccessOutOfBounds};

    /// Implements the [`memory.init`] instruction, which is also used in module instantiation.
    ///
    /// Asserts that `src.len` can fit into a `u32`, which is always the case for WASM data segments.
    ///
    /// [`memory.init`]: https://webassembly.github.io/spec/core/exec/instructions.html#exec-memory-init
    pub fn init(
        inst: *const MemInst,
        src: []const u8,
        len: u32,
        src_idx: u32,
        dst_idx: u32,
    ) OobError!void {
        inst.checkInvariants();
        std.debug.assert(src.len <= std.math.maxInt(u32));

        // std.debug.print(
        //     "memory.init: memory len={}, segment len={}, len={}, src_idx={}, dst_idx={}\n",
        //     .{ inst.size, src.len, len, src_idx, dst_idx },
        // );

        const src_end_idx = std.math.add(usize, src_idx, len) catch
            return error.MemoryAccessOutOfBounds;

        if (src_end_idx > src.len)
            return error.MemoryAccessOutOfBounds;

        const dst_end_idx = std.math.add(usize, dst_idx, len) catch
            return error.MemoryAccessOutOfBounds;

        if (dst_end_idx > inst.size)
            return error.MemoryAccessOutOfBounds;

        @memcpy(inst.bytes()[dst_idx..dst_end_idx], src[src_idx..src_end_idx]);
    }

    /// Implements the [`memory.copy`] instruction.
    ///
    /// [`memory.copy`]: https://webassembly.github.io/spec/core/exec/instructions.html#exec-memory-copy
    pub fn copy(
        dst: *const MemInst,
        src: *const MemInst,
        len: u32,
        src_idx: u32,
        dst_idx: u32,
    ) OobError!void {
        dst.checkInvariants();
        src.checkInvariants();
        // std.debug.print(
        //     "memory.copy: src len={}, dst len={}, len={}, src_idx={}, dst_idx={}\n",
        //     .{ src.size, dst.size, len, src_idx, dst_idx },
        // );

        const src_end_idx = std.math.add(usize, src_idx, len) catch
            return error.MemoryAccessOutOfBounds;

        if (src_end_idx > src.size)
            return error.MemoryAccessOutOfBounds;

        const dst_end_idx = std.math.add(usize, dst_idx, len) catch
            return error.MemoryAccessOutOfBounds;

        if (dst_end_idx > dst.size)
            return error.MemoryAccessOutOfBounds;

        if (len == 0) return;

        const src_slice: []const u8 = src.bytes()[src_idx..src_end_idx];
        @memmove(dst.bytes()[dst_idx..dst_end_idx], src_slice);
    }

    /// Implements the [`memory.fill`] instruction.
    ///
    /// [`memory.fill`]: https://webassembly.github.io/spec/core/exec/instructions.html#exec-memory-fill
    pub fn fill(
        inst: *const MemInst,
        num: u32,
        val: u8,
        start_idx: u32,
    ) OobError!void {
        inst.checkInvariants();

        const end_idx = std.math.add(usize, num, start_idx) catch
            return error.MemoryAccessOutOfBounds;

        if (end_idx > inst.size)
            return error.MemoryAccessOutOfBounds;

        @memset(inst.bytes()[start_idx..end_idx], val);
    }

    pub fn format(inst: *const MemInst, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("(memory {f} (;@{X};))", .{ inst.memType(), @intFromPtr(inst.base) });
    }
};

const std = @import("std");
const builtin = @import("builtin");
const Oom = std.mem.Allocator.Error;
