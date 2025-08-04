pub const MemInst = extern struct {
    base: [*]align(buffer_align) u8,
    // shared: bool,
    /// The current size, in bytes.
    size: usize,
    /// Indicates the amount that the memory's size, in bytes, can grow without reallocating.
    capacity: usize,
    /// The maximum size, in bytes.
    limit: usize,

    /// The amount memory buffers should be aligned by.
    ///
    /// Currently, this is enough to store aligned `v128` values.
    pub const buffer_align = 16;

    /// The size of a WebAssembly page, in bytes.
    pub const page_size = 65536;

    comptime {
        if (@import("builtin").cpu.arch.endian() != .little)
            @compileError("wasmstint is currently not supported on big-endian systems");
    }

    /// Returns a memory type matching the current memory instance.
    ///
    /// This does not use any original minimum limit as part of the memory type. For more information, see
    /// <https://webassembly.github.io/spec/core/appendix/properties.html#store-validity>.
    pub fn memType(inst: *const MemInst) @import("../Module.zig").MemType {
        return .{
            .limits = .{
                .min = inst.size / page_size,
                .max = inst.limit / page_size,
            },
        };
    }

    pub inline fn bytes(inst: *const MemInst) []align(buffer_align) u8 {
        return inst.base[0..inst.size];
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
        // std.debug.dumpHex(src_slice);
        const dst_slice = dst.bytes()[dst_idx..dst_end_idx];
        // std.debug.dumpHex(dst_slice);
        if (@intFromPtr(src) == @intFromPtr(dst) and (dst_idx < src_end_idx or src_idx < dst_end_idx)) {
            @memmove(dst_slice, src_slice);
        } else {
            @memcpy(dst_slice, src_slice);
        }

        // std.debug.dumpHex(dst_slice);
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
        const end_idx = std.math.add(usize, num, start_idx) catch
            return error.MemoryAccessOutOfBounds;

        if (end_idx > inst.size)
            return error.MemoryAccessOutOfBounds;

        @memset(inst.bytes()[start_idx..end_idx], val);
    }

    pub fn format(inst: *const MemInst, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("(module {f})", .{inst.memType()});
    }
};

const std = @import("std");
