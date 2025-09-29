//! Implementation of the legacy [WebAssembly System Interface preview 1] APIs.
//!
//! "Documentation" for these APIs is sparse and sometimes contradictory due to the fact that
//! `wasi_snapshot_preview1` was a prototype.
//!
//! - [`wasi_snapshot_preview1.witx`](https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/witx/wasi_snapshot_preview1.witx)
//! - [`wasi` Rust bindings](https://docs.rs/wasi/0.11.1+wasi-snapshot-preview1/wasi/)
//! - [WASIX](https://wasix.org/docs/api-reference#wasi-functions)
//!
//! Some comments are copied directly from the WASI documentation ([`preview1/docs.md`]).
//!
//! [WebAssembly System Interface preview 1]: https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/README.md
//! [`preview1/docs.md`]: https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md

const types = @import("WasiPreview1/types.zig");
const Errno = @import("WasiPreview1/errno.zig").Errno;
const Fd = @import("WasiPreview1/fd.zig").Fd;

/// A region of memory for scatter/gather **reads**.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#iovec
const Iovec = extern struct {
    /// The address of the buffer to be filled.
    buf: pointer.Pointer(u8),
    /// The length of the buffer to be filled.
    buf_len: types.Size,
};

/// A region of memory for scatter/gather **writes**.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#ciovec
const Ciovec = extern struct {
    /// The address of the buffer to be written.
    buf: pointer.ConstPointer(u8),
    /// The length of the buffer to be written.
    buf_len: types.Size,

    fn bytes(ciovec: Ciovec, mem: *const MemInst) pointer.OobError![]const u8 {
        return pointer.accessSlice(mem, ciovec.buf.addr, ciovec.buf_len);
    }
};

// TODO: Add more WASI API types

const File = @import("WasiPreview1/File.zig");

const Api = @import("WasiPreview1/api.zig").Api;

pub const Csprng = @import("WasiPreview1/Csprng.zig");

allocator: Allocator,
scratch: struct {
    state: ArenaAllocator.State,
    lock: std.debug.SafetyLock = .{},
},
api_lookup: Api.Lookup,
csprng: Csprng,
fd_table: Fd.Table,

const WasiPreview1 = @This();

pub fn function(state: *WasiPreview1, api: Api) wasmstint.runtime.FuncAddr {
    return .init(.{
        .host = .{
            .func = @constCast(api.hostFunc()),
            .data = @ptrCast(state),
        },
    });
}

pub const Char = @import("WasiPreview1/char.zig").Char;
pub const Arguments = @import("WasiPreview1/Arguments.zig");

/// Environment variable data to pass to the application.
pub const Environ = struct {
    ptr: [*]const Pair,
    count: u32,
    /// Total size, in bytes, of all argument data.
    ///
    /// TODO: Probably includes null-terminators too.
    size: u32,

    pub const empty = Environ{
        .ptr = @as([]const Pair, &.{}).ptr,
        .count = 0,
        .size = 0,
    };

    pub const Pair = struct {
        /// Invariant that this contains at least one (1) equals (`=`) character.
        ///
        /// `Char` guarantees no null-terminators are present.
        ptr: [*]const Char,
        /// Invariant that `len <= max_len`
        len: u32,
        /// Invariant that `ptr[key_len] == '='` and `key_len < len`.
        key_len: u32,

        const max_len = std.math.maxInt(u32) - 1; // only need room for null-terminator

        fn chars(pair: Pair) []const Char {
            std.debug.assert(pair.len <= max_len);
            std.debug.assert(pair.key_len < pair.len);
            std.debug.assert(pair.ptr[pair.key_len] == .@"=");
            return @ptrCast(pair.ptr[0..pair.len]);
        }

        fn bytes(pair: Pair) []const u8 {
            return @ptrCast(pair.chars());
        }

        /// Names are not allowed to contain an equals sign (`=`) character or a null-terminator
        /// (`\x00`).
        pub fn name(pair: Pair) [:'=']const u8 {
            return pair.bytes[0..pair.key_len :'='];
        }

        pub fn format(pair: Pair, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            return writer.writeAll(pair.bytes());
        }
    };
};

pub const InitError = Allocator.Error;

pub const InitOptions = struct {
    arguments: Arguments, // no default value since applications expect at least an application name
    environ: Environ = .empty,
    //stdout: ?union(enum) { null, real, some_memory_thing },
    //stderr: ?,
    //stdin: ?,
    fd_rng_seed: u64,
    csprng: Csprng = .os,
};

/// After initialization, hosts should call the entry point of the application (e.g. `_start`) as
/// per [the application ABI].
///
/// [the application ABI]: https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/application-abi.md
pub fn init(allocator: Allocator, options: InitOptions) InitError!WasiPreview1 {
    var rng = std.Random.SplitMix64.init(options.fd_rng_seed);
    var fd_table = try Fd.Table.init(
        allocator,
        .{ rng.next(), rng.next() },
        File.os.wrapStandardStreams(),
    );
    errdefer fd_table.deinit(allocator);

    var api_lookup = try Api.Lookup.init(allocator, rng.next());
    errdefer api_lookup.deinit(allocator);

    errdefer comptime unreachable;
    return .{
        .fd_table = fd_table,
        .api_lookup = api_lookup,
        .allocator = allocator,
        .scratch = .{ .state = ArenaAllocator.init(allocator).state },
        .csprng = options.csprng,
    };
}

pub const module_name: Module.Name = .init("wasi_snapshot_preview1");

fn resolveImport(
    ctx: *anyopaque,
    module: Module.Name,
    name: Module.Name,
    desc: wasmstint.runtime.ImportProvider.Desc,
) ?wasmstint.runtime.ExternVal {
    _ = desc;
    const state: *WasiPreview1 = @ptrCast(@alignCast(ctx));
    return if (std.mem.eql(u8, module_name.bytes(), module.bytes())) .{
        .func = state.function(state.api_lookup.get(name) orelse return null),
    } else null;
}

pub fn importProvider(state: *WasiPreview1) wasmstint.runtime.ImportProvider {
    return .{
        .ctx = @ptrCast(state),
        .resolve = resolveImport,
    };
}

fn acquireScratch(state: *WasiPreview1) ArenaAllocator {
    state.scratch.lock.lock();
    return state.scratch.state.promote(state.allocator);
}

fn releaseScratch(state: *WasiPreview1, arena: ArenaAllocator) void {
    var scratch = arena;
    _ = scratch.reset(.retain_capacity);
    state.scratch.state = scratch.state;
    state.scratch.lock.unlock();
}

// Note handlers here can just use `Errno.fault` for OOB memory accesses, which is nice since
// `AwaitingHost` doesn't support trapping yet.

const Ciovs = struct {
    list: []const File.Ciovec,
    total_len: u32,

    fn init(
        mem: *MemInst,
        ptr: pointer.ConstPointer(Ciovec),
        len: u32,
        scratch: *ArenaAllocator,
    ) !Ciovs {
        const iovs = try pointer.ConstSlice(Ciovec).init(mem, ptr, len);
        var list = try std.ArrayListUnmanaged(File.Ciovec).initCapacity(
            scratch.allocator(),
            iovs.items.len,
        );
        var total_len: u32 = 0;
        for (0..iovs.items.len) |i| {
            if (i > 0) {
                @branchHint(.cold);
            }

            const ciovec = try iovs.read(i).bytes(mem);
            const ciovec_len = std.math.cast(u32, ciovec.len) orelse break;
            total_len = std.math.add(u32, total_len, ciovec_len) catch |e| switch (e) {
                error.Overflow => return error.InvalidArgument,
            };
            list.appendAssumeCapacity(File.Ciovec.init(ciovec));
        }

        return .{ .list = list.items, .total_len = total_len };
    }
};

fn fd_pwrite(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_iovs: i32,
    raw_iovs_len: i32,
    raw_offset: i64,
    raw_ret: i32,
) Errno {
    const iovs_ptr = pointer.ConstPointer(Ciovec){ .addr = @bitCast(raw_iovs) };
    const ret_ptr = pointer.Pointer(u32){ .addr = @as(u32, @bitCast(raw_ret)) };
    const offset = types.FileSize{ .bytes = @bitCast(raw_offset) };

    std.log.debug(
        "fd_pwrite({}, {f}, {}, {}, {f})\n",
        .{
            @as(u32, @bitCast(raw_fd)),
            iovs_ptr,
            @as(u32, @bitCast(raw_iovs_len)),
            offset.bytes,
            ret_ptr,
        },
    );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    var scratch = wasi.acquireScratch();
    defer wasi.releaseScratch(scratch);

    const ciovs = Ciovs.init(mem, iovs_ptr, @bitCast(raw_iovs_len), &scratch) catch |e|
        return .mapError(e);
    const ret_bytes = ret_ptr.bytes(mem) catch |e| return .mapError(e);

    const ret = file.fd_pwrite(ciovs.list, offset, ciovs.total_len) catch |e| return .mapError(e);
    pointer.writeFromBytes(u32, ret_bytes, ret);
    return .success;
}

fn fd_write(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_iovs: i32,
    raw_iovs_len: i32,
    raw_ret: i32,
) Errno {
    const iovs_ptr = pointer.ConstPointer(Ciovec){ .addr = @bitCast(raw_iovs) };
    const ret_ptr = pointer.Pointer(u32){ .addr = @as(u32, @bitCast(raw_ret)) };

    std.log.debug(
        "fd_write({}, {f}, {}, {f})\n",
        .{
            @as(u32, @bitCast(raw_fd)),
            iovs_ptr,
            @as(u32, @bitCast(raw_iovs_len)),
            ret_ptr,
        },
    );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    var scratch = wasi.acquireScratch();
    defer wasi.releaseScratch(scratch);

    const ciovs = Ciovs.init(mem, iovs_ptr, @bitCast(raw_iovs_len), &scratch) catch |e|
        return .mapError(e);
    const ret_bytes = ret_ptr.bytes(mem) catch |e| return .mapError(e);

    const ret = file.fd_write(ciovs.list, ciovs.total_len) catch |e| return .mapError(e);
    pointer.writeFromBytes(u32, ret_bytes, ret);
    return .success;
}

/// Asserts that `state` indicates a host function is currently being called.
pub fn dispatch(
    wasi: *WasiPreview1,
    state: *Interpreter.State.AwaitingHost,
    memory: *MemInst,
    fuel: *Interpreter.Fuel,
) Interpreter.State {
    const callee = state.currentHostFunction().?;

    // TODO: Parameter to indicate if it safe to assume a WASI function is being called?
    std.debug.assert(@intFromPtr(callee.data) == @intFromPtr(wasi));

    const api = Api.fromHostFunc(callee.func);
    std.debug.assert(@intFromPtr(api.hostFunc()) == @intFromPtr(callee.func));
    switch (api) {
        inline .fd_pwrite,
        .fd_write,
        => |id| {
            const signature = comptime id.signature();
            var args_values: [signature.param_count]Interpreter.TaggedValue = undefined;
            state.copyParamsTo(&args_values);
            const args_tuple = id.taggedValuesToParamTuple(&args_values);
            const errno: Errno = @call(
                .auto,
                @field(WasiPreview1, @tagName(id)),
                .{ wasi, memory } ++ args_tuple,
            );

            return state.returnFromHostTyped(.{@as(i32, @intFromEnum(errno))}, fuel) catch
                unreachable;
        },
        else => if (std.mem.eql(Module.ValType, api.signature().results(), &.{.i32})) {
            std.log.err("TODO: handle {t}", .{api});
            return state.returnFromHostTyped(.{@as(i32, @intFromEnum(Errno.nosys))}, fuel) catch
                unreachable;
        } else {
            std.debug.panic("TODO: handle {t}", .{api});
        },
    }
}

pub fn deinit(state: *WasiPreview1) void {
    state.fd_table.deinit(state.allocator);
    state.api_lookup.deinit(state.allocator);
    state.scratch.lock.assertUnlocked();
    state.scratch.state.promote(state.allocator).deinit();
    state.* = undefined;
}

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const wasmstint = @import("wasmstint");
const Interpreter = wasmstint.Interpreter;
const MemInst = wasmstint.runtime.MemInst;
const Module = wasmstint.Module;
const pointer = wasmstint.pointer;

test {
    _ = WasiPreview1;
}
