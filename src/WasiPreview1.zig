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
pub const Path = @import("WasiPreview1/Path.zig");
pub const PreopenDir = @import("WasiPreview1/PreopenDir.zig");

allocator: Allocator,
scratch: struct {
    state: ArenaAllocator.State,
    lock: std.debug.SafetyLock = .{},
},
api_lookup: Api.Lookup,
csprng: Csprng,
fd_table: Fd.Table,
args: Arguments,
environ: Environ,
inode_hash_seed: types.INode.HashSeed,

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
pub const Environ = @import("WasiPreview1/Environ.zig");

pub const InitError = Allocator.Error;

pub const InitOptions = struct {
    /// No default value since most applications expect at least an application name.
    args: Arguments,
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
pub fn init(
    allocator: Allocator,
    options: InitOptions,
    // Can't put in `InitOptions` since these are file handles that need to be closed.
    preopen_dirs: *[]PreopenDir,
) InitError!WasiPreview1 {
    defer std.debug.assert(preopen_dirs.len == 0);

    var rng = std.Random.SplitMix64.init(options.fd_rng_seed);
    var fd_table = try Fd.Table.init(
        allocator,
        &rng,
        File.os.wrapStandardStreams(),
        preopen_dirs,
    );
    errdefer fd_table.deinit(allocator);
    std.debug.assert(preopen_dirs.len == 0); // `fd_table` handles cleanup

    var api_lookup = try Api.Lookup.init(allocator, rng.next());
    errdefer api_lookup.deinit(allocator);

    errdefer comptime unreachable;
    return .{
        .fd_table = fd_table,
        .api_lookup = api_lookup,
        .allocator = allocator,
        .scratch = .{ .state = ArenaAllocator.init(allocator).state },
        .csprng = options.csprng,
        .args = options.args,
        .environ = options.environ,
        .inode_hash_seed = @enumFromInt(rng.next()),
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

fn processParametersApi(comptime field: std.meta.FieldEnum(WasiPreview1)) type {
    return struct {
        const field_name = @tagName(field);

        fn get(
            wasi: *WasiPreview1,
            mem: *MemInst,
            raw_argv: i32,
            raw_argv_buf: i32,
        ) Errno {
            const argv_ptr = pointer.Pointer(pointer.Pointer(u32)){
                .addr = @as(u32, @bitCast(raw_argv)),
            };
            const argv_buf_ptr = pointer.Pointer(u8){ .addr = @as(u32, @bitCast(raw_argv_buf)) };

            // std.log.debug(@tagName(field) ++ "_get({f}, {f})\n", .{ argv_ptr, argv_buf_ptr });

            const argv = pointer.Slice(pointer.Pointer(u32)).init(
                mem,
                argv_ptr,
                @field(wasi, field_name).count,
            ) catch |e| return .mapError(e);

            const argv_buf = pointer.Slice(u8).init(
                mem,
                argv_buf_ptr,
                @field(wasi, field_name).size,
            ) catch |e| return .mapError(e);

            var dst_buf = argv_buf.bytes();
            var argv_addr = argv_buf_ptr.addr;
            for (0.., @field(wasi, field_name).entries()) |i, src| {
                const len_with_null = src.lenWithNullTerminator();
                argv.write(i, .{ .addr = argv_addr });

                const dst = dst_buf[0 .. len_with_null - 1];
                std.debug.assert( // wrong addr
                    dst_buf.ptr - argv_buf.bytes().ptr == argv_addr - argv_buf_ptr.addr,
                );

                @memcpy(dst, src.bytes());

                dst_buf[len_with_null - 1] = 0;
                dst_buf = dst_buf[len_with_null..];
                argv_addr += len_with_null;
            }

            std.debug.assert(dst_buf.len == 0);
            std.debug.assert(argv_addr - argv_buf_ptr.addr == @field(wasi, field_name).size);
            return .success;
        }

        fn sizes_get(
            wasi: *WasiPreview1,
            mem: *MemInst,
            raw_ret_count: i32,
            raw_ret_size: i32,
        ) Errno {
            const count = pointer.Pointer(u32){ .addr = @as(u32, @bitCast(raw_ret_count)) };
            const size = pointer.Pointer(u32){ .addr = @as(u32, @bitCast(raw_ret_size)) };

            // std.log.debug(@tagName(field) ++ "_sizes_get({f}, {f})\n", .{ argc, size });

            count.write(mem, @field(wasi, field_name).count) catch |e| return .mapError(e);
            size.write(mem, @field(wasi, field_name).size) catch |e| return .mapError(e);

            // std.log.debug(
            //     @tagName(field) ++ "_sizes_get -> ({}, {})\n",
            //     .{ @field(wasi, field_name).count, @field(wasi, field_name).size },
            // );

            if (builtin.mode == .Debug) {
                std.debug.assert(count.read(mem) catch unreachable == @field(wasi, field_name).count);
                std.debug.assert(size.read(mem) catch unreachable == @field(wasi, field_name).size);
            }

            return .success;
        }
    };
}

const args_api = processParametersApi(.args);
const args_get = args_api.get;
const args_sizes_get = args_api.sizes_get;

const environ_api = processParametersApi(.environ);
const environ_get = environ_api.get;
const environ_sizes_get = environ_api.sizes_get;

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

fn fd_close(wasi: *WasiPreview1, _: *MemInst, raw_fd: i32) Errno {
    // std.log.debug("fd_close({d})", .{@as(u32, @bitCast(raw_fd))});

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    wasi.fd_table.close(wasi.allocator, fd) catch |e| return .mapError(e);
    return .success;
}

// fn fd_datasync

// Note handlers here can just use `Errno.fault` for OOB memory accesses, which is nice since
// `AwaitingHost` doesn't support trapping yet.

fn fd_fdstat_get(wasi: *WasiPreview1, mem: *MemInst, raw_fd: i32, raw_ret: i32) Errno {
    const ret_ptr = pointer.Pointer(types.FdStat){ .addr = @as(u32, @bitCast(raw_ret)) };

    std.log.debug("fd_fdstat_get({d}, {f})", .{ @as(u32, @bitCast(raw_fd)), ret_ptr });

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    const stat = file.fd_fdstat_get() catch |e| return .mapError(e);
    ret_ptr.write(mem, stat) catch |e| return .mapError(e);

    return .success;
}

fn fd_prestat_get(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_buf: i32,
) Errno {
    const buf_ptr = pointer.Pointer(types.Prestat){ .addr = @as(u32, @bitCast(raw_buf)) };

    // std.log.debug("fd_prestat_get({}, {f})", .{ @as(u32, @bitCast(raw_fd)), buf_ptr });

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    const prestat = file.fd_prestat_get() catch |e| return .mapError(e);
    buf_ptr.write(mem, prestat) catch |e| return .mapError(e);

    return .success;
}

fn fd_prestat_dir_name(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_path: i32,
    raw_path_len: i32,
) Errno {
    const path_ptr = pointer.Pointer(u8){ .addr = @as(u32, @bitCast(raw_path)) };
    const path_len: u32 = @bitCast(raw_path_len);

    // std.log.debug(
    //     "fd_prestat_dir_name({}, {f}, {d})",
    //     .{ @as(u32, @bitCast(raw_fd)), path_ptr, path_len },
    // );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    const path = pointer.Slice(u8).init(mem, path_ptr, path_len) catch |e| return .mapError(e);
    file.fd_prestat_dir_name(path.bytes()) catch |e| return .mapError(e);

    return .success;
}

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

    // std.log.debug(
    //     "fd_pwrite({}, {f}, {}, {}, {f})",
    //     .{
    //         @as(u32, @bitCast(raw_fd)),
    //         iovs_ptr,
    //         @as(u32, @bitCast(raw_iovs_len)),
    //         offset.bytes,
    //         ret_ptr,
    //     },
    // );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    var scratch = wasi.acquireScratch();
    defer wasi.releaseScratch(scratch);

    const ciovs = Ciovs.init(mem, iovs_ptr, @bitCast(raw_iovs_len), &scratch) catch |e|
        return .mapError(e);

    ret_ptr.write(
        mem,
        file.fd_pwrite(ciovs.list, offset, ciovs.total_len) catch |e| return .mapError(e),
    ) catch |e| return .mapError(e);

    return .success;
}

fn fd_readdir(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_buf: i32,
    raw_buf_len: i32,
    raw_cookie: i64,
    raw_ret: i32,
) Errno {
    const buf_ptr = pointer.Pointer(u8){ .addr = @bitCast(raw_buf) };
    const buf_len: u32 = @bitCast(raw_buf_len);
    const cookie = types.DirCookie{ .n = @bitCast(raw_cookie) };
    const ret_ptr = pointer.Pointer(types.Size){ .addr = @as(u32, @bitCast(raw_ret)) };

    // std.log.debug(
    //     "fd_readdir({}, {f}, {}, {f}, {f})",
    //     .{ @as(u32, @bitCast(raw_fd)), buf_ptr, buf_len, cookie, ret_ptr },
    // );

    const buf = pointer.Slice(u8).init(mem, buf_ptr, buf_len) catch |e| return .mapError(e);

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    const size = file.fd_readdir(
        // wasi.allocator,
        wasi.inode_hash_seed,
        buf.bytes(),
        cookie,
    ) catch |e| return .mapError(e);

    ret_ptr.write(mem, size) catch |e| return .mapError(e);

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

    // std.log.debug(
    //     "fd_write({}, {f}, {}, {f})\n",
    //     .{
    //         @as(u32, @bitCast(raw_fd)),
    //         iovs_ptr,
    //         @as(u32, @bitCast(raw_iovs_len)),
    //         ret_ptr,
    //     },
    // );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    var scratch = wasi.acquireScratch();
    defer wasi.releaseScratch(scratch);

    const ciovs = Ciovs.init(mem, iovs_ptr, @bitCast(raw_iovs_len), &scratch) catch |e|
        return .mapError(e);

    ret_ptr.write(
        mem,
        file.fd_write(ciovs.list, ciovs.total_len) catch |e| return .mapError(e),
    ) catch |e| return .mapError(e);

    return .success;
}

pub const DispatchResult = union(enum) {
    @"continue": Interpreter.State,
    /// The WASM program called `proc_exit()`.
    ///
    /// Don't forget to call `WasiPreview1.deinit()`.
    proc_exit: i32,
};

/// Handles all calls to WASI API functions made by a WASM program.
///
/// Asserts that `state` indicates a host function is currently being called.
pub fn dispatch(
    wasi: *WasiPreview1,
    state: *Interpreter.State.AwaitingHost,
    memory: *MemInst,
    fuel: *Interpreter.Fuel,
) DispatchResult {
    const callee = state.currentHostFunction().?;

    // TODO: Parameter to indicate if it safe to assume a WASI function is being called?
    std.debug.assert(@intFromPtr(callee.data) == @intFromPtr(wasi));

    const api = Api.fromHostFunc(callee.func);
    std.debug.assert(@intFromPtr(api.hostFunc()) == @intFromPtr(callee.func));
    switch (api) {
        .proc_exit => {
            @branchHint(.cold);
            const exit_code = state.paramsTyped(struct { i32 }) catch unreachable;
            // std.log.debug("proc_exit({})", .{exit_code});
            return .{ .proc_exit = exit_code[0] };
        },
        .sched_yield => {
            const errno: Errno = err: {
                std.Thread.yield() catch |e| switch (e) {
                    error.SystemCannotYield => switch (builtin.os.tag) {
                        .windows, .linux => unreachable,
                        else => break :err .nosys,
                    },
                };

                break :err .success;
            };

            return .{
                .@"continue" = state.returnFromHostTyped(
                    .{@as(i32, @intFromEnum(errno))},
                    fuel,
                ) catch unreachable,
            };
        },
        inline .args_get,
        .args_sizes_get,
        .environ_get,
        .environ_sizes_get,
        .fd_close,
        .fd_fdstat_get,
        .fd_prestat_get,
        .fd_prestat_dir_name,
        .fd_readdir,
        .fd_pwrite,
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

            // if (errno != .success) {
            //     std.log.debug(@tagName(id) ++ " -> {f}", .{errno});
            // }

            return .{
                .@"continue" = state.returnFromHostTyped(
                    .{@as(i32, @intFromEnum(errno))},
                    fuel,
                ) catch unreachable,
            };
        },
        else => if (std.mem.eql(Module.ValType, api.signature().results(), &.{.i32})) {
            std.log.err("TODO: handle {t}", .{api});
            return .{
                .@"continue" = state.returnFromHostTyped(
                    .{@as(i32, @intFromEnum(Errno.nosys))},
                    fuel,
                ) catch unreachable,
            };
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
const builtin = @import("builtin");
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
