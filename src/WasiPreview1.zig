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

    fn bytes(iovec: Iovec, mem: *const MemInst) pointer.OobError![]u8 {
        return pointer.accessSlice(mem, iovec.buf.addr, iovec.buf_len);
    }
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
    // TODO: std.EnumSet(types.ClockId) to indicate available clocks
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
        File.host_file.wrapStandardStreams(),
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

// Note: handlers here can just use `Errno.fault` for OOB memory accesses, which is nice since
// `AwaitingHost` doesn't support trapping yet.

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
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#args_get
const args_get = args_api.get;
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#args_sizes_get
const args_sizes_get = args_api.sizes_get;

const environ_api = processParametersApi(.environ);
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#environ_get
const environ_get = environ_api.get;
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#environ_sizes_get
const environ_sizes_get = environ_api.sizes_get;

const InitIovsError = pointer.OobError || error{InvalidArgument};

// TODO: std.heap.stackFallback + only do portion of ciovecs; if OOM happens, do not return Errno.nomem to guest!
// ^ stack buffer to allow minimum of 1 (C)Iovec
fn initIoVectorList(
    comptime List: type,
    comptime GuestVec: type,
    comptime HostVec: type,
) fn (*MemInst, pointer.ConstPointer(GuestVec), len: u32, *ArenaAllocator) InitIovsError!List {
    return struct {
        fn init(
            mem: *MemInst,
            ptr: pointer.ConstPointer(GuestVec),
            len: u32,
            // Should be *std.heap.StackBufferAllocator
            scratch: *ArenaAllocator,
        ) InitIovsError!List {
            const iovs = try pointer.ConstSlice(GuestVec).init(mem, ptr, len);
            var list = std.ArrayListUnmanaged(HostVec).empty;
            list.ensureTotalCapacityPrecise(scratch.allocator(), iovs.items.len) catch {};
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
                list.appendAssumeCapacity(HostVec.init(ciovec)); // Should be list.append, breaking on OOM
            }

            return .{ .list = list.items, .total_len = total_len };
        }
    }.init;
}

const Iovs = struct {
    list: []const File.Iovec,
    total_len: u32,

    const init = initIoVectorList(Iovs, Iovec, File.Iovec);
};

const Ciovs = struct {
    list: []const File.Ciovec,
    total_len: u32,

    const init = initIoVectorList(Ciovs, Ciovec, File.Ciovec);
};

/// Return the resolution of a clock.
///
/// Implementations are required to provide a non-zero value for supported clocks. For unsupported
/// clocks, return `Errno.inval`. This is similar to `clock_getres` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#clock_res_get
fn clock_res_get(wasi: *WasiPreview1, mem: *MemInst, raw_clock_id: i32, raw_ret: i32) Errno {
    const clock_id: types.ClockId = @enumFromInt(@as(u32, @bitCast(raw_clock_id)));
    const ret_ptr = pointer.Pointer(types.Timestamp){ .addr = @as(u32, @bitCast(raw_ret)) };

    std.log.debug("clock_res_get({t}, {f})", .{ clock_id, ret_ptr });

    // TODO: Check allowed clocks

    _ = wasi;
    const resolution: types.Timestamp = switch (clock_id) {
        .real_time => if (true) {
            return Errno.nosys; // TODO: clock_res_get impl
        },
        .monotonic,
        .process_cputime_id,
        .thread_cputime_id,
        _,
        => return Errno.inval,
    };

    ret_ptr.write(mem, resolution) catch |e| return .mapError(e);

    return Errno.success;
}

/// Return the time value of a clock.
///
/// This is similar to `clock_gettime` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#clock_time_get
fn clock_time_get(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_clock_id: i32,
    /// A `types.Timestamp` indicating the maximum lag (exclusive) that the returned time value may
    /// have, compared to its actual value.
    raw_precision: i64,
    raw_ret: i32,
) Errno {
    const clock_id: types.ClockId = @enumFromInt(@as(u32, @bitCast(raw_clock_id)));
    const precision = types.Timestamp{ .ns = @as(u64, @bitCast(raw_precision)) };
    const ret_ptr = pointer.Pointer(types.Timestamp){ .addr = @as(u32, @bitCast(raw_ret)) };

    std.log.debug("clock_time_get({t}, {d}, {f})", .{ clock_id, precision.ns, ret_ptr });

    // TODO: Check allowed clocks
    _ = wasi;
    _ = mem;
    return .nosys; // TODO: clock_time_get impl
}

fn fd_advise(
    wasi: *WasiPreview1,
    _: *MemInst,
    raw_fd: i32,
    raw_offset: i64,
    raw_len: i64,
    raw_advice: i32,
) Errno {
    const offset = types.FileSize{ .bytes = @as(u64, @bitCast(raw_offset)) };
    const len = types.FileSize{ .bytes = @as(u64, @bitCast(raw_len)) };
    const advice_bits: u32 = @bitCast(raw_advice);
    const advice_casted = std.enums.fromInt(types.Advice, advice_bits);

    std.log.debug(
        "fd_advise({[fd]d}, {[offset]d}, {[len]d}, {[advice_bits]d} ({[advice_name]s}))",
        .{
            .fd = @as(u32, @intCast(raw_fd)),
            .offset = offset.bytes,
            .len = len.bytes,
            .advice_bits = advice_bits,
            .advice_name = if (advice_casted) |adv| @tagName(adv) else "invalid",
        },
    );

    const advice: types.Advice = advice_casted orelse return .inval;
    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();
    file.fd_advise(offset, len, advice) catch |e| return .mapError(e);

    return Errno.success;
}

fn fd_allocate(
    wasi: *WasiPreview1,
    _: *MemInst,
    raw_fd: i32,
    raw_offset: i64,
    raw_len: i64,
) Errno {
    const offset = types.FileSize{ .bytes = @as(u64, @bitCast(raw_offset)) };
    const len = types.FileSize{ .bytes = @as(u64, @bitCast(raw_len)) };
    std.log.debug(
        "fd_advise({d}, {d}, {d})",
        .{ @as(u32, @intCast(raw_fd)), offset.bytes, len.bytes },
    );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();
    file.fd_allocate(offset, len) catch |e| return .mapError(e);

    return Errno.success;
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

fn fd_close(wasi: *WasiPreview1, _: *MemInst, raw_fd: i32) Errno {
    // std.log.debug("fd_close({d})", .{@as(u32, @bitCast(raw_fd))});

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    wasi.fd_table.close(wasi.allocator, fd) catch |e| return .mapError(e);
    return Errno.success;
}

fn fd_datasync(wasi: *WasiPreview1, _: *MemInst, raw_fd: i32) Errno {
    std.log.debug("fd_datasync({d})", .{@as(u32, @bitCast(raw_fd))});

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();
    file.fd_datasync() catch |e| return .mapError(e);

    return Errno.success;
}

fn fd_fdstat_get(wasi: *WasiPreview1, mem: *MemInst, raw_fd: i32, raw_ret: i32) Errno {
    const ret_ptr = pointer.Pointer(types.FdStat){ .addr = @as(u32, @bitCast(raw_ret)) };

    std.log.debug("fd_fdstat_get({d}, {f})", .{ @as(u32, @bitCast(raw_fd)), ret_ptr });

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    const stat = file.fd_fdstat_get() catch |e| return .mapError(e);
    ret_ptr.write(mem, stat) catch |e| return .mapError(e);

    return Errno.success;
}

fn fd_fdstat_set_flags(wasi: *WasiPreview1, _: *MemInst, raw_fd: i32, raw_flags: i32) Errno {
    const flags_param: types.FdFlags.Param = @bitCast(raw_flags);

    std.log.debug(
        "fd_fdstat_set_flags({d}, {f})",
        .{ @as(u32, @bitCast(raw_fd)), flags_param },
    );

    const flags = flags_param.validate() orelse return Errno.inval;
    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    file.fd_fdstat_set_flags(flags) catch |e| return .mapError(e);

    return Errno.success;
}

fn fd_fdstat_set_rights(
    wasi: *WasiPreview1,
    _: *MemInst,
    raw_fd: i32,
    raw_rights_base: i64,
    raw_rights_inheriting: i64,
) Errno {
    const abi_rights_base: types.Rights = @bitCast(raw_rights_base);
    const abi_rights_inheriting: types.Rights = @bitCast(raw_rights_inheriting);

    std.log.debug(
        "fd_fdstat_set_rights({d}, {f}, {f})",
        .{ @as(u32, @bitCast(raw_fd)), abi_rights_base, abi_rights_inheriting },
    );

    const rights_base: types.Rights.Valid = abi_rights_base.validate() orelse
        return Errno.inval;
    const rights_inheriting: types.Rights.Valid = abi_rights_inheriting.validate() orelse
        return Errno.inval;

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    file.fd_fdstat_set_rights(rights_base, rights_inheriting) catch |e| return .mapError(e);

    return Errno.success;
}

fn fd_filestat_get(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_ret: i32,
) Errno {
    const ret_ptr = pointer.Pointer(types.FileStat){ .addr = @as(u32, @bitCast(raw_ret)) };

    std.log.debug("fd_filestat_get({}, {f})", .{ @as(u32, @bitCast(raw_fd)), ret_ptr });

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    ret_ptr.write(
        mem,
        file.fd_filestat_get() catch |e| return .mapError(e),
    ) catch |e| return .mapError(e);

    return Errno.success;
}

fn fd_filestat_set_size(
    wasi: *WasiPreview1,
    _: *MemInst,
    raw_fd: i32,
    raw_size: i64,
) Errno {
    const size = types.FileSize{ .bytes = @as(u64, @bitCast(raw_size)) };

    std.log.debug(
        "fd_filestat_set_size({d}, {d})",
        .{ @as(u32, @bitCast(raw_fd)), size.bytes },
    );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    file.fd_filestat_set_size(size) catch |e| return .mapError(e);

    return Errno.success;
}

fn fd_filestat_set_times(
    wasi: *WasiPreview1,
    _: *MemInst,
    raw_fd: i32,
    raw_atim: i64,
    raw_mtim: i64,
    raw_fst_flags: i32,
) Errno {
    const atim = types.Timestamp{ .ns = @as(u64, @bitCast(raw_atim)) };
    const mtim = types.Timestamp{ .ns = @as(u64, @bitCast(raw_mtim)) };
    const flags_param: types.FstFlags.Param = @bitCast(raw_fst_flags);

    std.log.debug(
        "fd_filestat_set_times({d}, {d}, {d}, {f})",
        .{ @as(u32, @bitCast(raw_fd)), atim.ns, mtim.ns, flags_param },
    );

    const flags: types.FstFlags.Valid = flags_param.validate() orelse return Errno.inval;
    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    file.fd_filestat_set_times(atim, mtim, flags) catch |e| return .mapError(e);

    return Errno.success;
}

fn fd_pread(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_iovs: i32,
    raw_iovs_len: i32,
    raw_offset: i64,
    raw_ret: i32,
) Errno {
    const iovs_ptr = pointer.ConstPointer(Iovec){ .addr = @bitCast(raw_iovs) };
    const iovs_len: u32 = @bitCast(raw_iovs_len);
    const ret_ptr = pointer.Pointer(u32){ .addr = @as(u32, @bitCast(raw_ret)) };
    const offset = types.FileSize{ .bytes = @bitCast(raw_offset) };

    std.log.debug(
        "fd_pread({d}, {f}, {d}, {d}, {f})",
        .{
            @as(u32, @bitCast(raw_fd)),
            iovs_ptr,
            iovs_len,
            offset.bytes,
            ret_ptr,
        },
    );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    var scratch = wasi.acquireScratch();
    defer wasi.releaseScratch(scratch);

    const iovs = Iovs.init(mem, iovs_ptr, iovs_len, &scratch) catch |e| return .mapError(e);

    ret_ptr.write(
        mem,
        file.fd_pread(iovs.list, offset, iovs.total_len) catch |e| return .mapError(e),
    ) catch |e| return .mapError(e);

    return .success;
}

fn fd_prestat_get(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_buf: i32,
) Errno {
    const buf_ptr = pointer.Pointer(types.PreStat){ .addr = @as(u32, @bitCast(raw_buf)) };

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
    const iovs_len: u32 = @bitCast(raw_iovs_len);
    const ret_ptr = pointer.Pointer(u32){ .addr = @as(u32, @bitCast(raw_ret)) };
    const offset = types.FileSize{ .bytes = @bitCast(raw_offset) };

    // std.log.debug(
    //     "fd_pwrite({}, {f}, {}, {}, {f})",
    //     .{
    //         @as(u32, @bitCast(raw_fd)),
    //         iovs_ptr,
    //         iovs_len,
    //         offset.bytes,
    //         ret_ptr,
    //     },
    // );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    var scratch = wasi.acquireScratch();
    defer wasi.releaseScratch(scratch);

    const ciovs = Ciovs.init(mem, iovs_ptr, iovs_len, &scratch) catch |e| return .mapError(e);

    ret_ptr.write(
        mem,
        file.fd_pwrite(ciovs.list, offset, ciovs.total_len) catch |e| return .mapError(e),
    ) catch |e| return .mapError(e);

    return .success;
}

fn fd_read(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_iovs: i32,
    raw_iovs_len: i32,
    raw_ret: i32,
) Errno {
    const iovs_ptr = pointer.ConstPointer(Iovec){ .addr = @bitCast(raw_iovs) };
    const iovs_len: u32 = @bitCast(raw_iovs_len);
    const ret_ptr = pointer.Pointer(u32){ .addr = @as(u32, @bitCast(raw_ret)) };

    std.log.debug(
        "fd_read({}, {f}, {}, {f})\n",
        .{ @as(u32, @bitCast(raw_fd)), iovs_ptr, iovs_len, ret_ptr },
    );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    var scratch = wasi.acquireScratch();
    defer wasi.releaseScratch(scratch);

    const iovs = Iovs.init(mem, iovs_ptr, iovs_len, &scratch) catch |e| return .mapError(e);

    ret_ptr.write(
        mem,
        file.fd_read(iovs.list, iovs.total_len) catch |e| return .mapError(e),
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

/// Atomically replace a file descriptor by renumbering another file descriptor.
///
/// Due to the strong focus on thread safety, this environment does not provide a mechanism to
/// duplicate or renumber a file descriptor to an arbitrary number, like `dup2()`. This would be
/// prone to race conditions, as an actual file descriptor with the same number could be allocated
/// by a different thread at the same time. This function provides a way to atomically renumber
/// file descriptors, which would disappear if `dup2()` were to be removed entirely.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_renumber
fn fd_renumber(
    wasi: *WasiPreview1,
    _: *MemInst,
    raw_fd: i32,
    raw_to: i32,
) Errno {
    std.log.debug(
        "fd_renumber({d}, {d})",
        .{ @as(u32, @bitCast(raw_fd)), @as(u32, @bitCast(raw_to)) },
    );

    const old_fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const new_fd = Fd.initRaw(raw_to) catch |e| return .mapError(e);
    _ = wasi;
    // wasi.fd_table.renumber(old_fd, new_fd) catch |e| return .mapError(e);
    _ = old_fd;
    _ = new_fd;

    return .nosys; // TODO: figure out semantics of `fd_renumber`
}

fn fd_seek(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_filedelta: i64,
    raw_whence: i32,
    raw_ret: i32,
) Errno {
    const delta = types.FileDelta{ .offset = raw_filedelta };
    const whence_bits: u32 = @bitCast(raw_whence);
    const whence_casted = std.enums.fromInt(types.Whence, raw_whence);
    const ret_ptr = pointer.Pointer(types.FileSize){ .addr = @as(u32, @bitCast(raw_ret)) };

    std.log.debug(
        "fd_seek({d}, {d}, {d} ({s}), {f})",
        .{
            @as(u32, @bitCast(raw_fd)),
            delta.offset,
            whence_bits,
            if (whence_casted) |whence| @tagName(whence) else "invalid",
            ret_ptr,
        },
    );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    ret_ptr.write(
        mem,
        file.fd_seek(delta, whence_casted orelse return .inval) catch |e| return .mapError(e),
    ) catch |e| return .mapError(e);

    return .success;
}

fn fd_sync(wasi: *WasiPreview1, _: *MemInst, raw_fd: i32) Errno {
    std.log.debug("fd_seek({d})", .{@as(u32, @bitCast(raw_fd))});

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    file.fd_sync() catch |e| return .mapError(e);

    return .success;
}

fn fd_tell(wasi: *WasiPreview1, mem: *MemInst, raw_fd: i32, raw_ret: i32) Errno {
    const ret_ptr = pointer.Pointer(types.FileSize){ .addr = @as(u32, @bitCast(raw_ret)) };
    std.log.debug("fd_tell({d}, {f})", .{ @as(u32, @bitCast(raw_fd)), ret_ptr });

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    ret_ptr.write(
        mem,
        file.fd_tell() catch |e| return .mapError(e),
    ) catch |e| return .mapError(e);

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
    const iovs_len: u32 = @bitCast(raw_iovs_len);
    const ret_ptr = pointer.Pointer(u32){ .addr = @as(u32, @bitCast(raw_ret)) };

    // std.log.debug(
    //     "fd_write({}, {f}, {}, {f})\n",
    //     .{ @as(u32, @bitCast(raw_fd)), iovs_ptr, iovs_len, ret_ptr },
    // );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    var scratch = wasi.acquireScratch();
    defer wasi.releaseScratch(scratch);

    const ciovs = Ciovs.init(mem, iovs_ptr, iovs_len, &scratch) catch |e| return .mapError(e);

    ret_ptr.write(
        mem,
        file.fd_write(ciovs.list, ciovs.total_len) catch |e| return .mapError(e),
    ) catch |e| return .mapError(e);

    return .success;
}

fn path_create_directory(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_path_ptr: i32,
    raw_path_len: i32,
) Errno {
    const path_ptr = pointer.ConstPointer(u8){ .addr = @as(u32, @bitCast(raw_path_ptr)) };
    const path_len: u32 = @bitCast(raw_path_len);

    std.log.debug(
        "path_create_directory({d}, {f}, {d})",
        .{ @as(u32, @bitCast(raw_fd)), path_ptr, path_len },
    );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    const path = pointer.ConstSlice(u8).init(mem, path_ptr, path_len) catch |e|
        return .mapError(e);

    file.path_create_directory(path.bytes()) catch |e| return .mapError(e);

    return .success;
}

fn path_filestat_get(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_flags: i32,
    raw_path_ptr: i32,
    raw_path_len: i32,
    raw_ret: i32,
) Errno {
    const flags_param: types.LookupFlags = @bitCast(raw_flags);
    const path_ptr = pointer.ConstPointer(u8){ .addr = @as(u32, @bitCast(raw_path_ptr)) };
    const path_len: u32 = @bitCast(raw_path_len);
    const ret_ptr = pointer.Pointer(types.FileStat){ .addr = @as(u32, @bitCast(raw_ret)) };

    std.log.debug(
        "path_filestat_get({d}, {f}, {f}, {d}, {f})",
        .{ @as(u32, @bitCast(raw_fd)), flags_param, path_ptr, path_len, ret_ptr },
    );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    const path = pointer.ConstSlice(u8).init(mem, path_ptr, path_len) catch |e|
        return .mapError(e);

    const flags = flags_param.validate() orelse return Errno.inval;

    ret_ptr.write(
        mem,
        file.path_filestat_get(flags, path.bytes()) catch |e| return .mapError(e),
    ) catch |e| return .mapError(e);

    return .success;
}

fn path_filestat_set_times(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_lookup_flags: i32,
    raw_path_ptr: i32,
    raw_path_len: i32,
    raw_atim: i64,
    raw_mtim: i64,
    raw_fst_flags: i32,
) Errno {
    const lookup_param: types.LookupFlags = @bitCast(raw_lookup_flags);
    const path_ptr = pointer.ConstPointer(u8){ .addr = @as(u32, @bitCast(raw_path_ptr)) };
    const path_len: u32 = @bitCast(raw_path_len);
    const atim = types.Timestamp{ .ns = @as(u64, @bitCast(raw_atim)) };
    const mtim = types.Timestamp{ .ns = @as(u64, @bitCast(raw_mtim)) };
    const fst_param: types.FstFlags.Param = @bitCast(raw_fst_flags);

    std.log.debug(
        "path_filestat_set_times({[fd]d}, {[lookup_flags]f}, {[path_ptr]f}, {[path_len]d}), " ++
            "{[atim]d}, {[mtim]d}, {[fst_flags]f}",
        .{
            .fd = @as(u32, @bitCast(raw_fd)),
            .lookup_flags = lookup_param,
            .path_ptr = path_ptr,
            .path_len = path_len,
            .atim = atim.ns,
            .mtim = mtim.ns,
            .fst_flags = fst_param,
        },
    );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    const path = pointer.ConstSlice(u8).init(mem, path_ptr, path_len) catch |e|
        return .mapError(e);

    const lookup_flags = lookup_param.validate() orelse return Errno.inval;
    const fst_flags = fst_param.validate() orelse return Errno.inval;

    file.path_filestat_set_times(lookup_flags, path.bytes(), atim, mtim, fst_flags) catch |e|
        return .mapError(e);

    return .success;
}

fn path_link(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_old_fd: i32,
    raw_flags: i32,
    raw_old_path_ptr: i32,
    raw_old_path_len: i32,
    raw_new_fd: i32,
    raw_new_path_ptr: i32,
    raw_new_path_len: i32,
) Errno {
    const lookup_param: types.LookupFlags = @bitCast(raw_flags);
    const old_path_ptr = pointer.ConstPointer(u8){ .addr = @as(u32, @bitCast(raw_old_path_ptr)) };
    const old_path_len: u32 = @bitCast(raw_old_path_len);
    const new_path_ptr = pointer.ConstPointer(u8){ .addr = @as(u32, @bitCast(raw_new_path_ptr)) };
    const new_path_len: u32 = @bitCast(raw_new_path_len);

    std.log.debug(
        "path_link({[old_fd]d}, {[flags]f}, {[old_path_ptr]f}, {[old_path_len]d}, {[new_fd]d}, " ++
            "{[new_path_ptr]f}, {[new_path_len]d})",
        .{
            .old_fd = @as(u32, @bitCast(raw_old_fd)),
            .flags = lookup_param,
            .old_path_ptr = old_path_ptr,
            .old_path_len = old_path_len,
            .new_fd = @as(u32, @bitCast(raw_new_fd)),
            .new_path_ptr = new_path_ptr,
            .new_path_len = new_path_len,
        },
    );

    const old_fd = Fd.initRaw(raw_old_fd) catch |e| return .mapError(e);
    const new_fd = Fd.initRaw(raw_new_fd) catch |e| return .mapError(e);
    const old_file = wasi.fd_table.get(old_fd) catch |e| return .mapError(e);
    wasi.fd_table.unlockTable();
    const new_file = wasi.fd_table.get(new_fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    const old_path = pointer.ConstSlice(u8).init(mem, old_path_ptr, old_path_len) catch |e|
        return .mapError(e);
    const new_path = pointer.ConstSlice(u8).init(mem, new_path_ptr, new_path_len) catch |e|
        return .mapError(e);

    const lookup_flags = lookup_param.validate() orelse return Errno.inval;

    _ = old_file;
    _ = new_file;
    _ = old_path;
    _ = new_path;
    _ = lookup_flags;

    return Errno.nosys; // TODO: path_link implementation, two FD's? How daring...
}

fn typedPathOpen(
    wasi: *WasiPreview1,
    dir_fd: Fd,
    dir_flags: types.LookupFlags.Valid,
    path: []const u8,
    open_flags: types.OpenFlags.Valid,
    rights_base: types.Rights.Valid,
    rights_inheriting: types.Rights.Valid,
    fs_flags: types.FdFlags.Valid,
) !Fd {
    const new_fd = try wasi.fd_table.create(wasi.allocator);
    wasi.fd_table.unlockTable();
    errdefer {
        std.debug.assert(wasi.fd_table.removeWithoutClosing(new_fd.fd));
    }
    const dir = try wasi.fd_table.get(dir_fd);
    defer wasi.fd_table.unlockTable();

    new_fd.file.* = try dir.path_open(
        dir_flags,
        path,
        open_flags,
        rights_base,
        rights_inheriting,
        fs_flags,
    );

    return new_fd.fd;
}

fn path_open(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_dir_fd: i32,
    raw_dir_flags: i32,
    raw_path_ptr: i32,
    raw_path_len: i32,
    raw_open_flags: i32,
    raw_rights_base: i64,
    raw_rights_inheriting: i64,
    raw_fs_flags: i32,
    raw_ret: i32,
) Errno {
    const dir_flags_param: types.LookupFlags = @bitCast(raw_dir_flags);
    const path_ptr = pointer.ConstPointer(u8){ .addr = @as(u32, @bitCast(raw_path_ptr)) };
    const path_len: u32 = @bitCast(raw_path_len);
    const open_flags_param: types.OpenFlags.Param = @bitCast(raw_open_flags);
    const rights_base_param: types.Rights = @bitCast(raw_rights_base);
    const rights_inheriting_param: types.Rights = @bitCast(raw_rights_inheriting);
    const fs_flags_param: types.FdFlags.Param = @bitCast(raw_fs_flags);
    const ret_fd_ptr = pointer.Pointer(u32){ .addr = @as(u32, @bitCast(raw_ret)) };

    std.log.debug(
        "path_open({[dir_fd]d}, {[dir_flags]f}, {[path_ptr]f}, {[path_len]d}), {[open_flags]f}, " ++
            "{[rights_base]f}, {[rights_inheriting]f}, {[fs_flags]f}, {[ret_ptr]f})",
        .{
            .dir_fd = @as(u32, @bitCast(raw_dir_fd)),
            .dir_flags = dir_flags_param,
            .path_ptr = path_ptr,
            .path_len = path_len,
            .open_flags = open_flags_param,
            .rights_base = rights_base_param,
            .rights_inheriting = rights_inheriting_param,
            .fs_flags = fs_flags_param,
            .ret_ptr = ret_fd_ptr,
        },
    );

    const dir_fd = Fd.initRaw(raw_dir_fd) catch |e| return .mapError(e);

    const path = pointer.ConstSlice(u8).init(mem, path_ptr, path_len) catch |e|
        return .mapError(e);

    const dir_flags = dir_flags_param.validate() orelse return Errno.inval;
    const open_flags = open_flags_param.validate() orelse return Errno.inval;
    const rights_base = rights_base_param.validate() orelse return Errno.inval;
    const rights_inheriting = rights_inheriting_param.validate() orelse return Errno.inval;
    const fs_flags = fs_flags_param.validate() orelse return Errno.inval;

    const ret_fd_bytes = ret_fd_ptr.access(mem) catch |e| return .mapError(e);

    const new_fd = wasi.typedPathOpen(
        dir_fd,
        dir_flags,
        path.bytes(),
        open_flags,
        rights_base,
        rights_inheriting,
        fs_flags,
    ) catch |e| return .mapError(e);

    pointer.writeToBytes(u32, ret_fd_bytes, @bitCast(new_fd));

    return .success;
}

fn path_readlink(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_path_ptr: i32,
    raw_path_len: i32,
    raw_buf_ptr: i32,
    raw_buf_len: i32,
    raw_ret: i32,
) Errno {
    const path_ptr = pointer.ConstPointer(u8){ .addr = @as(u32, @bitCast(raw_path_ptr)) };
    const path_len: u32 = @bitCast(raw_path_len);
    const buf_ptr = pointer.Pointer(u8){ .addr = @as(u32, @bitCast(raw_buf_ptr)) };
    const buf_len: u32 = @bitCast(raw_buf_len);
    const ret_ptr = pointer.Pointer(types.Size){ .addr = @as(u32, @bitCast(raw_ret)) };

    std.log.debug(
        "path_readlink({d}, {f}, {d}, {f}, {d}, {f})",
        .{ @as(u32, @bitCast(raw_fd)), path_ptr, path_len, buf_ptr, buf_len, ret_ptr },
    );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    const path = pointer.ConstSlice(u8).init(mem, path_ptr, path_len) catch |e|
        return .mapError(e);
    const buf = pointer.Slice(u8).init(mem, buf_ptr, buf_len) catch |e|
        return .mapError(e);

    ret_ptr.write(
        mem,
        file.path_readlink(path.bytes(), buf.bytes()) catch |e| return .mapError(e),
    ) catch |e| return .mapError(e);

    return .success;
}

fn path_remove_directory(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_path_ptr: i32,
    raw_path_len: i32,
) Errno {
    const path_ptr = pointer.ConstPointer(u8){ .addr = @as(u32, @bitCast(raw_path_ptr)) };
    const path_len: u32 = @bitCast(raw_path_len);

    std.log.debug(
        "path_readlink({d}, {f}, {d})",
        .{ @as(u32, @bitCast(raw_fd)), path_ptr, path_len },
    );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    const path = pointer.ConstSlice(u8).init(mem, path_ptr, path_len) catch |e|
        return .mapError(e);

    file.path_remove_directory(path.bytes()) catch |e| return .mapError(e);

    return .success;
}

fn path_rename(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_old_fd: i32,
    raw_old_path_ptr: i32,
    raw_old_path_len: i32,
    raw_new_fd: i32,
    raw_new_path_ptr: i32,
    raw_new_path_len: i32,
) Errno {
    const old_path_ptr = pointer.ConstPointer(u8){ .addr = @as(u32, @bitCast(raw_old_path_ptr)) };
    const old_path_len: u32 = @bitCast(raw_old_path_len);
    const new_path_ptr = pointer.ConstPointer(u8){ .addr = @as(u32, @bitCast(raw_new_path_ptr)) };
    const new_path_len: u32 = @bitCast(raw_new_path_len);

    std.log.debug(
        "path_rename({[old_fd]d}, {[old_path_ptr]f}, {[old_path_len]d}, {[new_fd]d}, " ++
            "{[new_path_ptr]f}, {[new_path_len]d})",
        .{
            .old_fd = @as(u32, @bitCast(raw_old_fd)),
            .old_path_ptr = old_path_ptr,
            .old_path_len = old_path_len,
            .new_fd = @as(u32, @bitCast(raw_new_fd)),
            .new_path_ptr = new_path_ptr,
            .new_path_len = new_path_len,
        },
    );

    const old_fd = Fd.initRaw(raw_old_fd) catch |e| return .mapError(e);
    const new_fd = Fd.initRaw(raw_new_fd) catch |e| return .mapError(e);
    const old_file = wasi.fd_table.get(old_fd) catch |e| return .mapError(e);
    wasi.fd_table.unlockTable();
    const new_file = wasi.fd_table.get(new_fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    const old_path = pointer.ConstSlice(u8).init(mem, old_path_ptr, old_path_len) catch |e|
        return .mapError(e);
    const new_path = pointer.ConstSlice(u8).init(mem, new_path_ptr, new_path_len) catch |e|
        return .mapError(e);

    _ = old_file;
    _ = new_file;
    _ = old_path;
    _ = new_path;

    return Errno.nosys; // TODO: path_rename implementation, two FD's? How daring...
}

fn path_symlink(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_old_path_ptr: i32,
    raw_old_path_len: i32,
    raw_fd: i32,
    raw_new_path_ptr: i32,
    raw_new_path_len: i32,
) Errno {
    const old_path_ptr = pointer.ConstPointer(u8){ .addr = @as(u32, @bitCast(raw_old_path_ptr)) };
    const old_path_len: u32 = @bitCast(raw_old_path_len);
    const new_path_ptr = pointer.ConstPointer(u8){ .addr = @as(u32, @bitCast(raw_new_path_ptr)) };
    const new_path_len: u32 = @bitCast(raw_new_path_len);

    std.log.debug(
        "path_symlink({[old_path_ptr]f}, {[old_path_len]d}, {[fd]d}, {[new_path_ptr]f}, " ++
            "{[new_path_len]d})",
        .{
            .old_path_ptr = old_path_ptr,
            .old_path_len = old_path_len,
            .fd = @as(u32, @bitCast(raw_fd)),
            .new_path_ptr = new_path_ptr,
            .new_path_len = new_path_len,
        },
    );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    const old_path = pointer.ConstSlice(u8).init(mem, old_path_ptr, old_path_len) catch |e|
        return .mapError(e);
    const new_path = pointer.ConstSlice(u8).init(mem, new_path_ptr, new_path_len) catch |e|
        return .mapError(e);

    file.path_symlink(old_path.bytes(), new_path.bytes()) catch |e| return .mapError(e);

    return .success;
}

fn path_unlink_file(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_path_ptr: i32,
    raw_path_len: i32,
) Errno {
    const path_ptr = pointer.ConstPointer(u8){ .addr = @as(u32, @bitCast(raw_path_ptr)) };
    const path_len: u32 = @bitCast(raw_path_len);

    std.log.debug(
        "path_unlink_file({d}, {f}, {d})",
        .{ @as(u32, @bitCast(raw_fd)), path_ptr, path_len },
    );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    const path = pointer.ConstSlice(u8).init(mem, path_ptr, path_len) catch |e|
        return .mapError(e);

    file.path_unlink_file(path.bytes()) catch |e| return .mapError(e);

    return .success;
}

/// Concurrently poll for the occurrence of a set of events.
///
/// Returns the number of events stored.
///
/// If nsubscriptions is 0, returns `Errno.inval`.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#poll_oneoff
fn poll_oneoff(
    wasi: *WasiPreview1,
    mem: *MemInst,
    /// The events to which to subscribe.
    raw_in: i32,
    /// The events that have occurred.
    raw_out: i32,
    /// Both the number of subscriptions and events.
    raw_nsubscriptions: i32,
    raw_ret: i32,
) Errno {
    const in_ptr = pointer.ConstPointer(types.Subscription){ .addr = @as(u32, @bitCast(raw_in)) };
    const out_ptr = pointer.Pointer(types.Event){ .addr = @as(u32, @bitCast(raw_out)) };
    const num_subscriptions: types.Size = @bitCast(raw_nsubscriptions);
    const ret_ptr = pointer.Pointer(types.Size){ .addr = @as(u32, @bitCast(raw_ret)) };

    std.log.debug("poll_oneoff({f}, {f}, {d})", .{ in_ptr, out_ptr, num_subscriptions });

    if (num_subscriptions == 0) {
        return Errno.inval;
    }

    const subscriptions = pointer.ConstSlice(types.Subscription).init(
        mem,
        in_ptr,
        num_subscriptions,
    ) catch |e| return .mapError(e);

    const events = pointer.Slice(types.Event).init(mem, out_ptr, num_subscriptions) catch |e|
        return .mapError(e);

    if (true) {
        return .nosys;
    }

    _ = wasi;
    _ = subscriptions;
    _ = events;

    ret_ptr.write(mem, 0xFFFF_FFFF) catch |e| return .mapError(e);

    return .success;
}

// `proc_exit` handled in `dispatch()`

fn proc_raise(
    _: *WasiPreview1,
    _: *MemInst,
    /// The signal condition to trigger.
    raw_sig: i32,
) Errno {
    const sig_casted = std.enums.fromInt(types.Signal, raw_sig);

    std.log.debug(
        "proc_raise({d} ({s}))",
        .{ raw_sig, if (sig_casted) |s| @tagName(s) else "???" },
    );

    if (sig_casted == null) {
        return Errno.inval;
    }

    // Basically no one supports this function.
    // https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/README.md
    return Errno.nosys;
}

// `sched_yield` handled in `dispatch()`.

fn random_get(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_buf_ptr: i32,
    raw_buf_len: i32,
) Errno {
    const buf_ptr = pointer.Pointer(u8){ .addr = @bitCast(raw_buf_ptr) };
    const buf_len: u32 = @bitCast(raw_buf_len);

    std.log.debug("random_get({f}, {d})", .{ buf_ptr, buf_len });

    const buf = pointer.Slice(u8).init(mem, buf_ptr, buf_len) catch |e| return .mapError(e);

    wasi.csprng.get(buf.bytes()) catch |e| return .mapError(e);

    return .success;
}

fn typedSockAccept(
    wasi: *WasiPreview1,
    socket_fd: Fd,
    flags: types.FdFlags.Valid,
) !Fd {
    const new_fd = try wasi.fd_table.create(wasi.allocator);
    wasi.fd_table.unlockTable();
    errdefer {
        std.debug.assert(wasi.fd_table.removeWithoutClosing(new_fd.fd));
    }
    const socket = try wasi.fd_table.get(socket_fd);
    defer wasi.fd_table.unlockTable();

    new_fd.file.* = try socket.sock_accept(flags);
    return new_fd.fd;
}

fn sock_accept(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_flags: i32,
    raw_ret: i32,
) Errno {
    const flags_param: types.FdFlags.Param = @bitCast(raw_flags);
    const ret_fd_ptr = pointer.Pointer(u32){ .addr = @as(u32, @bitCast(raw_ret)) };

    std.log.debug(
        "sock_accept({d}, {f}, {f})",
        .{ @as(u32, @bitCast(raw_fd)), flags_param, ret_fd_ptr },
    );

    const flags = flags_param.validate() orelse return Errno.inval;
    const socket_fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);

    const ret_fd_bytes = ret_fd_ptr.access(mem) catch |e| return .mapError(e);
    const new_fd = wasi.typedSockAccept(socket_fd, flags) catch |e| return .mapError(e);
    pointer.writeToBytes(u32, ret_fd_bytes, @bitCast(new_fd));
    return .success;
}

fn sock_recv(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_iovs: i32,
    raw_iovs_len: i32,
    raw_flags: i32,
    raw_ret_size: i32,
    raw_ret_flags: i32,
) Errno {
    const iovs_ptr = pointer.ConstPointer(Iovec){ .addr = @bitCast(raw_iovs) };
    const iovs_len: u32 = @bitCast(raw_iovs_len);
    const flags_param: types.RiFlags.Param = @bitCast(raw_flags);
    const ret_size = pointer.Pointer(types.Size){ .addr = @as(u32, @bitCast(raw_ret_size)) };
    const ret_flags = pointer.Pointer(types.RoFlags){ .addr = @as(u32, @bitCast(raw_ret_flags)) };

    std.log.debug(
        "sock_recv({d}, {f}, {d}, {f}, {f}, {f})",
        .{ @as(u32, @bitCast(raw_fd)), iovs_ptr, iovs_len, flags_param, ret_size, ret_flags },
    );

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const socket = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    const ri_flags = flags_param.validate() orelse return .inval;

    var scratch = wasi.acquireScratch();
    defer wasi.releaseScratch(scratch);

    const iovs = Iovs.init(mem, iovs_ptr, iovs_len, &scratch) catch |e| return .mapError(e);

    const result = socket.sock_recv(iovs.list, iovs.total_len, ri_flags) catch |e|
        return .mapError(e);

    ret_size.write(mem, result.len) catch |e| return .mapError(e);
    ret_flags.write(mem, result.flags) catch |e| return .mapError(e);

    return .success;
}

fn sock_send(
    wasi: *WasiPreview1,
    mem: *MemInst,
    raw_fd: i32,
    raw_iovs: i32,
    raw_iovs_len: i32,
    /// Message flags (`siflags`). No flags are defined so this must be set to zero.
    raw_flags: i32,
    raw_ret: i32,
) Errno {
    const iovs_ptr = pointer.ConstPointer(Ciovec){ .addr = @bitCast(raw_iovs) };
    const iovs_len: u32 = @bitCast(raw_iovs_len);
    const flags: u32 = @bitCast(raw_flags);
    const ret_ptr = pointer.Pointer(types.Size){ .addr = @as(u32, @bitCast(raw_ret)) };

    std.log.debug(
        "sock_send({d}, {f}, {d}, 0x{X}, {f})\n",
        .{ @as(u32, @bitCast(raw_fd)), iovs_ptr, iovs_len, flags, ret_ptr },
    );

    if (flags != 0) {
        return Errno.inval;
    }

    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    var scratch = wasi.acquireScratch();
    defer wasi.releaseScratch(scratch);

    const ciovs = Ciovs.init(mem, iovs_ptr, iovs_len, &scratch) catch |e| return .mapError(e);

    ret_ptr.write(
        mem,
        file.sock_send(ciovs.list, ciovs.total_len) catch |e| return .mapError(e),
    ) catch |e| return .mapError(e);

    return .success;
}

fn sock_shutdown(
    wasi: *WasiPreview1,
    _: *MemInst,
    raw_fd: i32,
    raw_flags: i32,
) Errno {
    const flags_param: types.SdFlags.Param = @bitCast(raw_flags);

    std.log.debug("sock_shutdown({d}, {f})", .{ @as(u32, @bitCast(raw_fd)), flags_param });

    const flags = flags_param.validate() orelse return Errno.inval;
    const fd = Fd.initRaw(raw_fd) catch |e| return .mapError(e);
    const file = wasi.fd_table.get(fd) catch |e| return .mapError(e);
    defer wasi.fd_table.unlockTable();

    file.sock_shutdown(flags) catch |e| return .mapError(e);
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
            // rval - The exit code returned by the process.
            const exit_code = state.paramsTyped(struct { i32 }) catch unreachable;
            // std.log.debug("proc_exit({})", .{exit_code});
            return .{ .proc_exit = exit_code[0] };
        },
        .sched_yield => {
            // Could pass control to host instead (new DispatchResult case)
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
        .clock_res_get,
        .clock_time_get,
        .fd_advise,
        .fd_allocate,
        .fd_close,
        .fd_datasync,
        .fd_fdstat_get,
        .fd_fdstat_set_flags,
        .fd_fdstat_set_rights,
        .fd_filestat_get,
        .fd_filestat_set_size,
        .fd_filestat_set_times,
        .fd_pread,
        .fd_prestat_get,
        .fd_prestat_dir_name,
        .fd_pwrite,
        .fd_read,
        .fd_readdir,
        .fd_renumber,
        .fd_seek,
        .fd_sync,
        .fd_tell,
        .fd_write,
        .path_create_directory,
        .path_filestat_get,
        .path_filestat_set_times,
        .path_link,
        .path_open,
        .path_readlink,
        .path_remove_directory,
        .path_rename,
        .path_symlink,
        .path_unlink_file,
        .poll_oneoff,
        .proc_raise,
        .random_get,
        .sock_accept,
        .sock_recv,
        .sock_send,
        .sock_shutdown,
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
