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

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#size
const Size = u32;

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#filesize
const FileSize = packed struct(u64) { bytes: u64 };

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#timestamp
const Timestamp = packed struct(u64) { ns: u64 };

/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#clockid
const ClockId = enum(u32) {
    /// The clock measuring real time. Time value zero corresponds with `1970-01-01T00:00:00Z`.
    realtime,
    /// The store-wide monotonic clock, which is defined as a clock measuring real time, whose
    /// value cannot be adjusted and which cannot have negative clock jumps.
    ///
    /// The epoch of this clock is undefined. The absolute time value of this clock therefore has
    /// no meaning.
    monotonic,

    // Apparently these were never widely supported

    /// The CPU-time clock associated with the current process.
    process_cputime_id,
    /// The CPU-time clock associated with the current thread.
    thread_cputime_id,
    _,
};

pub const Errno = @import("WasiPreview1/errno.zig").Errno;

const Fd = @import("WasiPreview1/fd.zig").Fd;

fn Pointer(comptime T: type) type {
    return packed struct(u32) {
        addr: u32,

        const Pointee = T;
        const Ptr = @This();
        const Const = ConstPointer(T);

        fn toConst(ptr: Ptr) Const {
            return .{ .addr = ptr.addr };
        }
    };
}

/// A region of memory for scatter/gather **reads**.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#iovec
const Iovec = extern struct {
    /// The address of the buffer to be filled.
    buf: Pointer(u8),
    /// The length of the buffer to be filled.
    buf_len: Size,
};

fn ConstPointer(comptime T: type) type {
    return packed struct(u32) {
        addr: u32,

        const Pointee = T;
    };
}

/// A region of memory for scatter/gather **writes**.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#ciovec
const Ciovec = extern struct {
    /// The address of the buffer to be written.
    buf: ConstPointer(u8),
    /// The length of the buffer to be written.
    buf_len: Size,

    //const List // TODO: have an iterator type, yields slices and does MemInst bounds checks
};

// TODO: Add more WASI API types

const File = @import("WasiPreview1/File.zig");

pub const Csprng = @import("WasiPreview1/Csprng.zig");

pub const Api = enum {
    // args_get,
    // args_sizes_get,

    fd_filestat_get,

    fd_pwrite,
    fd_read,

    fd_seek,

    fd_write,

    proc_exit,

    pub fn signature(api: Api) Module.FuncType {
        const result: []const Module.ValType = &.{.i32};
        return switch (api) {
            .fd_filestat_get => .initComptime(&.{ .i32, .i32 }, result),

            .fd_pwrite => .initComptime(&.{ .i32, .i32, .i32, .i64, .i32 }, result),
            .fd_read, .fd_write => .initComptime(&.{ .i32, .i32, .i32, .i32 }, result),

            .fd_seek => .initComptime(&.{ .i32, .i64, .i32, .i32 }, result),

            .proc_exit => .initComptime(&.{.i32}, &.{}),
        };
    }

    fn ValTypeType(comptime ty: Module.ValType) type {
        return switch (ty) {
            .i32,
            .i64,
            .f32,
            .f64,
            .funcref,
            .externref,
            => |tag| @FieldType(Interpreter.TaggedValue, @tagName(tag)),
            .v128 => unreachable,
        };
    }

    fn ParamTuple(comptime api: Api) type {
        const params = api.signature().parameters();
        var field_types: [params.len]type = undefined;
        for (&field_types, params) |*dst, ty| {
            dst.* = ValTypeType(ty);
        }

        return std.meta.Tuple(&field_types);
    }

    fn taggedValuesToParamTuple(
        comptime api: Api,
        src: []const Interpreter.TaggedValue,
    ) ParamTuple(api) {
        var tuple: ParamTuple(api) = undefined;
        inline for (0.., comptime api.signature().parameters()) |i, ty| {
            tuple[i] = @field(src[i], @tagName(ty));
        }
        return tuple;
    }

    pub fn name(api: Api) Module.Name {
        return switch (api) {
            inline else => |tag| comptime .init(@tagName(tag)),
        };
    }

    const all = std.enums.values(Api);

    const min_name_len: comptime_int = max: {
        var len = std.math.maxInt(u16);
        for (all) |api| {
            len = @min(len, api.name().len);
        }
        break :max len;
    };

    const max_name_len: comptime_int = max: {
        var len = 0;
        for (all) |api| {
            len = @max(len, api.name().len);
        }
        break :max len;
    };

    const host_func_table: [all.len]wasmstint.runtime.FuncAddr.Host = table: {
        var host_funcs: [all.len]wasmstint.runtime.FuncAddr.Host = undefined;
        for (&host_funcs, all) |*dst, api| {
            dst.* = .{ .signature = api.signature() };
        }
        break :table host_funcs;
    };

    fn fromHostFunc(ptr: *const wasmstint.runtime.FuncAddr.Host) Api {
        return @enumFromInt(
            ptr - @as([]const wasmstint.runtime.FuncAddr.Host, &host_func_table).ptr,
        );
    }

    fn hostFunc(api: Api) *const wasmstint.runtime.FuncAddr.Host {
        return &host_func_table[@intFromEnum(api)];
    }

    comptime {
        for (all) |api| {
            std.debug.assert(api.hostFunc().signature.matches(&api.signature()));
        }
    }

    const Lookup = struct {
        map: std.HashMapUnmanaged(
            Api,
            void,
            InitContext,
            std.hash_map.default_max_load_percentage,
        ),
        hash_seed: u64,

        const GetContext = struct {
            hash_seed: u64,

            pub fn hash(ctx: GetContext, function_name: Module.Name) u64 {
                std.debug.assert(min_name_len <= function_name.len);
                std.debug.assert(function_name.len <= max_name_len);
                return @call(
                    .always_inline,
                    std.hash.XxHash3.hash,
                    .{ ctx.hash_seed, function_name.bytes() },
                );
            }

            pub fn eql(ctx: GetContext, function_name: Module.Name, api: Api) bool {
                _ = ctx;
                const api_name = api.name();
                std.debug.assert(min_name_len <= api_name.len);
                std.debug.assert(api_name.len <= max_name_len);
                std.debug.assert(min_name_len <= function_name.len);
                std.debug.assert(function_name.len <= max_name_len);
                return std.mem.eql(u8, api_name.bytes(), function_name.bytes());
            }
        };

        const InitContext = struct {
            hash_seed: u64,

            pub fn hash(ctx: InitContext, a: Api) u64 {
                return GetContext.hash(.{ .hash_seed = ctx.hash_seed }, a.name());
            }

            pub fn eql(ctx: InitContext, x: Api, y: Api) bool {
                _ = ctx;
                return x == y;
            }
        };

        fn init(allocator: Allocator, hash_seed: u64) Allocator.Error!Lookup {
            var lookup = Lookup{ .map = .empty, .hash_seed = hash_seed };
            const ctx = InitContext{ .hash_seed = hash_seed };
            try lookup.map.ensureTotalCapacityContext(allocator, all.len, ctx);
            errdefer comptime unreachable;
            for (all) |api| {
                lookup.map.putAssumeCapacityNoClobberContext(api, {}, ctx);
            }

            std.debug.assert(lookup.map.size == all.len);
            return lookup;
        }

        fn get(lookup: *const Lookup, function_name: Module.Name) ?Api {
            return if (function_name.len > max_name_len or function_name.len < min_name_len)
                null
            else
                lookup.map.getKeyAdapted(
                    function_name,
                    GetContext{ .hash_seed = lookup.hash_seed },
                );
        }

        fn deinit(lookup: *Lookup, allocator: Allocator) void {
            lookup.map.deinit(allocator);
            lookup.* = undefined;
        }
    };
};

allocator: Allocator,
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

/// Command-line argument data to pass to the application.
///
/// Obtained by calling `args_sizes_get` and `args_get`.
pub const Arguments = struct {
    ptr: [*]const String,
    count: u32,
    /// Total size, in bytes, of all argument data.
    ///
    /// TODO: Probably includes null-terminators too.
    size: u32,

    pub fn applicationName(name: *const String) Arguments {
        return .{
            .ptr = name[0..1].ptr,
            .count = 1,
            .size = name.len() + 1,
        };
    }

    pub const String = struct {
        /// Invariant that `chars.len <= max_len`.
        ///
        /// `Char` guarantees no null-terminators are present.
        chars: []const Char,

        pub const max_len = std.math.maxInt(u32) - 1;

        /// Takes a slice of the given bytes up to the first encountered null-terminator (`\x00`),
        /// and truncates the length up to `max_len`.
        pub fn initTruncated(s: []const u8) String {
            const null_terminated = std.mem.sliceTo(s[0..@min(max_len, s.len)], 0);
            return .{ .chars = @ptrCast(null_terminated) };
        }

        pub fn len(s: String) u32 {
            return @intCast(s.chars.len);
        }

        pub fn bytes(s: String) []const u8 {
            _ = s.len();
            return @ptrCast(s.chars);
        }

        pub fn format(s: String, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            return writer.writeAll(s.bytes());
        }

        // pub fn formatEscaped(s: String, writer: *std.Io.Writer) std.Io.Writer.Error!void {}
    };
};

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

// Note handlers here can just use `Errno.fault`, which is nice since `AwaitingHost` doesn't
// support trapping yet.

fn fd_write(
    wasi: *WasiPreview1,
    memory: *MemInst,
    raw_fd: i32,
    raw_iovs: i32,
    raw_iovs_len: i32,
    raw_ret: i32,
) Errno {
    const fd = Fd.initRaw(raw_fd) catch |e| switch (e) {
        error.BadFd => return .badf,
    };
    _ = wasi;
    _ = memory;
    std.debug.print(
        "TODO: fd_write({f}, 0x{X}, 0x{X}, 0x{X})\n",
        .{
            fd,
            @as(u32, @bitCast(raw_iovs)),
            @as(u32, @bitCast(raw_iovs_len)),
            @as(u32, @bitCast(raw_ret)),
        },
    );
    return .nosys;
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
        inline .fd_write => |id| {
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
    state.* = undefined;
}

const std = @import("std");
const Allocator = std.mem.Allocator;
const wasmstint = @import("wasmstint");
const Interpreter = wasmstint.Interpreter;
const MemInst = wasmstint.runtime.MemInst;
const Module = wasmstint.Module;

test {
    _ = WasiPreview1;
}
