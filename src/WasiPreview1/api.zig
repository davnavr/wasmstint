pub const Api = enum {
    args_get,
    args_sizes_get,
    environ_get,
    environ_sizes_get,
    clock_res_get,
    clock_time_get,
    fd_advise,
    fd_allocate,
    fd_close,
    fd_datasync,
    fd_fdstat_get,
    fd_fdstat_set_flags,
    fd_fdstat_set_rights,
    fd_filestat_get,
    fd_filestat_set_size,
    fd_filestat_set_times,
    fd_pread,
    fd_prestat_get,
    fd_prestat_dir_name,
    fd_pwrite,
    fd_read,
    fd_readdir,
    fd_renumber,
    fd_seek,
    fd_sync,
    fd_tell,
    fd_write,
    path_create_directory,
    path_filestat_get,
    path_filestat_set_times,
    path_link,
    path_open,
    path_readlink,
    path_remove_directory,
    path_rename,
    path_symlink,
    path_unlink_file,
    poll_oneoff,
    /// Terminate the process normally.
    ///
    /// An exit code of 0 indicates successful termination of the program. The meanings of other
    /// values is dependent on the environment.
    proc_exit,
    proc_raise,
    /// Temporarily yield execution of the calling thread.
    ///
    /// This is similar to `sched_yield` in POSIX.
    sched_yield,
    random_get,
    sock_accept,
    sock_recv,
    sock_send,
    sock_shutdown,

    // /// https://github.com/WebAssembly/wasi-threads/blob/main/wasi-threads.abi.md
    // @"thread-spawn", // in "wasi" module, not "wasi_snapshot_preview1"

    fn returnsErrno(comptime params: []const Module.ValType) Module.FuncType {
        return .initComptime(params, &.{.i32});
    }

    pub fn signature(api: Api) Module.FuncType {
        return switch (api) {
            .args_get,
            .args_sizes_get,
            .environ_get,
            .environ_sizes_get,
            .clock_res_get,
            .fd_fdstat_get,
            .fd_fdstat_set_flags,
            .fd_filestat_get,
            .fd_prestat_get,
            .fd_renumber,
            .fd_tell,
            .random_get,
            .sock_shutdown,
            => returnsErrno(&.{ .i32, .i32 }),
            .clock_time_get => returnsErrno(&.{ .i32, .i64, .i32 }),
            .fd_advise,
            .fd_filestat_set_times,
            => returnsErrno(&.{ .i32, .i64, .i64, .i32 }),
            .fd_allocate,
            .fd_fdstat_set_rights,
            => returnsErrno(&.{ .i32, .i64, .i64 }),
            .fd_filestat_set_size => returnsErrno(&.{ .i32, .i64 }),
            .fd_close,
            .fd_datasync,
            .fd_sync,
            .proc_raise,
            => returnsErrno(&.{.i32}),
            .fd_prestat_dir_name,
            .path_create_directory,
            .path_remove_directory,
            .path_unlink_file,
            .sock_accept,
            => returnsErrno(&.{ .i32, .i32, .i32 }),
            .fd_pread,
            .fd_pwrite,
            .fd_readdir,
            => returnsErrno(&.{ .i32, .i32, .i32, .i64, .i32 }),
            .fd_read,
            .fd_write,
            .poll_oneoff,
            => returnsErrno(&.{ .i32, .i32, .i32, .i32 }),
            .fd_seek => returnsErrno(&.{ .i32, .i64, .i32, .i32 }),
            .path_filestat_get,
            .path_symlink,
            .sock_send,
            => returnsErrno(&.{ .i32, .i32, .i32, .i32, .i32 }),
            .path_filestat_set_times => returnsErrno(
                &.{ .i32, .i32, .i32, .i32, .i64, .i64, .i32 },
            ),
            .path_link => returnsErrno(
                &.{ .i32, .i32, .i32, .i32, .i32, .i32, .i32 },
            ),
            .path_open => returnsErrno(
                &.{ .i32, .i32, .i32, .i32, .i32, .i64, .i64, .i32, .i32 },
            ),
            .path_readlink,
            .path_rename,
            .sock_recv,
            => returnsErrno(&.{ .i32, .i32, .i32, .i32, .i32, .i32 }),

            .proc_exit => .initComptime(&.{.i32}, &.{}),
            .sched_yield => returnsErrno(&.{}),
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
            => |tag| @FieldType(wasmstint.Interpreter.TaggedValue, @tagName(tag)),
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

    pub fn taggedValuesToParamTuple(
        comptime api: Api,
        src: []const wasmstint.Interpreter.TaggedValue,
    ) ParamTuple(api) {
        var tuple: ParamTuple(api) = undefined;
        inline for (0.., comptime api.signature().parameters()) |i, ty| {
            tuple[i] = @field(src[i], @tagName(ty));
        }
        return tuple;
    }

    pub fn name(api: Api) Module.Name {
        return Module.Name.init(@tagName(api));
    }

    const all = std.enums.values(Api);

    const min_name_len: comptime_int = max: {
        @setEvalBranchQuota(3000);
        var len = std.math.maxInt(u16);
        for (all) |api| {
            len = @min(len, api.name().len);
        }
        break :max len;
    };

    const max_name_len: comptime_int = max: {
        @setEvalBranchQuota(3000);
        var len = 0;
        for (all) |api| {
            len = @max(len, api.name().len);
        }
        break :max len;
    };

    const host_func_table: [all.len]wasmstint.runtime.HostFunc = table: {
        var host_funcs: [all.len]wasmstint.runtime.HostFunc = undefined;
        for (&host_funcs, all) |*dst, api| {
            dst.* = .{ .signature = api.signature() };
        }
        break :table host_funcs;
    };

    pub fn fromHostFunc(ptr: *const wasmstint.runtime.HostFunc) Api {
        return @enumFromInt(
            ptr - @as([]const wasmstint.runtime.HostFunc, &host_func_table).ptr,
        );
    }

    pub fn hostFunc(api: Api) *const wasmstint.runtime.HostFunc {
        return &host_func_table[@intFromEnum(api)];
    }

    comptime {
        for (all) |api| {
            std.debug.assert(api.hostFunc().signature.matches(&api.signature()));
        }
    }

    pub const Lookup = struct {
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

        pub fn init(allocator: Allocator, hash_seed: u64) Allocator.Error!Lookup {
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

        pub fn get(lookup: *const Lookup, function_name: Module.Name) ?Api {
            return if (function_name.len > max_name_len or function_name.len < min_name_len)
                null
            else
                lookup.map.getKeyAdapted(
                    function_name,
                    GetContext{ .hash_seed = lookup.hash_seed },
                );
        }

        pub fn deinit(lookup: *Lookup, allocator: Allocator) void {
            lookup.map.deinit(allocator);
            lookup.* = undefined;
        }
    };
};

const std = @import("std");
const Allocator = std.mem.Allocator;
const wasmstint = @import("wasmstint");
const Module = wasmstint.Module;
