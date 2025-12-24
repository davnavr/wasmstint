const ImportProvider = @This();

/// Used to indicate the type of value the module is expecting.
pub const Desc = union(std.meta.FieldEnum(Module.Export.Desc)) {
    func: *const Module.FuncType,
    table: *const Module.TableType,
    mem: *const Module.MemType,
    global: *const Module.GlobalType,

    pub fn format(desc: *const Desc, writer: *Writer) Writer.Error!void {
        try writer.writeByte('(');
        switch (desc.*) {
            .func => |func| {
                try writer.writeAll("func");
                if (func.param_count > 0 or func.result_count > 0) {
                    try writer.writeByte(' ');
                }

                try func.format(writer);
            },
            .table => |table| try writer.print("table {f}", .{table}),
            .mem => |mem| try writer.print("memory {f}", .{mem}),
            .global => |global| try writer.print("global {f}", .{global}),
        }
        try writer.writeByte(')');
    }
};

ctx: *anyopaque,
/// Returns `null` to indicate that an import was unavailable or could not be provided.
resolve: *const fn (
    ctx: *anyopaque,
    module: Module.Name,
    name: Module.Name,
    desc: Desc,
) anyerror!?ExternVal,

pub const Error = error{
    /// The host did not provide an import with the given name or one with the expected type.
    ImportFailure,
};

pub const FailedRequest = struct {
    module: Module.Name,
    name: Module.Name,
    desc: Desc,
    reason: Reason,

    pub const Reason = union(enum) {
        none_provided,
        error_returned: anyerror,
        type_mismatch,
        wrong_desc,
    };

    pub fn format(info: *const FailedRequest, writer: *Writer) Writer.Error!void {
        try writer.print(
            "could not provide import (import {f} {f} {f}), ",
            .{ info.module, info.name, info.desc },
        );

        switch (info.reason) {
            .none_provided => try writer.writeAll("no value provided"),
            .type_mismatch => try writer.writeAll("type mismatch"),
            .error_returned => |err| try writer.print("error occurred: {t}", .{err}),
            .wrong_desc => try writer.writeAll("wrong kind"),
        }
    }
};

pub fn resolveTyped(
    provider: *const ImportProvider,
    module: Module.Name,
    name: Module.Name,
    comptime desc_tag: std.meta.FieldEnum(Module.Export.Desc),
    desc: @FieldType(Desc, @tagName(desc_tag)),
    failed: ?*FailedRequest,
) Error!@FieldType(ExternVal, @tagName(desc_tag)) {
    const import_desc = @unionInit(
        Desc,
        std.meta.fieldInfo(Desc, desc_tag).name,
        desc,
    );

    const reason: FailedRequest.Reason = failed_request: {
        const provided = provider.resolve(
            provider.ctx,
            module,
            name,
            import_desc,
        ) catch |e| {
            break :failed_request .{ .error_returned = e };
        } orelse {
            break :failed_request .none_provided;
        };

        switch (desc_tag) {
            .func => if (provided == .func) {
                if (!provided.func.signature().matches(desc)) {
                    break :failed_request .type_mismatch;
                }
                return provided.func;
            },
            .table => if (provided == .table) {
                if (!provided.table.tableType().matches(desc)) {
                    break :failed_request .type_mismatch;
                }
                return provided.table;
            },
            .mem => if (provided == .mem) {
                if (!provided.mem.memType().matches(desc)) {
                    break :failed_request .type_mismatch;
                }
                return provided.mem;
            },
            .global => if (provided == .global) {
                if (!provided.global.global_type.matches(desc)) {
                    break :failed_request .type_mismatch;
                }
                return provided.global;
            },
        }

        break :failed_request .wrong_desc;
    };

    if (failed) |failed_ptr| failed_ptr.* = FailedRequest{
        .module = module,
        .name = name,
        .desc = import_desc,
        .reason = reason,
    };

    return Error.ImportFailure;
}

pub const no_imports = struct {
    fn resolve(
        ctx: *anyopaque,
        module: std.unicode.Utf8View,
        name: std.unicode.Utf8View,
        desc: Desc,
    ) ?ExternVal {
        _ = ctx;
        _ = module;
        _ = name;
        _ = desc;
        return null;
    }

    pub const provider = ImportProvider{
        .ctx = undefined,
        .resolve = resolve,
    };
};

const std = @import("std");
const Writer = std.Io.Writer;
const Module = @import("../Module.zig");
const ExternVal = @import("value.zig").ExternVal;
