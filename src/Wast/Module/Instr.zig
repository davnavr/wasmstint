const IndexedArena = @import("../../IndexedArena.zig");

const sexpr = @import("../sexpr.zig");
const Error = sexpr.Error;

const Ident = @import("../Ident.zig");
const Name = @import("../Name.zig");
const Caches = @import("../Caches.zig");

const Instr = @This();

/// For most instructions, this is the `atom` corresponding to the keyword.
///
/// For implicit `end` instuctions in folded instructions, this refers to the list
/// corresponding to the folded instruction.
keyword: sexpr.Value,
args: Args,

pub const Args = union {
    none: void,
    end: Ident,
    @"local.get": Ident, // Rename to ident
    @"i32.const": i32,
    @"i64.const": i64, // Make this an idx?
    f32: u32,
    f64: u64,
};

// comptime {
//     std.debug.assert(@alignOf(Instr) == @alignOf(u32));
//     std.debug.assert(@sizeOf(Instr) == switch (@import("builtin").mode) {
//         .Debug, .ReleaseSafe => 16,
//         .ReleaseFast, .ReleaseSmall => 16,
//     });
// }

pub fn parseArgs(
    keyword: sexpr.TokenId,
    contents: *sexpr.Parser,
    tree: *const sexpr.Tree,
    parent: sexpr.List.Id,
    arena: *IndexedArena,
    caches: *Caches,
    errors: *Error.List,
) error{OutOfMemory}!sexpr.Parser.Result(Instr) {
    _ = arena;
    const args: Args = args: switch (keyword.tag(tree)) {
        .keyword_nop,
        .keyword_unreachable,
        .keyword_drop,
        .@"keyword_i32.eqz",
        .@"keyword_i32.eq",
        .@"keyword_i32.ne",
        .@"keyword_i32.lt_s",
        .@"keyword_i32.lt_u",
        .@"keyword_i32.gt_s",
        .@"keyword_i32.gt_u",
        .@"keyword_i32.le_s",
        .@"keyword_i32.le_u",
        .@"keyword_i32.ge_s",
        .@"keyword_i32.ge_u",
        .@"keyword_i64.eqz",
        .@"keyword_i64.eq",
        .@"keyword_i64.ne",
        .@"keyword_i64.lt_s",
        .@"keyword_i64.lt_u",
        .@"keyword_i64.gt_s",
        .@"keyword_i64.gt_u",
        .@"keyword_i64.le_s",
        .@"keyword_i64.le_u",
        .@"keyword_i64.ge_s",
        .@"keyword_i64.ge_u",
        .@"keyword_f32.eq",
        .@"keyword_f32.ne",
        .@"keyword_f32.lt",
        .@"keyword_f32.gt",
        .@"keyword_f32.le",
        .@"keyword_f32.ge",
        .@"keyword_f64.eq",
        .@"keyword_f64.ne",
        .@"keyword_f64.lt",
        .@"keyword_f64.gt",
        .@"keyword_f64.le",
        .@"keyword_f64.ge",
        .@"keyword_i32.clz",
        .@"keyword_i32.ctz",
        .@"keyword_i32.popcnt",
        .@"keyword_i32.add",
        .@"keyword_i32.sub",
        .@"keyword_i32.mul",
        .@"keyword_i32.div_s",
        .@"keyword_i32.div_u",
        .@"keyword_i32.rem_s",
        .@"keyword_i32.rem_u",
        .@"keyword_i32.and",
        .@"keyword_i32.or",
        .@"keyword_i32.xor",
        .@"keyword_i32.shl",
        .@"keyword_i32.shr_s",
        .@"keyword_i32.shr_u",
        .@"keyword_i32.rotl",
        .@"keyword_i32.rotr",
        .@"keyword_i64.clz",
        .@"keyword_i64.ctz",
        .@"keyword_i64.popcnt",
        .@"keyword_i64.add",
        .@"keyword_i64.sub",
        .@"keyword_i64.mul",
        .@"keyword_i64.div_s",
        .@"keyword_i64.div_u",
        .@"keyword_i64.rem_s",
        .@"keyword_i64.rem_u",
        .@"keyword_i64.and",
        .@"keyword_i64.or",
        .@"keyword_i64.xor",
        .@"keyword_i64.shl",
        .@"keyword_i64.shr_s",
        .@"keyword_i64.shr_u",
        .@"keyword_i64.rotl",
        .@"keyword_i64.rotr",
        .@"keyword_f32.abs",
        .@"keyword_f32.neg",
        .@"keyword_f32.ceil",
        .@"keyword_f32.floor",
        .@"keyword_f32.trunc",
        .@"keyword_f32.nearest",
        .@"keyword_f32.sqrt",
        .@"keyword_f32.add",
        .@"keyword_f32.sub",
        .@"keyword_f32.mul",
        .@"keyword_f32.div",
        .@"keyword_f32.min",
        .@"keyword_f32.max",
        .@"keyword_f32.copysign",
        .@"keyword_f64.abs",
        .@"keyword_f64.neg",
        .@"keyword_f64.ceil",
        .@"keyword_f64.floor",
        .@"keyword_f64.trunc",
        .@"keyword_f64.nearest",
        .@"keyword_f64.sqrt",
        .@"keyword_f64.add",
        .@"keyword_f64.sub",
        .@"keyword_f64.mul",
        .@"keyword_f64.div",
        .@"keyword_f64.min",
        .@"keyword_f64.max",
        .@"keyword_f64.copysign",
        .@"keyword_i32.wrap_i64",
        .@"keyword_i32.trunc_f32_s",
        .@"keyword_i32.trunc_f32_u",
        .@"keyword_i32.trunc_f64_s",
        .@"keyword_i32.trunc_f64_u",
        .@"keyword_i64.extend_i32_s",
        .@"keyword_i64.extend_i32_u",
        .@"keyword_i64.trunc_f32_s",
        .@"keyword_i64.trunc_f32_u",
        .@"keyword_i64.trunc_f64_s",
        .@"keyword_i64.trunc_f64_u",
        .@"keyword_f32.convert_i32_s",
        .@"keyword_f32.convert_i32_u",
        .@"keyword_f32.convert_i64_s",
        .@"keyword_f32.convert_i64_u",
        .@"keyword_f32.demote_f64",
        .@"keyword_f64.convert_i32_s",
        .@"keyword_f64.convert_i32_u",
        .@"keyword_f64.convert_i64_s",
        .@"keyword_f64.convert_i64_u",
        .@"keyword_f64.promote_f32",
        .@"keyword_i32.reinterpret_f32",
        .@"keyword_i64.reinterpret_f64",
        .@"keyword_f32.reinterpret_i32",
        .@"keyword_f64.reinterpret_i64",
        .@"keyword_i32.extend8_s",
        .@"keyword_i32.extend16_s",
        .@"keyword_i64.extend8_s",
        .@"keyword_i64.extend16_s",
        .@"keyword_i64.extend32_s",
        .@"keyword_i32.trunc_sat_f32_s",
        .@"keyword_i32.trunc_sat_f32_u",
        .@"keyword_i32.trunc_sat_f64_s",
        .@"keyword_i32.trunc_sat_f64_u",
        .@"keyword_i64.trunc_sat_f32_s",
        .@"keyword_i64.trunc_sat_f32_u",
        .@"keyword_i64.trunc_sat_f64_s",
        .@"keyword_i64.trunc_sat_f64_u",
        => Args{ .none = {} },
        .@"keyword_local.get" => {
            const local = switch (try Ident.parseRequired(contents, tree, parent, caches.allocator, &caches.ids)) {
                .ok => |ok| ok,
                .err => |err| return .{ .err = err },
            };

            break :args Args{ .@"local.get" = local };
        },
        .@"keyword_i32.const" => {
            const literal: i32 = literal: switch (contents.parseUninterpretedIntegerInList(i32, parent, tree)) {
                .ok => |ok| ok.value,
                .err => |err| {
                    try errors.append(err);
                    break :literal 0;
                },
            };

            break :args Args{ .@"i32.const" = literal };
        },
        .@"keyword_i64.const" => {
            const literal: i64 = literal: switch (contents.parseUninterpretedIntegerInList(i64, parent, tree)) {
                .ok => |ok| ok.value,
                .err => |err| {
                    try errors.append(err);
                    break :literal 0;
                },
            };

            break :args Args{ .@"i64.const" = literal };
        },
        .@"keyword_f32.const" => {
            const literal: u32 = literal: switch (contents.parseFloatInList(f32, parent, tree)) {
                .ok => |ok| ok.value,
                .err => |err| {
                    try errors.append(err);
                    break :literal 0;
                },
            };

            break :args Args{ .f32 = literal };
        },
        .@"keyword_f64.const" => {
            const literal: u64 = literal: switch (contents.parseFloatInList(f64, parent, tree)) {
                .ok => |ok| ok.value,
                .err => |err| {
                    try errors.append(err);
                    break :literal 0;
                },
            };

            break :args Args{ .f64 = literal };
        },
        // Unknown instruction.
        else => return .{
            .err = Error.initExpectedToken(sexpr.Value.initAtom(keyword), .keyword_unknown, .at_value),
        },
    };

    return .{ .ok = Instr{ .keyword = sexpr.Value.initAtom(keyword), .args = args } };
}
