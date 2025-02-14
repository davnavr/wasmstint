const std = @import("std");
const meta = std.meta;

const opcodes = @This();

pub const ByteOpcode = enum(u8) {
    @"unreachable" = 0x00,
    nop = 0x01,
    block = 0x02,
    loop = 0x03,
    @"if" = 0x04,
    @"else" = 0x05,
    end = 0x0B,
    br = 0x0C,
    br_if = 0x0D,
    br_table = 0x0E,
    @"return" = 0x0F,
    call = 0x10,
    call_indirect = 0x11,

    drop = 0x1A,
    select = 0x1B,
    @"select t" = 0x1C,

    @"local.get" = 0x20,
    @"local.set" = 0x21,
    @"local.tee" = 0x22,
    @"global.get" = 0x23,
    @"global.set" = 0x24,

    @"table.get" = 0x25,
    @"table.set" = 0x26,

    @"i32.load" = 0x28,
    @"i64.load" = 0x29,
    @"f32.load" = 0x2A,
    @"f64.load" = 0x2B,
    @"i32.load8_s" = 0x2C,
    @"i32.load8_u" = 0x2D,
    @"i32.load16_s" = 0x2E,
    @"i32.load16_u" = 0x2F,
    @"i64.load8_s" = 0x30,
    @"i64.load8_u" = 0x31,
    @"i64.load16_s" = 0x32,
    @"i64.load16_u" = 0x33,
    @"i64.load32_s" = 0x34,
    @"i64.load32_u" = 0x35,
    @"i32.store" = 0x36,
    @"i64.store" = 0x37,
    @"f32.store" = 0x38,
    @"f64.store" = 0x39,
    @"i32.store8" = 0x3A,
    @"i32.store16" = 0x3B,
    @"i64.store8" = 0x3C,
    @"i64.store16" = 0x3D,
    @"i64.store32" = 0x3E,
    @"memory.size" = 0x3F,
    @"memory.grow" = 0x40,

    @"i32.const" = 0x41,
    @"i64.const" = 0x42,
    @"f32.const" = 0x43,
    @"f64.const" = 0x44,

    @"i32.eqz" = 0x45,
    @"i32.eq" = 0x46,
    @"i32.ne" = 0x47,
    @"i32.lt_s" = 0x48,
    @"i32.lt_u" = 0x49,
    @"i32.gt_s" = 0x4A,
    @"i32.gt_u" = 0x4B,
    @"i32.le_s" = 0x4C,
    @"i32.le_u" = 0x4D,
    @"i32.ge_s" = 0x4E,
    @"i32.ge_u" = 0x4F,

    @"i64.eqz" = 0x50,
    @"i64.eq" = 0x51,
    @"i64.ne" = 0x52,
    @"i64.lt_s" = 0x53,
    @"i64.lt_u" = 0x54,
    @"i64.gt_s" = 0x55,
    @"i64.gt_u" = 0x56,
    @"i64.le_s" = 0x57,
    @"i64.le_u" = 0x58,
    @"i64.ge_s" = 0x59,
    @"i64.ge_u" = 0x5A,

    @"f32.eq" = 0x5B,
    @"f32.ne" = 0x5C,
    @"f32.lt" = 0x5D,
    @"f32.gt" = 0x5E,
    @"f32.le" = 0x5F,
    @"f32.ge" = 0x60,

    @"f64.eq" = 0x61,
    @"f64.ne" = 0x62,
    @"f64.lt" = 0x63,
    @"f64.gt" = 0x64,
    @"f64.le" = 0x65,
    @"f64.ge" = 0x66,

    @"i32.clz" = 0x67,
    @"i32.ctz" = 0x68,
    @"i32.popcnt" = 0x69,
    @"i32.add" = 0x6A,
    @"i32.sub" = 0x6B,
    @"i32.mul" = 0x6C,
    @"i32.div_s" = 0x6D,
    @"i32.div_u" = 0x6E,
    @"i32.rem_s" = 0x6F,
    @"i32.rem_u" = 0x70,
    @"i32.and" = 0x71,
    @"i32.or" = 0x72,
    @"i32.xor" = 0x73,
    @"i32.shl" = 0x74,
    @"i32.shr_s" = 0x75,
    @"i32.shr_u" = 0x76,
    @"i32.rotl" = 0x77,
    @"i32.rotr" = 0x78,

    @"i64.clz" = 0x79,
    @"i64.ctz" = 0x7A,
    @"i64.popcnt" = 0x7B,
    @"i64.add" = 0x7C,
    @"i64.sub" = 0x7D,
    @"i64.mul" = 0x7E,
    @"i64.div_s" = 0x7F,
    @"i64.div_u" = 0x80,
    @"i64.rem_s" = 0x81,
    @"i64.rem_u" = 0x82,
    @"i64.and" = 0x83,
    @"i64.or" = 0x84,
    @"i64.xor" = 0x85,
    @"i64.shl" = 0x86,
    @"i64.shr_s" = 0x87,
    @"i64.shr_u" = 0x88,
    @"i64.rotl" = 0x89,
    @"i64.rotr" = 0x8A,

    @"f32.abs" = 0x8B,
    @"f32.neg" = 0x8C,
    @"f32.ceil" = 0x8D,
    @"f32.floor" = 0x8E,
    @"f32.trunc" = 0x8F,
    @"f32.nearest" = 0x90,
    @"f32.sqrt" = 0x91,
    @"f32.add" = 0x92,
    @"f32.sub" = 0x93,
    @"f32.mul" = 0x94,
    @"f32.div" = 0x95,
    @"f32.min" = 0x96,
    @"f32.max" = 0x97,
    @"f32.copysign" = 0x98,

    @"f64.abs" = 0x99,
    @"f64.neg" = 0x9A,
    @"f64.ceil" = 0x9B,
    @"f64.floor" = 0x9C,
    @"f64.trunc" = 0x9D,
    @"f64.nearest" = 0x9E,
    @"f64.sqrt" = 0x9F,
    @"f64.add" = 0xA0,
    @"f64.sub" = 0xA1,
    @"f64.mul" = 0xA2,
    @"f64.div" = 0xA3,
    @"f64.min" = 0xA4,
    @"f64.max" = 0xA5,
    @"f64.copysign" = 0xA6,

    @"i32.wrap_i64" = 0xA7,
    @"i32.trunc_f32_s" = 0xA8,
    @"i32.trunc_f32_u" = 0xA9,
    @"i32.trunc_f64_s" = 0xAA,
    @"i32.trunc_f64_u" = 0xAB,
    @"i64.extend_i32_s" = 0xAC,
    @"i64.extend_i32_u" = 0xAD,
    @"i64.trunc_f32_s" = 0xAE,
    @"i64.trunc_f32_u" = 0xAF,
    @"i64.trunc_f64_s" = 0xB0,
    @"i64.trunc_f64_u" = 0xB1,
    @"f32.convert_i32_s" = 0xB2,
    @"f32.convert_i32_u" = 0xB3,
    @"f32.convert_i64_s" = 0xB4,
    @"f32.convert_i64_u" = 0xB5,
    @"f32.demote_f64" = 0xB6,
    @"f64.convert_i32_s" = 0xB7,
    @"f64.convert_i32_u" = 0xB8,
    @"f64.convert_i64_s" = 0xB9,
    @"f64.convert_i64_u" = 0xBA,
    @"f64.promote_f32" = 0xBB,
    @"i32.reinterpret_f32" = 0xBC,
    @"i64.reinterpret_f64" = 0xBD,
    @"f32.reinterpret_i32" = 0xBE,
    @"f64.reinterpret_i64" = 0xBF,

    @"i32.extend8_s" = 0xC0,
    @"i32.extend16_s" = 0xC1,
    @"i64.extend8_s" = 0xC2,
    @"i64.extend16_s" = 0xC3,
    @"i64.extend32_s" = 0xC4,

    @"ref.null" = 0xD0,
    @"ref.is_null" = 0xD1,
    @"ref.func" = 0xD2,

    /// See `FCPrefixOpcode`.
    @"0xFC" = 0xFC,
    // /// See `FDPrefixOpcode`.
    // @"0xFD" = 0xFD,
};

pub const IllegalOpcode = enum(u8) {
    /// The `0xFF` opcode is currently used by some engines for private opcodes.
    ///
    /// See <https://github.com/WebAssembly/design/issues/1539> for more information.
    @"wasmstint.validation_fail" = 0xFF,

    comptime {
        for (std.enums.values(IllegalOpcode)) |illegal| {
            for (std.enums.values(ByteOpcode)) |byte| {
                std.debug.assert(@intFromEnum(illegal) != @intFromEnum(byte));
            }
        }
    }
};

// Added in some proposal?
/// Technically a LEB128 encoded `u32`, but all of these are `<= 0x7F` for now.
pub const FCPrefixOpcode = enum(u5) {
    @"i32.trunc_sat_f32_s" = 0,
    @"i32.trunc_sat_f32_u" = 1,
    @"i32.trunc_sat_f64_s" = 2,
    @"i32.trunc_sat_f64_u" = 3,
    @"i64.trunc_sat_f32_s" = 4,
    @"i64.trunc_sat_f32_u" = 5,
    @"i64.trunc_sat_f64_s" = 6,
    @"i64.trunc_sat_f64_u" = 7,

    @"memory.init" = 8,
    @"data.drop" = 9,
    @"memory.copy" = 10,
    @"memory.fill" = 11,

    @"table.init" = 12,
    @"elem.drop" = 13,
    @"table.copy" = 14,
    @"table.grow" = 15,
    @"table.size" = 16,
    @"table.fill" = 17,
};

// pub const FDPrefixOpcode = enum(u8) {
//     @"v128.load" = 0,
// };

pub const PrefixSet = struct {
    prefix: ByteOpcode,
    @"enum": type,

    fn init(comptime prefix: ByteOpcode) @This() {
        return .{
            .prefix = prefix,
            .@"enum" = @field(opcodes, @tagName(prefix)[2..4] ++ "PrefixOpcode"),
        };
    }

    fn fields(set: *const PrefixSet) []const std.builtin.Type.EnumField {
        return @typeInfo(set.@"enum").@"enum".fields;
    }

    pub const all = [1]PrefixSet{PrefixSet.init(.@"0xFC")};
};

pub const AllOpcodes: type = ty: {
    const byte_opcodes = @typeInfo(ByteOpcode).@"enum".fields;
    const non_prefix_byte_opcode_count = byte_opcodes.len - PrefixSet.all.len;

    const total_count = count: {
        var total = non_prefix_byte_opcode_count;
        for (PrefixSet.all) |set| total += set.fields().len;
        break :count total;
    };

    const TagType = std.math.IntFittingRange(0, total_count);

    var fields: [total_count]std.builtin.Type.EnumField = undefined;
    var init_fields: TagType = 0;

    @setEvalBranchQuota(total_count * 2);

    for (byte_opcodes) |byte_opcode| {
        if (std.mem.startsWith(u8, byte_opcode.name, "0x")) continue;
        fields[init_fields] = .{ .name = byte_opcode.name, .value = init_fields };
        init_fields += 1;
    }

    std.debug.assert(init_fields == non_prefix_byte_opcode_count);

    for (PrefixSet.all) |set| {
        for (set.fields()) |opcode| {
            fields[init_fields] = .{ .name = opcode.name, .value = init_fields };
            init_fields += 1;
        }
    }

    std.debug.assert(init_fields == fields.len);

    break :ty @Type(std.builtin.Type{
        .@"enum" = .{
            .tag_type = TagType,
            .fields = &fields,
            .decls = &[0]std.builtin.Type.Declaration{},
            .is_exhaustive = true,
        },
    });
};
