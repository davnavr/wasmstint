pub const Opcode = union(enum) {
    byte: opcodes.ByteOpcode,
    fc: opcodes.FCPrefixOpcode,
    fd: opcodes.FDPrefixOpcode,

    pub fn init(comptime E: type, opcode: E) Opcode {
        return @unionInit(
            Opcode,
            switch (E) {
                opcodes.ByteOpcode => "byte",
                opcodes.FCPrefixOpcode => "fc",
                opcodes.FDPrefixOpcode => "fd",
                else => @compileError("no case for opcode " ++ @typeName(E)),
            },
            opcode,
        );
    }

    pub fn name(opcode: Opcode) []const u8 {
        return switch (opcode) {
            .byte => |byte| if (byte != .@"select t") @tagName(byte) else "select_t",
            inline else => |n| @tagName(n),
        };
    }

    pub fn fromName(comptime E: type, s: []const u8) Opcode {
        return .init(
            E,
            std.meta.stringToEnum(E, s) orelse
                std.debug.panic("no opcode {s} in " ++ @typeName(E), .{s}),
        );
    }

    pub fn fromPrefixedName(
        comptime E: type,
        scratch: *std.heap.ArenaAllocator,
        prefix: []const u8,
        s: []const u8,
    ) std.mem.Allocator.Error!Opcode {
        _ = scratch.reset(.retain_capacity);
        return .fromName(E, try std.mem.concat(scratch.allocator(), u8, &.{ prefix, ".", s }));
    }
};

const std = @import("std");
const opcodes = @import("opcodes");
