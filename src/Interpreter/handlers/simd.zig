//! Implementation of instructions introduced in the
//! [fixed-width SIMD proposal](https://github.com/WebAssembly/simd).

pub fn @"v128.const"(
    ip: Ip,
    sp: Sp,
    fuel: *Fuel,
    stp: Stp,
    locals: Locals,
    module: runtime.ModuleInst,
    interp: *Interpreter,
    eip: Eip,
) callconv(ohcc) Transition {
    var instr = Instr.init(ip, eip);
    var vals = Stack.Values.init(sp, &interp.stack, 0, 1);

    const bytes = instr.readByteArray(16);
    vals.pushArray(1)[0] = Value{ .v128 = V128.init(.u8, bytes.*) };

    return dispatchNextOpcode(instr, vals.top, fuel, stp, locals, module, interp);
}

const Interpreter = @import("../../Interpreter.zig");
const handlers = @import("../handlers.zig");
const ohcc = handlers.ohcc;
const dispatchNextOpcode = handlers.dispatchNextOpcode;
const Ip = handlers.Ip;
const Eip = handlers.Eip;
const Sp = handlers.Sp;
const Stp = handlers.Stp;
const Instr = @import("../Instr.zig");
const Stack = @import("../Stack.zig");
const Locals = handlers.Locals;
const Fuel = Interpreter.Fuel;
const Transition = handlers.Transition;
const Value = @import("../value.zig").Value;
const V128 = @import("../../v128.zig").V128;
const runtime = @import("../../runtime.zig");
