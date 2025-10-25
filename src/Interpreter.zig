//! Represents a single thread of WebAssembly computation.
//!
//! Based on <https://doi.org/10.48550/arXiv.2205.01183>.

const Value = @import("Interpreter/value.zig").Value;
const Stack = @import("Interpreter/Stack.zig");
const SideTable = @import("Interpreter/side_table.zig").SideTable;
const Instr = @import("Interpreter/Instr.zig");
const handlers = @import("Interpreter/handlers.zig");
const instantiation = @import("Interpreter/instantiation.zig");
const Version = @import("Interpreter/version.zig").Version;

pub const TaggedValue = Value.Tagged;
pub const Trap = @import("Interpreter/Trap.zig");

stack: Stack,
/// Must not be accessed from within opcode handlers.
stack_top: Stack.Top,
dummy_instantiate_flag: bool = false,
version: Version = Version{},
current_state: Status,

const Interpreter = @This();

/// Places an upper bound on the number of WASM instructions an interpreter can execute.
///
/// TODO: Make some instructions like `memory.copy`, `table.copy`, `memory.init`, etc. take more fuel
pub const Fuel = extern struct {
    remaining: u64,
};

pub const InitOptions = struct {
    /// The initial size, in bytes, of the stack.
    stack_reserve: u32 = @sizeOf(Value) * 1024,
};

pub fn init(
    interp: *Interpreter,
    /// Used to allocate the `stack`.
    alloca: Allocator,
    options: InitOptions,
) Allocator.Error!State {
    const stack = try Stack.init(
        alloca,
        std.math.divCeil(u32, options.stack_reserve, @sizeOf(Value)) catch return error.OutOfMemory,
    );

    interp.* = Interpreter{
        .stack = stack,
        .stack_top = Stack.Top{ .ptr = stack.allocated.ptr },
        .current_state = Status{ .awaiting_host = .{} },
    };

    return State.init(interp);
}

/// Discards the current computation.
pub fn reset(interp: *Interpreter) State {
    interp.version.increment();
    if (builtin.mode == .Debug) {
        @memset(
            interp.stack.allocated[0..(interp.stack_top.ptr - interp.stack.allocated.ptr)],
            undefined,
        );
    }

    interp.stack.call_depth = 0;
    interp.stack.current_frame = .none;
    interp.stack_top = Stack.Top{ .ptr = interp.stack.allocated.ptr };
    interp.current_state = Status{ .awaiting_host = .{} };
    return State.init(interp);
}

pub const InterruptionCause = union(enum) {
    out_of_fuel,
    memory_grow: MemoryGrow,
    table_grow: TableGrow,

    pub const MemoryGrow = struct {
        memory: *runtime.MemInst,
        /// Modifying this value is a violation of WebAssembly semantics.
        old_size: usize,
        /// Invariant that `new_size >= memory.size`.
        new_size: usize,
        result: *align(@sizeOf(Value)) Value,

        /// The amount to increase the size of the memory by, in bytes.
        pub fn delta(grow: *const MemoryGrow) usize {
            return grow.new_size - grow.memory.size;
        }
    };

    pub const TableGrow = struct {
        table: runtime.TableAddr,
        /// Also used as the result where an `i32` to indicate the old size is written.
        elem: *align(@sizeOf(Value)) Value,
        old_len: u32,
        /// Invariant that `new_size >= table.len`.
        new_len: u32,
    };
};

fn CopyConst(comptime Self: type, comptime T: type, comptime U: type) type {
    return switch (Self) {
        *T => *U,
        *const T => *const U,
        else => @compileError(@tagName(Self) ++ " is not a " ++ @tagName(T) ++ " pointer"),
    };
}

const Status = union(State.Tag) {
    awaiting_host: struct {
        result_types: []const Module.ValType = &.{},
    },
    awaiting_validation,
    call_stack_exhaustion: struct {
        callee: runtime.FuncAddr,
    },
    interrupted: struct {
        cause: Interpreter.InterruptionCause,
    },
    trapped: struct {
        source: State.Trapped.Source,
        trap: Trap,
    },
    // unhandled_exception: struct {},
};

/// The current execution state of the `Interpreter`.
///
/// Execution of WebAssembly is represented by a state machine to allow for the stackless design.
pub const State = union(Tag) {
    const Tag = enum {
        awaiting_host,
        awaiting_validation,
        call_stack_exhaustion,
        interrupted,
        trapped,
    };

    const Inner = extern struct {
        owning_interpreter: *Interpreter,
        version: Version,

        pub fn interpreter(self: *const Inner) *Interpreter {
            self.owning_interpreter.version.check(self.version);
            return self.owning_interpreter;
        }

        pub fn currentFrame(self: *const Inner) ?*Stack.Frame {
            const stack: *const Stack = &self.interpreter().stack;
            return stack.frameAt(stack.current_frame);
        }

        /// Modifications to the `Interpreter` and `state` must not happen while the stack is being
        /// walked, as it may cause iterator invalidation.
        pub fn walkCallStack(self: *const Inner) Stack.Walker {
            // TODO: Could have version field in `Stack` and `Stack.Walker`
            return self.owning_interpreter.stack.walkCallStack();
        }

        // inline so `new_state` is written directly
        inline fn transition(self: Inner, new_state: Status) State {
            const interp = self.interpreter();
            interp.current_state = new_state;
            interp.version.increment();
            return State.init(interp);
        }

        /// Given a WASM function at the top of the call stack, resumes execution.
        ///
        /// Asserts that the top of the stack frame corresponds to a WASM function that has already
        /// been validated.
        fn enterMainLoop(self: Inner, fuel: *Fuel) State {
            const old_version = self.version;
            const interp = self.interpreter();
            defer if (Version.enabled) {
                std.debug.assert(old_version.number != interp.version.number);
            };

            const frame: *Stack.Frame = self.currentFrame().?;
            std.debug.assert(@intFromPtr(frame.wasm.ip) <= @intFromPtr(frame.wasm.eip));

            const wasm_callee = frame.function.expanded().wasm;
            const code = wasm_callee.code();
            std.debug.assert(code.isValidationFinished());

            if (builtin.mode == .Debug) {
                std.debug.assert( // IP below bounds
                    @intFromPtr(code.inner.instructions_start) <= @intFromPtr(frame.wasm.ip),
                );
                std.debug.assert( // EIP mismatch
                    @intFromPtr(code.inner.instructions_end) == @intFromPtr(frame.wasm.eip),
                );

                if (@intFromPtr(frame.wasm.stp) < @intFromPtr(code.inner.side_table_ptr)) {
                    std.debug.panic( // STP below bounds
                        "side table OOB: {*} < {*}",
                        .{ frame.wasm.stp, code.inner.side_table_ptr },
                    );
                }

                const side_table_end = code.inner.side_table_ptr + code.inner.side_table_len;
                if (@intFromPtr(frame.wasm.stp) > @intFromPtr(side_table_end)) {
                    std.debug.panic("side table OOB: {*} > {*}", .{ frame.wasm.stp, side_table_end });
                }
            }

            // std.debug.print("ENTERING MAIN LOOP (ver = {})\n", .{interp.version.number});

            var i = Instr.init(frame.wasm.ip, frame.wasm.eip);
            const locals = handlers.Locals{ .ptr = frame.localValues(&interp.stack).ptr };
            const handler: *const handlers.OpcodeHandler = i.readNextOpcodeHandler(
                fuel,
                locals,
                wasm_callee.module,
                interp,
            );

            const transitioned = handler(
                i.next,
                interp.stack_top,
                fuel,
                frame.wasm.stp,
                locals,
                wasm_callee.module,
                interp,
                i.end,
            );

            if (builtin.mode == .Debug) {
                interp.version.check(transitioned.version);
            }

            return State.init(interp);
        }
    };

    awaiting_host: AwaitingHost,
    awaiting_validation: AwaitingValidation,
    call_stack_exhaustion: CallStackExhaustion,
    interrupted: Interrupted,
    trapped: Trapped,

    comptime {
        for (@typeInfo(State).@"union".fields) |f| {
            const fields = @typeInfo(f.type).@"struct".fields;
            std.debug.assert(fields.len == 1);
            std.debug.assert(std.mem.eql(u8, "inner", fields[0].name));
            std.debug.assert(fields[0].type == Inner);
        }
    }

    fn init(interp: *Interpreter) State {
        const init_inner = State.Inner{ .owning_interpreter = interp, .version = interp.version };
        // Since all cases are just `State.Inner`, this should be optimized
        return switch (@as(State.Tag, interp.current_state)) {
            inline else => |tag| @unionInit(State, @tagName(tag), .{ .inner = init_inner }),
        };
    }

    pub fn inner(state: anytype) CopyConst(@TypeOf(state), State, Inner) {
        // comptime check ensures offset of `inner` is `0`, so this is optimized
        return switch (state.*) {
            inline else => |*case| &case.inner,
        };
    }

    /// Either WASM code is ready to be interpreted, or WASM code is awaiting the results of
    /// calling a host function.
    pub const AwaitingHost = extern struct {
        inner: Inner,

        /// The types of the values at the top of the value stack, which are the results of the
        /// most recently called function.
        pub fn resultTypes(state: *const AwaitingHost) []const Module.ValType {
            return state.inner.interpreter().current_state.awaiting_host.result_types;
        }

        fn copyValues(
            types: []const Module.ValType,
            values: []align(@sizeOf(Value)) const Value,
            output: []TaggedValue,
        ) void {
            for (output, types, values) |*dst, ty, *val| {
                dst.* = val.tagged(ty);
            }
        }

        /// Asserts that a host function frame is active.
        fn params(state: *const AwaitingHost) []align(@sizeOf(Value)) const Value {
            const frame = state.inner.currentFrame().?;
            const locals = frame.localValues(&state.inner.interpreter().stack);
            std.debug.assert(locals.len == frame.signature.param_count);
            return locals;
        }

        fn results(state: *const AwaitingHost) []align(@sizeOf(Value)) const Value {
            const interp: *const Interpreter = state.inner.interpreter();
            const result_count: u16 = @intCast(interp.current_state.awaiting_host.result_types.len);
            return Stack.Values.init(
                interp.stack_top,
                &interp.stack,
                result_count,
                result_count,
            ).topSlice(result_count);
        }

        /// Copies the parameters passed to the host function to a list.
        ///
        /// Asserts that a host function is currently being called.
        pub fn copyParamsTo(state: *const AwaitingHost, output: []TaggedValue) void {
            copyValues(
                state.inner.currentFrame().?.signature.parameters(),
                state.params(),
                output,
            );
        }

        /// Copies the values returned from the most recent function call.
        pub fn copyResultsTo(state: *const AwaitingHost, output: []TaggedValue) void {
            copyValues(
                state.inner.interpreter().current_state.awaiting_host.result_types,
                state.results(),
                output,
            );
        }

        /// Copies the parameters passed to the host function to a new allocation.
        pub fn allocParams(
            state: *const AwaitingHost,
            allocator: Allocator,
        ) Allocator.Error![]TaggedValue {
            const dst = try allocator.alloc(
                TaggedValue,
                state.inner.interpreter().currentFrame().?.signature.param_count,
            );

            state.copyParamsTo(dst);
            return dst;
        }

        /// Copies the results from the most recent function call to a new allocation.
        pub fn allocResults(
            state: *const AwaitingHost,
            allocator: Allocator,
        ) Allocator.Error![]TaggedValue {
            const ret = try allocator.alloc(
                TaggedValue,
                state.inner.interpreter().current_state.awaiting_host.result_types.len,
            );

            state.copyResultsTo(ret);
            return ret;
        }

        pub const SignatureMismatchError = error{
            /// The number or type of values provided does not match the signature of the function.
            SignatureMismatch,
        };

        fn valuesTyped(
            comptime T: type,
            types: []const Module.ValType,
            values: []align(@sizeOf(Value)) const Value,
        ) SignatureMismatchError!T {
            const result_fields = tuple: {
                switch (@typeInfo(T)) {
                    .@"struct" => |s| if (s.is_tuple) break :tuple s.fields,
                    else => {},
                }

                @compileError("expected tuple, got " ++ @typeName(T));
            };

            std.debug.assert(types.len == values.len);
            if (result_fields.len != types.len) {
                return error.SignatureMismatch; // bad count
            }

            var result_tuple: T = undefined;
            inline for (0.., result_fields, types, values) |i, *field, ty, *src| {
                result_tuple[i] = val: switch (field.type) {
                    i32, u32 => {
                        if (ty != .i32) return error.SignatureMismatch;
                        break :val src.i32;
                    },
                    i64, u64 => {
                        if (ty != .i64) return error.SignatureMismatch;
                        break :val src.i64;
                    },
                    f32 => {
                        if (ty != .f32) return error.SignatureMismatch;
                        break :val src.f32;
                    },
                    f64 => {
                        if (ty != .f64) return error.SignatureMismatch;
                        break :val src.f64;
                    },
                    runtime.ExternAddr => {
                        if (ty != .externref) return error.SignatureMismatch;
                        break :val src.externref.addr;
                    },
                    runtime.FuncAddr.Nullable => {
                        if (ty != .funcref) return error.SignatureMismatch;
                        break :val src.funcref;
                    },
                    else => @compileError("unsupported result type " ++ @typeName(field.type)),
                };
            }

            return result_tuple;
        }

        pub fn paramsTyped(
            state: *const AwaitingHost,
            comptime T: type,
        ) SignatureMismatchError!T {
            return valuesTyped(
                T,
                state.inner.currentFrame().?.signature.parameters(),
                state.params(),
            );
        }

        pub const CallError = Allocator.Error || SignatureMismatchError || error{
            /// The function to call has not yet been validated.
            ValidationNeeded,
        };

        fn clearResultsOnStack(state: *const AwaitingHost) void {
            const interp = state.inner.interpreter();
            const result_types: *[]const Module.ValType = &interp.current_state.awaiting_host
                .result_types;

            const result_count: u16 = @intCast(result_types.*.len);

            var stack = Stack.Values.init(
                interp.stack_top,
                &interp.stack,
                result_count,
                result_count,
            );

            const prev_results = stack.popSlice(result_count);
            stack.assertRemainingCountIs(0);
            @memset(prev_results, undefined);
            interp.stack_top = stack.top;
            result_types.* = &.{};
        }

        /// Begins the process of calling a function. Always clears the results of the previous
        /// function call.
        ///
        /// For a WASM function, the interpreter loop is entered, returning when a `Trap` occurs or
        /// when `Interrupted`.
        ///
        /// For a host function, this returns immediately with `State.AwaitingHost`.
        pub fn beginCall(
            state: *const AwaitingHost,
            /// Used to allocate more space for the stack if necessary.
            alloca: Allocator,
            callee: runtime.FuncAddr,
            arguments: []const TaggedValue,
            fuel: *Fuel,
        ) CallError!State {
            var coz_begin = coz.begin("wasmstint.Interpreter.AwaitingHost.beginCall");
            defer coz_begin.end();

            state.clearResultsOnStack();

            const signature = callee.signature();
            if (arguments.len != signature.param_count) {
                return error.SignatureMismatch; // wrong # of arguments provided
            }

            // Check argument types before pushing the stack frame, as doing it after would require
            // restoring values in `state`.
            for (arguments, signature.parameters()) |*src, param_type| {
                if (param_type != src.valueType()) {
                    return error.SignatureMismatch; // argument type mismatch
                }
            }

            const interp = state.inner.interpreter();

            std.debug.assert( // `call_depth` and `current_frame` mismatch
                (interp.stack.current_frame == .none) == (interp.stack.call_depth == 0),
            );

            // std.debug.print("HOST WANTS TO CALL {f}\n", .{callee});

            const new_frame = try interp.stack.pushFrame(
                interp.stack_top,
                alloca,
                &interp.dummy_instantiate_flag,
                .allocate,
                callee,
            );

            errdefer unreachable;
            interp.stack_top = new_frame.top;

            for ( // copy parameters
                new_frame.frame.localValues(&interp.stack)[0..signature.param_count],
                arguments,
            ) |*dst, *src| {
                dst.* = src.untagged();
            }

            return switch (callee.expanded()) {
                .host => state.inner.transition(Status{ .awaiting_host = .{} }),
                .wasm => state.inner.enterMainLoop(fuel),
            };
        }

        /// [Instantiates] a module, beginning the process of invoking its start function (if it
        /// exists) as if passed to `.beginCall()`.
        ///
        /// If a start function exists, once it successfully returns, then the `module` has been
        /// instantiated.
        ///
        /// [Instantiates]: https://webassembly.github.io/spec/core/exec/modules.html#instantiation
        pub fn instantiateModule(
            state: *const AwaitingHost,
            alloca: Allocator,
            module: *runtime.ModuleAlloc,
            fuel: *Fuel,
        ) Allocator.Error!State {
            var coz_begin = coz.begin("wasmstint.Interpreter.AwaitingHost.instantiateModule");
            defer coz_begin.end();

            state.clearResultsOnStack();

            if (module.instantiated) {
                return state.inner.transition(Status{ .awaiting_host = .{} });
            }

            const interp: *Interpreter = state.inner.interpreter();
            const start_func = module.requiring_instantiation.header().startFuncAddr();

            if (start_func.funcInst()) |start| {
                const signature = start.signature();
                std.debug.assert(signature.param_count == 0);
                std.debug.assert(signature.result_count == 0);
                try interp.stack.reserveFrame(interp.stack_top, alloca, .preallocated, start);
            }

            errdefer unreachable;

            var instantiation_error: instantiation.SetupError = undefined;
            instantiation.setupModule(module, &instantiation_error) catch {
                const trap = switch (instantiation_error) {
                    inline else => |info, tag| Trap.init(@field(Trap.Code, @tagName(tag)), info),
                };

                return state.inner.transition(Status{
                    .trapped = .{ .source = .module_instantiation, .trap = trap },
                });
            };

            if (start_func.funcInst()) |start| {
                _ = interp.stack.pushFrameWithinCapacity(
                    interp.stack_top,
                    &module.instantiated,
                    .preallocated, // no parameters
                    start,
                ) catch unreachable; // bad reserve for module start function

                return switch (start.expanded()) {
                    .host => state.inner.transition(Status{ .awaiting_host = .{} }),
                    .wasm => state.inner.enterMainLoop(fuel),
                };
            } else {
                module.instantiated = true;
                return state.inner.transition(Status{ .awaiting_host = .{} });
            }
        }

        /// Returns the current host function being called, or `null` if the call stack is empty.
        pub fn currentHostFunction(state: *const AwaitingHost) ?runtime.FuncAddr.Expanded.Host {
            return if (state.inner.currentFrame()) |stack_frame|
                stack_frame.function.expanded().host
            else
                null;
        }

        /// Return from the currently executing host function to the calling function, typically
        /// WASM code whose interpretation will continue with the given `fuel` amount.
        ///
        /// Asserts that the call stack is not empty.
        pub fn returnFromHost(
            state: *AwaitingHost,
            result_values: []const TaggedValue,
            fuel: *Fuel,
        ) SignatureMismatchError!State {
            var coz_begin = coz.begin("wasmstint.Interpreter.AwaitingHost.returnFromHost");
            defer coz_begin.end();

            const interp: *Interpreter = state.inner.interpreter();
            const popped_signature = state.inner.currentFrame().?.signature;

            if (result_values.len != popped_signature.result_count) {
                return error.SignatureMismatch; // wrong # of results
            }

            // Need to check types of results now, otherwise the current frame would be clobbered
            for (result_values, popped_signature.results()) |*src, result_type| {
                if (result_type != src.valueType()) {
                    return error.SignatureMismatch; // bad result type
                }
            }

            errdefer comptime unreachable;

            const popped = interp.stack.popFrame(interp.stack_top, .manually);
            interp.stack_top = popped.top;
            for (result_values, popped.results) |*src, *dst| {
                dst.* = src.untagged();
            }

            if (interp.stack.currentFrame()) |current| {
                switch (current.function.expanded()) {
                    .wasm => return state.inner.enterMainLoop(fuel),
                    .host => {},
                }
            }

            return state.inner.transition(Status{
                .awaiting_host = .{ .result_types = popped_signature.results() },
            });
        }

        pub fn returnFromHostTyped(
            state: *AwaitingHost,
            result_tuple: anytype,
            fuel: *Fuel,
        ) SignatureMismatchError!State {
            if (@TypeOf(result_tuple) == void) {
                return state.returnFromHost(&[0]TaggedValue{}, fuel);
            }

            const results_len = len: {
                switch (@typeInfo(@TypeOf(result_tuple))) {
                    .@"struct" => |s| if (s.is_tuple) break :len s.fields.len,
                    else => {},
                }

                @compileError("expect result tuple, got " ++ @typeName(@TypeOf(result_tuple)));
            };

            var result_array: [results_len]TaggedValue = undefined;
            inline for (&result_array, result_tuple) |*dst, src| {
                dst.* = TaggedValue.initInferred(src);
            }

            return state.returnFromHost(&result_array, fuel);
        }

        // pub fn trapWithHostCode(state: *AwaitingHost, code: u31) State {
        // }
    };

    /// Indicates that a WASM function being called by WASM needs to be
    /// validated.
    ///
    /// In this state, the instruction pointer refers to the interrupted `call` instruction to
    /// execute again.
    pub const AwaitingValidation = struct {
        inner: Inner,

        // pub fn waitForLazyValidation(Timeout)

        pub fn validate(
            state: *AwaitingValidation,
            /// Used to allocate information about the function body, such as
            /// the the side table.
            code_allocator: Allocator,
            scratch: *std.heap.ArenaAllocator,
            fuel: *Fuel,
        ) error{OutOfMemory}!State {
            _ = state;
            _ = code_allocator;
            _ = scratch;
            _ = fuel;
            @compileError("TODO: lazy validation");
            // TODO: restore stack just like CallStackExhaustion.resumeExecution()

            // const interp: *Interpreter = self.interpreter();
            // const current_frame = interp.currentFrame();

            // const callee = current_frame.function;
            // const function = callee.expanded().wasm;
            // const code = function.code();
            // const finished = code.validate(
            //     code_allocator,
            //     function.module.header().module,
            //     scratch,
            // ) catch {
            //     interp.state = .{
            //         .trapped = Trap.init(
            //             .lazy_validation_failure,
            //             .{ .function = function.idx },
            //         ),
            //     };

            //     return &interp.state;
            // };

            // if (finished) {
            //     current_frame.wasm = .{
            //         .instructions = Instructions.init(
            //             code.inner.instructions_start,
            //             code.inner.instructions_end,
            //         ),
            //         .branch_table = code.inner.side_table_ptr,
            //     };

            //     _ = interp.allocateValueStackSpace(alloca, &code.inner) catch {
            //         interp.state = .{
            //             .call_stack_exhaustion = .{
            //                 .callee = callee,
            //                 .values_base = @intCast(interp.value_stack.items.len),
            //                 .signature = callee.signature(),
            //             },
            //         };

            //         return &interp.state;
            //     };

            //     interp.state = .{ .awaiting_host = .{ .types = &.{} } };
            //     interp.enterMainLoop(fuel);
            // }

            // return &interp.state;
        }
    };

    /// A `call` instruction required pushing a new stack frame, which required a reallocation of
    /// the `call_stack`.
    ///
    /// In this state, the instruction pointer refers to the `call` instruction to execute again.
    pub const CallStackExhaustion = struct {
        inner: Inner,

        /// Attempts to allocate space for a stack frame before attempting to execute the `call`
        /// instruction again.
        pub fn resumeExecution(
            state: *CallStackExhaustion,
            alloca: Allocator,
            fuel: *Fuel,
        ) error{OutOfMemory}!State {
            var coz_begin = coz.begin(
                "wasmstint.Interpreter.CallStackExhaustion.resumeExecution",
            );
            defer coz_begin.end();

            const interp = state.inner.interpreter();
            _ = try interp.stack.reserveFrame(
                interp.stack_top,
                alloca,
                .preallocated,
                interp.current_state.call_stack_exhaustion.callee,
            );
            return state.inner.enterMainLoop(fuel);
        }
    };

    /// Execution of WASM bytecode was interrupted.
    ///
    /// The host can stop using the interpreter further, resume execution with more fuel by calling
    /// `resumeExecution()`, or reuse the interpreter for a new computation after calling
    /// `Interpreter.reset`.
    ///
    /// If `cause == .out_of_fuel`, the IP refers to the instruction that was not executed when fuel
    /// ran out.
    ///
    /// If the host receives a `cause` that it does not know how to handle, such as one that is
    /// introduced in a future version of this library, `resumeExecution` could be called anyways,
    /// though it may cause errors or a `Trap` in guest code.
    pub const Interrupted = struct {
        inner: Inner,

        pub fn cause(state: *const Interrupted) *const Interpreter.InterruptionCause {
            return &state.inner.interpreter().current_state.interrupted.cause;
        }

        /// Resumes execution of WASM bytecode after being interrupted.
        pub fn resumeExecution(state: *Interrupted, fuel: *Fuel) State {
            var coz_begin = coz.begin("wasmstint.Interpreter.Interrupted.resumeExecution");
            defer coz_begin.end();
            return state.inner.enterMainLoop(fuel);
        }
    };

    /// The computation was aborted due to a *trap*. The call stack of the interpreter can be
    /// inspected to determine where and when the trap occurred.
    ///
    /// Note that no stack frame is recorded if a *trap* occurs during module *instantation*
    /// before the *start* function (if it exists) is invoked.
    pub const Trapped = struct {
        inner: Inner,

        pub const Source = enum {
            function_call,
            /// The `Trap` occurred during module *instantiation* before a *start* function was
            /// called.
            module_instantiation,
        };

        /// Indicates if a trap occurred as a result of a function call.
        pub fn source(state: *const Trapped) Source {
            return state.inner.interpreter().current_state.trapped.source;
        }

        pub fn trap(state: *const Trapped) *const Trap {
            return &state.inner.interpreter().current_state.trapped.trap;
        }
    };
};

pub fn deinit(interp: *Interpreter, alloca: Allocator) void {
    interp.stack.deinit(alloca);
    interp.* = undefined;
}

const std = @import("std");
const builtin = @import("builtin");
const coz = @import("coz");
const Allocator = std.mem.Allocator;
const Module = @import("Module.zig");
const runtime = @import("runtime.zig");

test {
    _ = Instr;
}
