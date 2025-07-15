//! Iterates over commands to execute within a WebAssembly specification test JSON script file.

const Parser = @This();

source_filename: []const u8,
command_count: usize,
scanner: json.Scanner,
diagnostics: json.Diagnostics,
state: State,

const State = enum { more, finished };

//// Leftover from previous attempt that tried streaming without knowing nextAlloc was unusable.
// fn handleBufferUnderrun(parser: *Parser, reader: *Reader) error{ReadFailed}!void {
//     reader.tossBuffered();
//     reader.fillMore() catch |e| switch (e) {
//         error.ReadFailed => |failed| return failed,
//         error.EndOfStream => {
//             parser.scanner.endInput();
//             return;
//         },
//     };
//     parser.scanner.feedInput(reader.buffered());
// }

fn nextToken(parser: *Parser) error{MalformedJson}!json.Token {
    return parser.scanner.next() catch |e| switch (e) {
        Oom.OutOfMemory, error.BufferUnderrun => unreachable,
        error.SyntaxError, error.UnexpectedEndOfInput => return error.MalformedJson,
    };
}

fn expectNextToken(
    parser: *Parser,
    expected: @typeInfo(json.Token).@"union".tag_type.?,
) error{MalformedJson}!void {
    if ((try parser.nextToken()) != expected) {
        return error.MalformedJson;
    }
}

pub const InitError = Oom || error{MalformedJson};

pub fn init(parser: *Parser, allocator: std.mem.Allocator, input: []const u8) InitError!void {
    // Need pointer to `diagnostics` to be stable.
    parser.* = .{
        .source_filename = "error occurred before 'source_filename' could be parsed",
        .command_count = 0,
        .scanner = json.Scanner.initCompleteInput(allocator, input),
        .diagnostics = .{},
        .state = .more,
    };
    parser.scanner.enableDiagnostics(&parser.diagnostics);
    errdefer parser.state = .finished;

    try parser.expectNextToken(.object_begin);

    // JSON technically is unordered, but spectest-interp reads fields in order too
    // This also allows streaming instead of reading the whole file at once
    switch (try parser.nextToken()) {
        .string, .allocated_string => |s| if (!std.mem.eql(u8, s, "source_filename")) {
            return error.MalformedJson; // expected source_filename key
        },
        else => return error.MalformedJson,
    }

    parser.source_filename = switch (try parser.nextToken()) {
        .string, .allocated_string => |s| s,
        else => return error.MalformedJson, // source_filename must be a string.
    };
}

const std = @import("std");
const Oom = std.mem.Allocator.Error;
const ArenaAllocator = std.heap.ArenaAllocator;
const json = std.json;
