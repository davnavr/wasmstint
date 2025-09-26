/// A character used in CLI arguments and environment variables.
///
/// `null` is not a valid character as it is used as a terminator.
pub const Char = enum(u8) {
    /// Start of Heading.
    soh = 0x01,
    /// Start of Text.
    stx = 0x02,
    /// End of Text.
    etx = 0x03,
    /// End of Transmission.
    eot = 0x04,
    /// Enquiry.
    enq = 0x05,
    /// Acknowledge.
    ack = 0x06,
    /// Bell, Alert.
    bel = 0x07,
    /// Backspace.
    bs = 0x08,
    /// Horizontal Tab.
    ht = '\t',
    /// Line Feed.
    lf = '\n',
    /// Vertical Tab.
    vt = 0x0B,
    /// Form Feed.
    ff = 0x0C,
    /// Carriage Return.
    cr = '\r',
    /// Shift Out.
    so = 0x0E,
    /// Shift In.
    si = 0x0F,
    /// Data Link Escape.
    dle = 0x10,
    /// Device Control One (XON).
    dc1 = 0x11,
    /// Device Control Two.
    dc2 = 0x12,
    /// Device Control Three (XOFF).
    dc3 = 0x13,
    /// Device Control Four.
    dc4 = 0x14,
    /// Negative Acknowledge.
    nak = 0x15,
    /// Synchronous Idle.
    syn = 0x16,
    /// End of Transmission Block
    etb = 0x17,
    /// Cancel.
    can = 0x18,
    /// End of Medium.
    em = 0x19,
    /// Substitute.
    sub = 0x1A,
    /// Escape.
    esc = 0x1B,
    /// File Separator.
    fs = 0x1C,
    /// Group Separator.
    gs = 0x1D,
    /// Record Separator.
    rs = 0x1E,
    /// Unit Separator.
    us = 0x1F,
    @" " = ' ',
    @"!" = '!',
    quot = '\"',
    @"#" = '#',
    @"$" = '$',
    @"%" = '%',
    @"&" = '&',
    apos = '\'',
    lpar = '(',
    rpar = ')',
    @"*" = '*',
    @"+" = '+',
    @"," = ',',
    @"-" = '-',
    @"." = '.',
    @"/" = '/',
    @"0" = '0',
    @"1" = '1',
    @"2" = '2',
    @"3" = '3',
    @"4" = '4',
    @"5" = '5',
    @"6" = '6',
    @"7" = '7',
    @"8" = '8',
    @"9" = '9',
    @":" = ':',
    @";" = ';',
    @"<" = '<',
    @"=" = '=',
    @">" = '>',
    @"?" = '?',
    @"@" = '@',
    A = 'A',
    B = 'B',
    C = 'C',
    D = 'D',
    E = 'E',
    F = 'F',
    G = 'G',
    H = 'H',
    I = 'I',
    J = 'J',
    K = 'K',
    L = 'L',
    M = 'M',
    N = 'N',
    O = 'O',
    P = 'P',
    Q = 'Q',
    R = 'R',
    S = 'S',
    T = 'T',
    U = 'U',
    V = 'V',
    W = 'W',
    X = 'X',
    Y = 'Y',
    Z = 'Z',
    lbrk = '[',
    @"\\" = '\\',
    rbrk = ']',
    @"^" = '^',
    @"_" = '_',
    grav = '`',
    a = 'a',
    b = 'b',
    c = 'c',
    d = 'd',
    e = 'e',
    f = 'f',
    g = 'g',
    h = 'h',
    i = 'i',
    j = 'j',
    k = 'k',
    l = 'l',
    m = 'm',
    n = 'n',
    o = 'o',
    p = 'p',
    q = 'q',
    r = 'r',
    s = 's',
    t = 't',
    u = 'u',
    v = 'v',
    w = 'w',
    x = 'x',
    y = 'y',
    z = 'z',
    lcub = '{',
    @"|" = '|',
    rcub = '}',
    @"~" = '~',
    del = 0x7F,

    // End of ASCII range
    x80 = 0x80,
    x81 = 0x81,
    x82 = 0x82,
    x83 = 0x83,
    x84 = 0x84,
    x85 = 0x85,
    x86 = 0x86,
    x87 = 0x87,
    x88 = 0x88,
    x89 = 0x89,
    x8A = 0x8A,
    x8B = 0x8B,
    x8C = 0x8C,
    x8D = 0x8D,
    x8E = 0x8E,
    x8F = 0x8F,

    x90 = 0x90,
    x91 = 0x91,
    x92 = 0x92,
    x93 = 0x93,
    x94 = 0x94,
    x95 = 0x95,
    x96 = 0x96,
    x97 = 0x97,
    x98 = 0x98,
    x99 = 0x99,
    x9A = 0x9A,
    x9B = 0x9B,
    x9C = 0x9C,
    x9D = 0x9D,
    x9E = 0x9E,
    x9F = 0x9F,

    xA0 = 0xA0,
    xA1 = 0xA1,
    xA2 = 0xA2,
    xA3 = 0xA3,
    xA4 = 0xA4,
    xA5 = 0xA5,
    xA6 = 0xA6,
    xA7 = 0xA7,
    xA8 = 0xA8,
    xA9 = 0xA9,
    xAA = 0xAA,
    xAB = 0xAB,
    xAC = 0xAC,
    xAD = 0xAD,
    xAE = 0xAE,
    xAF = 0xAF,

    xB0 = 0xB0,
    xB1 = 0xB1,
    xB2 = 0xB2,
    xB3 = 0xB3,
    xB4 = 0xB4,
    xB5 = 0xB5,
    xB6 = 0xB6,
    xB7 = 0xB7,
    xB8 = 0xB8,
    xB9 = 0xB9,
    xBA = 0xBA,
    xBB = 0xBB,
    xBC = 0xBC,
    xBD = 0xBD,
    xBE = 0xBE,
    xBF = 0xBF,

    xC0 = 0xC0,
    xC1 = 0xC1,
    xC2 = 0xC2,
    xC3 = 0xC3,
    xC4 = 0xC4,
    xC5 = 0xC5,
    xC6 = 0xC6,
    xC7 = 0xC7,
    xC8 = 0xC8,
    xC9 = 0xC9,
    xCA = 0xCA,
    xCB = 0xCB,
    xCC = 0xCC,
    xCD = 0xCD,
    xCE = 0xCE,
    xCF = 0xCF,

    xD0 = 0xD0,
    xD1 = 0xD1,
    xD2 = 0xD2,
    xD3 = 0xD3,
    xD4 = 0xD4,
    xD5 = 0xD5,
    xD6 = 0xD6,
    xD7 = 0xD7,
    xD8 = 0xD8,
    xD9 = 0xD9,
    xDA = 0xDA,
    xDB = 0xDB,
    xDC = 0xDC,
    xDD = 0xDD,
    xDE = 0xDE,
    xDF = 0xDF,

    xE0 = 0xE0,
    xE1 = 0xE1,
    xE2 = 0xE2,
    xE3 = 0xE3,
    xE4 = 0xE4,
    xE5 = 0xE5,
    xE6 = 0xE6,
    xE7 = 0xE7,
    xE8 = 0xE8,
    xE9 = 0xE9,
    xEA = 0xEA,
    xEB = 0xEB,
    xEC = 0xEC,
    xED = 0xED,
    xEE = 0xEE,
    xEF = 0xEF,

    xF0 = 0xF0,
    xF1 = 0xF1,
    xF2 = 0xF2,
    xF3 = 0xF3,
    xF4 = 0xF4,
    xF5 = 0xF5,
    xF6 = 0xF6,
    xF7 = 0xF7,
    xF8 = 0xF8,
    xF9 = 0xF9,
    xFA = 0xFA,
    xFB = 0xFB,
    xFC = 0xFC,
    xFD = 0xFD,
    xFE = 0xFE,
    xFF = 0xFF,

    comptime {
        for (1..std.math.maxInt(u8)) |i| {
            const c: Char = @enumFromInt(i);
            if (std.ascii.isAlphanumeric(i)) {
                std.debug.assert(std.mem.eql(u8, @tagName(c), &.{@intCast(i)}));
            }
        }
    }

    pub fn format(c: Char, writer: *Writer) Writer.Error!void {
        return writer.writeByte(@intFromEnum(c));
    }

    //pub fn formatEscaped(c: Char, writer: *Writer) Writer.Error!void {}
};

const std = @import("std");
const Writer = std.Io.Writer;
