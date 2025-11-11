//! Wrappers over the Windows (Win32/`kernel32.dll`) and Windows Native (`ntdll.dll`) APIs.

fn Mask(comptime ValidFlags: type) type {
    return packed struct(u32) {
        bits: std.os.windows.ULONG,

        const Valid = ValidFlags;
        const Self = @This();

        pub const zero = Self{ .bits = 0 };

        pub fn init(flags: []const Valid) Self {
            var mask = Self.zero;
            for (flags) |f| {
                switch (f) {
                    inline else => |tag| mask.bits |= @field(std.os.windows, @tagName(tag)),
                }
            }
            return mask;
        }

        pub fn set(mask: Self, others: Self) Self {
            return Self{ .bits = mask.bits | others.bits };
        }

        pub fn setFlag(mask: Self, flag: Valid) Self {
            return mask.set(Self.init(&.{flag}));
        }

        pub fn setConditional(a: Self, condition: bool, b: Self) Self {
            return if (condition) a.set(b) else a;
        }

        pub fn setFlagConditional(mask: Self, condition: bool, flag: Valid) Self {
            return mask.setConditional(condition, Self.init(&.{flag}));
        }

        pub fn without(mask: Self, removed: Self) Self {
            return Self{ .bits = mask.bits & (~removed.bits) };
        }

        pub fn contains(a: Self, b: Self) bool {
            return a.bits | b.bits == a.bits;
        }

        pub fn containsFlag(mask: Self, flag: Valid) bool {
            return mask.contains(Self.init(&.{flag}));
        }
    };
}

/// https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/access-mask
pub const AccessMask = Mask(enum {
    DELETE,
    FILE_READ_DATA,
    FILE_READ_ATTRIBUTES,
    FILE_READ_EA,
    FILE_WRITE_DATA,
    FILE_WRITE_ATTRIBUTES,
    FILE_APPEND_DATA,
    FILE_GENERIC_READ,
    FILE_GENERIC_WRITE,
    FILE_LIST_DIRECTORY,
    FILE_TRAVERSE,
    STANDARD_RIGHTS_READ,
    STANDARD_RIGHTS_WRITE,
    SYNCHRONIZE,
});

/// `ShareAccess` parameter in `NtCreateFile()`.
pub const ShareAccess = Mask(enum {
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILE_SHARE_DELETE,
});

pub const share_access_default = ShareAccess.init(
    &.{ .FILE_SHARE_READ, .FILE_SHARE_WRITE, .FILE_SHARE_DELETE },
);

/// `CreateDisposition` parameter in `NtCreateFile()`.
pub const CreateDisposition = @Type(std.builtin.Type{
    .@"enum" = std.builtin.Type.Enum{
        .tag_type = std.os.windows.ULONG,
        .decls = &.{},
        .is_exhaustive = true,
        .fields = fields: {
            const options = [_][:0]const u8{
                "FILE_SUPERSEDE",
                "FILE_CREATE",
                "FILE_OPEN",
                "FILE_OPEN_IF",
                "FILE_OVERWRITE",
                "FILE_OVERWRITE_IF",
            };

            var fields: [options.len]std.builtin.Type.EnumField = undefined;
            for (options, &fields) |name, *dst| {
                dst.* = std.builtin.Type.EnumField{
                    .name = name,
                    .value = @field(std.os.windows, name),
                };
            }

            break :fields &fields;
        },
    },
});

/// `CreateOptions` parameter in `NtCreateFile()`.
pub const CreateOptions = Mask(enum {
    FILE_DIRECTORY_FILE,
    FILE_NON_DIRECTORY_FILE,
    FILE_WRITE_THROUGH,
    FILE_SEQUENTIAL_ONLY,
    FILE_RANDOM_ACCESS,
    FILE_NO_INTERMEDIATE_BUFFERING,
    FILE_SYNCHRONOUS_IO_NONALERT,
    FILE_OPEN_REPARSE_POINT,
    /// Required for opening directories.
    FILE_OPEN_FOR_BACKUP_INTENT,
});

pub const FileAttributes = Mask(enum {
    FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_SYSTEM,
    FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_ARCHIVE,
    FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_TEMPORARY,
    FILE_ATTRIBUTE_COMPRESSED,
});

pub const DUPLICATE_SAME_ATTRIBUTES = 0x0000_0004;

/// `OBJ_DONT_REPARSE` fails on paths like `C:\Users\You\file.txt`, so it should only be used when
/// processing relative paths.
///
// For more information see:
/// https://www.tiraniddo.dev/2020/05/objdontreparse-is-mostly-useless.html
pub const OBJ_DONT_REPARSE = 0x0000_1000;

/// Documentation for `NtCreateFile` only lists `OBJ_CASE_INSENSITIVE` for `Attributes`
pub const obj_dont_reparse_min_version = std.Target.Os.WindowsVersion.win10_rs1;

pub const has_obj_dont_reparse = builtin.os.version_range.windows
    .isAtLeast(obj_dont_reparse_min_version);

/// https://ntdoc.m417z.com/ntduplicateobject
/// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicateobject
pub extern "ntdll" fn NtDuplicateObject(
    source_process_handle: Handle,
    source_handle: Handle,
    target_process_handle: ?Handle,
    target_handle: ?*Handle,
    desired_access: AccessMask,
    handle_attributes: std.os.windows.ULONG,
    options: std.os.windows.ULONG,
) callconv(.winapi) Status;

/// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
pub extern "ntdll" fn NtCreateFile(
    file_handle: *Handle,
    desired_access: AccessMask,
    object_attributes: *std.os.windows.OBJECT_ATTRIBUTES,
    io_status_block: *std.os.windows.IO_STATUS_BLOCK,
    allocation_size: ?*std.os.windows.LARGE_INTEGER,
    file_attributes: FileAttributes,
    share_access: ShareAccess,
    create_disposition: CreateDisposition,
    create_options: CreateOptions,
    ea_buffer: ?*anyopaque,
    ea_length: std.os.windows.ULONG,
) callconv(.winapi) Status;

/// Returned when `OBJ_DONT_REPARSE` is used and a reparse point was encountered.
pub const STATUS_REPARSE_POINT_ENCOUNTERED: Status = @enumFromInt(0xC000_050B);

/// https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string
pub fn initUnicodeString(str: []u16) std.os.windows.UNICODE_STRING {
    return std.os.windows.UNICODE_STRING{
        // Lengths are in bytes, excluding null-terminator
        .Length = @intCast(str.len * 2),
        .MaximumLength = @intCast(str.len * 2),
        .Buffer = str.ptr,
    };
}

pub fn FileInformationType(comptime class: std.os.windows.FILE_INFORMATION_CLASS) type {
    return switch (class) {
        .FileBasicInformation => std.os.windows.FILE_BASIC_INFORMATION,
        .FilePositionInformation => std.os.windows.FILE_POSITION_INFORMATION,
        .FileAllInformation => std.os.windows.FILE_ALL_INFORMATION,
        .FileStandardInformation => std.os.windows.FILE_STANDARD_INFORMATION,
        else => @compileError("specify file information struct for " ++ @tagName(class)),
    };
}

pub fn ntQueryInformationFile(
    handle: Handle,
    io_status_block: *std.os.windows.IO_STATUS_BLOCK,
    comptime file_information_class: std.os.windows.FILE_INFORMATION_CLASS,
    file_information: *FileInformationType(file_information_class),
) Status {
    return std.os.windows.ntdll.NtQueryInformationFile(
        handle,
        io_status_block,
        file_information,
        @sizeOf(FileInformationType(file_information_class)),
        file_information_class,
    );
}

/// Assumed to be available in all versions of Windows supported by Zig.
///
/// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_id_full_dir_information
pub const FILE_ID_FULL_DIR_INFORMATION = extern struct {
    NextEntryOffset: std.os.windows.ULONG,
    FileIndex: std.os.windows.ULONG,
    CreationTime: std.os.windows.LARGE_INTEGER,
    LastAccessTime: std.os.windows.LARGE_INTEGER,
    LastWriteTime: std.os.windows.LARGE_INTEGER,
    ChangeTime: std.os.windows.LARGE_INTEGER,
    EndOfFile: std.os.windows.LARGE_INTEGER,
    AllocationSize: std.os.windows.LARGE_INTEGER,
    FileAttributes: FileAttributes,
    /// In bytes.
    FileNameLength: std.os.windows.ULONG,
    EaSize: std.os.windows.ULONG,
    FileId: std.os.windows.LARGE_INTEGER,
    FileName: [0]std.os.windows.WCHAR,
};

pub fn queryDirectoryFile(
    handle: Handle,
    io_status_block: *std.os.windows.IO_STATUS_BLOCK,
    file_information: []u8,
    file_information_class: std.os.windows.FILE_INFORMATION_CLASS,
    scan: enum(u1) { restart = std.os.windows.TRUE, @"resume" = 0 },
) Status {
    return std.os.windows.ntdll.NtQueryDirectoryFile(
        handle,
        null,
        null,
        null,
        io_status_block,
        file_information.ptr,
        std.math.cast(std.os.windows.ULONG, file_information.len) orelse
            std.math.maxInt(std.os.windows.ULONG),
        file_information_class,
        std.os.windows.FALSE,
        null,
        @intFromEnum(scan),
    );
}

pub const RTL_RELATIVE_NAME = extern struct {
    /// Seems to store a path relative to `ContainingDirectory`, if it is not `null`.
    RelativeName: std.os.windows.UNICODE_STRING,
    ContainingDirectory: ?Handle,
    CurDirRef: ?*anyopaque,
};

/// https://learn.microsoft.com/en-us/windows/win32/devnotes/rtldospathnametontpathname_u_withstatus
pub extern "ntdll" fn RtlDosPathNameToNtPathName_U_WithStatus(
    dos_path_name: [*:0]const u16,
    /// On successful return, will contain the NT path name.
    nt_path_name: *std.os.windows.UNICODE_STRING,
    file_part: ?*?[*:0]const u16,
    /// Undocumented API, use at your own risk!
    ///
    /// https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html
    relative_name: ?*RTL_RELATIVE_NAME,
) callconv(.winapi) Status;

/// Includes console handle detection logic that is not provided by the equivalent `ntdll` API.
///
/// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfiletype
pub extern "kernel32" fn GetFileType(hFile: Handle) FileType;

pub const FileType = enum(std.os.windows.DWORD) {
    disk = 0x0001,
    char = 0x0002,
    pipe = 0x0003,
    remote = 0x8000,
    unknown = 0x0000,
    _,
};

/// An MSYS2 or Cygwin named pipe used as a Unix-style pty (pseudoterminal).
pub const NamedPipePty = packed struct(u76) {
    tag: Tag,
    id: Id,

    pub const Tag = enum(u2) { msys, cygwin, not_a_pty };

    pub const not_a_pty = NamedPipePty{
        .tag = .not_a_pty,
        .id = @bitCast(@as(u74, std.math.maxInt(u74))),
    };

    pub const Id = packed struct(u74) {
        installation_key: u64,
        /// Cygwin seems to allow at most 128 ptys.
        number: u7,
        type: Type,
    };

    pub const Type = enum(u3) {
        echoloop,
        @"from-master",
        @"from-master-nat",
        @"to-master",
        @"to-master-nat",
        unknown,

        fn get(s: []const u16) ?Type {
            if (s.len == 0) {
                return null;
            }

            inline for (comptime std.enums.values(Type)) |kind| {
                switch (kind) {
                    .unknown => {},
                    inline else => |known| {
                        if (std.mem.eql(u16, wideLiteral(@tagName(known)), s)) {
                            return kind;
                        }
                    },
                }
            }

            return Type.unknown;
        }
    };

    fn wideCharToHexDigit(c: u16) error{InvalidCharacter}!u4 {
        return @intCast(switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            else => return error.InvalidCharacter,
        });
    }

    test wideCharToHexDigit {
        try std.testing.expectEqual(0, wideCharToHexDigit('0'));
        try std.testing.expectEqual(9, wideCharToHexDigit('9'));
        try std.testing.expectEqual(0xA, wideCharToHexDigit('a'));
        try std.testing.expectEqual(0xF, wideCharToHexDigit('f'));
    }

    fn fromName(name: []const u16) NamedPipePty {
        const kind_end = std.mem.indexOfScalar(u16, name, '-') orelse return .not_a_pty;
        const kind_str = name[0..kind_end];
        const after_kind = name[kind_end + 1 ..];

        const kind: Tag = if (std.mem.eql(u16, wideLiteral("msys"), kind_str))
            .msys
        else if (std.mem.eql(u16, wideLiteral("cygwin"), kind_str))
            .cygwin
        else
            return .not_a_pty;

        if (after_kind.len <= 16 or after_kind[16] != '-') {
            return .not_a_pty;
        }

        var installation_key: u64 = 0;
        const installation_key_digits = after_kind[0..16];
        for (0..8) |i| {
            const hi_digit = installation_key_digits[i * 2];
            const lo_digit = installation_key_digits[(i * 2) + 1];
            const hi_nibble = @shlExact(
                @as(u8, wideCharToHexDigit(hi_digit) catch return .not_a_pty),
                4,
            );
            const lo_nibble = wideCharToHexDigit(lo_digit) catch return .not_a_pty;
            const byte: u8 = hi_nibble | @as(u8, lo_nibble);
            installation_key = @shlExact(installation_key, 8) | @as(u64, byte);
        }

        const after_installation_key = after_kind[17..];
        if (!std.mem.startsWith(u16, after_installation_key, wideLiteral("pty"))) {
            return .not_a_pty;
        }
        const after_pty = after_installation_key["pty".len..];

        const pty_number_end = std.mem.indexOfScalar(u16, after_pty, '-') orelse return .not_a_pty;
        const pty_number_digits = after_pty[0..pty_number_end];

        const id = NamedPipePty.Id{
            .installation_key = installation_key,
            .number = number: {
                var pty_number: u7 = 0;
                for (pty_number_digits) |d| {
                    const n: u7 = switch (d) {
                        '0'...'9' => @intCast(d - '0'),
                        else => return .not_a_pty,
                    };

                    pty_number = std.math.mul(u7, pty_number, 10) catch return .not_a_pty;
                    pty_number = std.math.add(u7, pty_number, n) catch return .not_a_pty;
                }

                break :number pty_number;
            },
            .type = NamedPipePty.Type.get(after_pty[pty_number_end + 1 ..]) orelse
                return .not_a_pty,
        };

        return NamedPipePty{ .tag = kind, .id = id };
    }

    test fromName {
        try std.testing.expectEqual(
            NamedPipePty{
                .tag = .msys,
                .id = Id{
                    .installation_key = 0x1888_AE32_E00D_56AA,
                    .number = 0,
                    .type = Type.@"from-master",
                },
            },
            NamedPipePty.fromName(wideLiteral("msys-1888ae32e00d56aa-pty0-from-master")),
        );
    }
};

/// Similar to `std.fs.File.isCygwinPty`, except it assumes that `handle` is already a named pipe,
/// and also returns the "installation key", the `pty` number, and the type of pty.
pub fn isMsysOrCygwinPty(handle: Handle) NamedPipePty {
    const min_len_bytes = "\\msys-0123456789ABCDEF-ptyN-echoloop".len * 2;
    const max_len_bytes = "\\cygwin-0123456789ABCDEF-ptyNNN-from-master-nat".len * 2;

    const FileNameInfo = extern struct {
        byte_len: std.os.windows.DWORD,
        name: [@divExact(max_len_bytes, 2)]std.os.windows.WCHAR,
    };

    var name_info: FileNameInfo = undefined;
    {
        var io_status_block: std.os.windows.IO_STATUS_BLOCK = undefined;
        const query_status = std.os.windows.ntdll.NtQueryInformationFile(
            handle,
            &io_status_block,
            @ptrCast(&name_info),
            @sizeOf(FileNameInfo),
            .FileNameInformation,
        );

        switch (query_status) {
            .SUCCESS => {},
            .INVALID_PARAMETER => unreachable,
            // .BUFFER_OVERFLOW,
            else => return .not_a_pty,
        }
    }

    std.debug.assert(name_info.byte_len % 2 == 0);
    if (name_info.byte_len < min_len_bytes or max_len_bytes < name_info.byte_len) {
        return .not_a_pty;
    }

    const name: []const u16 = name_info.name[0..@divExact(name_info.byte_len, 2)];
    std.debug.assert(name[0] == '\\');
    return NamedPipePty.fromName(name[1..]);
}

const std = @import("std");
const builtin = @import("builtin");
const Handle = std.os.windows.HANDLE;
const Status = std.os.windows.NTSTATUS;
const wideLiteral = std.unicode.wtf8ToWtf16LeStringLiteral;

test {
    _ = NamedPipePty;
}
