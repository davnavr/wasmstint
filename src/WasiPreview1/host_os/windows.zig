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

/// `ShareAccess` parameter in [`NtCreateFile()`].
///
/// [`NtCreateFile()`]: https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
pub const ShareAccess = Mask(enum {
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILE_SHARE_DELETE,
});

/// `CreateDisposition` parameter in [`NtCreateFile()`].
///
/// [`NtCreateFile()`]: https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
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

/// `CreateOptions` parameter in [`NtCreateFile()`].
///
/// [`NtCreateFile()`]: https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
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

pub const DUPLICATE_SAME_ATTRIBUTES = 0x0000_0004;

/// https://www.tiraniddo.dev/2020/05/objdontreparse-is-mostly-useless.html
pub const OBJ_DONT_REPARSE = 0x0000_1000;

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
) callconv(.winapi) NtStatus;

/// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
pub extern "ntdll" fn NtCreateFile(
    file_handle: *Handle,
    desired_access: AccessMask,
    object_attributes: *std.os.windows.OBJECT_ATTRIBUTES,
    io_status_block: *std.os.windows.IO_STATUS_BLOCK,
    allocation_size: ?*std.os.windows.LARGE_INTEGER,
    file_attributes: std.os.windows.ULONG,
    share_access: ShareAccess,
    create_disposition: CreateDisposition,
    create_options: CreateOptions,
    ea_buffer: ?*anyopaque,
    ea_length: std.os.windows.ULONG,
) callconv(.winapi) NtStatus;

/// Returned when `OBJ_DONT_REPARSE` is used and a reparse point was encountered.
pub const STATUS_REPARSE_POINT_ENCOUNTERED: NtStatus = @enumFromInt(0xC000_050B);

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
        else => @compileError("specify FILE_INFORMATION_ struct for " ++ @tagName(class)),
    };
}

pub fn ntQueryInformationFile(
    handle: Handle,
    io_status_block: *std.os.windows.IO_STATUS_BLOCK,
    comptime file_information_class: std.os.windows.FILE_INFORMATION_CLASS,
    file_information: *FileInformationType(file_information_class),
) NtStatus {
    return std.os.windows.ntdll.NtQueryInformationFile(
        handle,
        io_status_block,
        file_information,
        @sizeOf(FileInformationType(file_information_class)),
        file_information_class,
    );
}

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

const std = @import("std");
const Handle = std.os.windows.HANDLE;
const NtStatus = std.os.windows.NTSTATUS;
