const std = @import("std");

const Coff = std.coff.Coff;

pub const gb = 1_000_000_000;

const ExportDirectoryTable = extern struct {
    export_flags: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name_rva: u32,
    ordinal_base: u32,
    address_table_entries: u32,
    number_of_name_pointers: u32,
    export_address_table_rva: u32,
    name_pointer_rva: u32,
    ordinal_table_rva: u32,
};

const FunctionSig = packed struct {
    b1: u8,
    b2: u8,
    b3: u8,
    b4: u8,
    syscall: u32,
};

pub const FunctionInformation = struct {
    name: []u8,
    syscall: u32,
};

pub const DllInfo = struct {
    allocator: std.mem.Allocator,
    fi: []FunctionInformation,

    pub fn deinit(self: DllInfo) void {
        self.allocator.free(self.fi);
    }
};

/// Fills the information of the `ScanInformation` struct
/// Parameters:
///   scan_information: A pointer to the instance of a `ScanInformation` struct
///   path_to_dlls: A string to where the .DLLs reside
///   alloc: The allocator.
///   max_load_size: The maximum amount of how much of the binary can be kept in memory.
///                  If `null` is passed, it will use 1GB (1000 * 1000 * 1000 Bytes)
/// Return:
///   The pointer to the passed `scan_information` or in case something went wrong an error.
pub fn fillInformation(
    alloc: std.mem.Allocator,
    path_to_dlls: []const u8,
    dll: []const u8,
    comptime max_load_size: ?usize,
) !DllInfo {
    const path = try std.fs.path.join(alloc, &.{ path_to_dlls, dll });

    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    var data = std.ArrayList(u8).init(alloc);
    defer data.deinit();
    try file.reader().readAllArrayList(&data, max_load_size orelse gb);

    const coff = try Coff.init(data.items, false);

    const export_table_dir = coff.getDataDirectories()[@intFromEnum(std.coff.DirectoryEntry.EXPORT)];
    const immutable_data: []const u8 = data.items;
    var fbs = std.io.fixedBufferStream(immutable_data);
    try fbs.seekTo(export_table_dir.virtual_address);

    const export_table = try fbs.reader().readStructEndian(ExportDirectoryTable, .little);

    // keep address temporarily, we exchange it with the syscall number.
    const info = DllInfo{
        .allocator = alloc,
        .fi = try alloc.alloc(FunctionInformation, export_table.number_of_name_pointers),
    };
    errdefer alloc.free(info.fi);

    const addresses = try alloc.alloc(u32, export_table.number_of_name_pointers);
    defer alloc.free(addresses);

    for (0..export_table.number_of_name_pointers) |i| {
        try fbs.seekTo(export_table.export_address_table_rva + @sizeOf(u32) + i * @sizeOf(u32)); // skip the first table entry
        addresses[i] = try fbs.reader().readInt(u32, .little);
    }

    const names = try alloc.alloc(u32, export_table.number_of_name_pointers);
    defer alloc.free(names);

    for (0..export_table.number_of_name_pointers) |i| {
        try fbs.seekTo(export_table.name_pointer_rva + i * @sizeOf(u32)); // skip the first table entry
        names[i] = try fbs.reader().readInt(u32, .little);
    }

    var i: usize = 0;
    for (addresses, names) |addr, name| {
        try fbs.seekTo(name);
        // i would assume no function has more than 100 characters.
        const n = try fbs.reader().readUntilDelimiterAlloc(alloc, 0, 100);

        try fbs.seekTo(addr);
        const func = try fbs.reader().readStructEndian(FunctionSig, .little);

        var syscall: u32 = 0;

        const magic: *[4]u8 = @ptrFromInt(@intFromPtr(&func));
        const as_bits: [4]u8 = magic.*;
        if (std.mem.eql(u8, &as_bits, "\x4c\x8b\xd1\xb8")) {
            try fbs.seekTo(addr + @sizeOf([4]u8));
            syscall = try fbs.reader().readInt(u32, .little);
            const fi = FunctionInformation{ .name = n, .syscall = syscall };
            info.fi[i] = fi;
            i += 1;
        } else {
            continue;
        }
    }

    const log = std.log.scoped(.FillInformation);
    if (!alloc.resize(info.fi, i)) {
        log.err(
            "The allocator could not resize the field list. Because of this, so many bytes are \"wasted\": {d}",
            .{@sizeOf(FunctionInformation) * (info.fi.len - i)},
        );
    }

    return info;
}
