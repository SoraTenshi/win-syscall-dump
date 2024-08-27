const std = @import("std");

const Coff = std.coff.Coff;

const gb = 1_000_000_000;

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

    pub fn format(self: ExportDirectoryTable, alloc: std.mem.Allocator) ![]const u8 {
        const fmt_str =
            \\ExportDirectoryTable -> {{
            \\    export_flags: 0x{x}
            \\    time_date_stamp: 0x{x}
            \\    major_version: 0x{x}
            \\    minor_version: 0x{x}
            \\    name_rva: 0x{x}
            \\    ordinal_base: 0x{x}
            \\    address_table_entries: 0x{x}
            \\    number_of_name_pointers: 0x{x}
            \\    export_address_table_rva: 0x{x}
            \\    name_poiunter_rva: 0x{x}
            \\    ordinal_table_rva: 0x{x}
            \\}}
        ;
        return std.fmt.allocPrint(alloc, fmt_str, .{
            self.export_flags,
            self.time_date_stamp,
            self.major_version,
            self.minor_version,
            self.name_rva,
            self.ordinal_base,
            self.address_table_entries,
            self.number_of_name_pointers,
            self.export_address_table_rva,
            self.name_pointer_rva,
            self.ordinal_table_rva,
        });
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const file = try std.fs.openFileAbsolute("/mnt/c/Windows/System32/ntdll.dll", .{});
    defer file.close();

    var data = std.ArrayList(u8).init(alloc);
    defer data.deinit();

    try file.reader().readAllArrayList(&data, gb);
    const coff = try Coff.init(data.items, false);

    const export_table_dir = coff.getDataDirectories()[@intFromEnum(std.coff.DirectoryEntry.EXPORT)];
    var fbs = std.io.fixedBufferStream(data.items);
    try fbs.seekTo(export_table_dir.virtual_address);
    std.debug.print("vaddr: 0x{x} --- seeked to: 0x{x}\n", .{ export_table_dir.virtual_address, fbs.pos });

    const export_table = try fbs.reader().readStructEndian(ExportDirectoryTable, .little);

    std.debug.print("{s}\n", .{try export_table.format(alloc)});

    var name_address_table = std.StringHashMap(u32).init(alloc);
    defer name_address_table.deinit();
    try name_address_table.ensureTotalCapacity(export_table.number_of_name_pointers);

    const addresses = try alloc.alloc(u32, export_table.number_of_name_pointers);
    for (0..export_table.number_of_name_pointers) |i| {
        try fbs.seekTo(export_table.export_address_table_rva + @sizeOf(u32) + i * @sizeOf(u32)); // skip the first table entry
        addresses[i] = try fbs.reader().readInt(u32, .little);
    }

    const names = try alloc.alloc(u32, export_table.number_of_name_pointers);
    for (0..export_table.number_of_name_pointers) |i| {
        try fbs.seekTo(export_table.name_pointer_rva + i * @sizeOf(u32)); // skip the first table entry
        names[i] = try fbs.reader().readInt(u32, .little);
    }

    for (addresses, names) |addr, name| {
        try fbs.seekTo(name);
        const n = try fbs.reader().readUntilDelimiterAlloc(alloc, '\x00', 1337);

        std.debug.print("Name: {s} -> 0x{X}\n", .{ n, addr });

        try name_address_table.put(n, addr);
    }
}
