const std = @import("std");

const Coff = std.coff.Coff;
const Buffer = std.io.FixedBufferStream([]const u8);
const createBuffer = std.io.fixedBufferStream;

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
    dll: struct {
        fi: []FunctionInformation,
        name: []const u8,
    },

    pub fn deinit(self: DllInfo) void {
        for (self.dll.fi) |n| {
            self.allocator.free(n.name);
        }
        self.allocator.free(self.dll.fi);
    }
};

/// The wanted mode for fillInformation to contain
pub const Mode = enum {
    /// Store only syscall indezes
    syscalls,

    /// Store (possibly resolved) imports / exports
    addresses,
};

/// Fills the information of the `DllInfo` struct
/// Parameters:
///   alloc: The allocator.
///   path_to_dlls: The actual system path where the requested paths can be found
///   max_load_size: The maximum amount of how much of the binary can be kept in memory.
///                  If `null` is passed, it will use 1GB (1000 * 1000 * 1000 Bytes)
/// Return:
///   The DllInfo struct, which contains all the collected information
///   The caller owns the memory.
/// Errors:
///   Typical errors, File not found, OOM, ...
pub fn fillInformation(
    alloc: std.mem.Allocator,
    path_to_dlls: []const u8,
    dll: []const u8,
    comptime mode: Mode,
    comptime max_load_size: ?usize,
) !*DllInfo {
    const log = std.log.scoped(.Syscalls);
    const path = try std.fs.path.join(alloc, &.{ path_to_dlls, dll });
    defer alloc.free(path);

    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    const data = try file.reader().readAllAlloc(alloc, max_load_size orelse gb);
    defer alloc.free(data);

    const coff = try Coff.init(data, false);

    const export_table_dir = coff.getDataDirectories()[@intFromEnum(std.coff.DirectoryEntry.EXPORT)];
    const immutable_data: []const u8 = data;
    var fbs = createBuffer(immutable_data);
    try fbs.seekTo(export_table_dir.virtual_address);

    const export_table = try fbs.reader().readStructEndian(ExportDirectoryTable, .little);

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

    log.info("Found {d} names and {d} addresses.", .{ names.len, addresses.len });

    // keep address temporarily, we exchange it with the syscall number.
    var list = try std.ArrayList(FunctionInformation).initCapacity(alloc, export_table.number_of_name_pointers);
    const info = try alloc.create(DllInfo);
    info.* = DllInfo{
        .allocator = alloc,
        .dll = .{
            .fi = &.{},
            .name = dll[0 .. std.mem.indexOfScalar(u8, dll, '.') orelse dll.len],
        },
    };
    errdefer info.deinit();

    const i = switch (mode) {
        inline .syscalls => try fillSyscalls(alloc, &fbs, addresses, names, &list),
        inline .addresses => @as(usize, 0),
    };

    try list.resize(i);
    info.dll.fi = try list.toOwnedSlice();

    return info;
}

/// This function resolves all the syscalls
///
/// Return:
///   The amount of iterations done
fn fillSyscalls(
    alloc: std.mem.Allocator,
    fbs: *Buffer,
    addresses: []u32,
    names: []u32,
    list: *std.ArrayList(FunctionInformation),
) !usize {
    var i: usize = 0;
    std.debug.print("addresses and names: {d}, {d}\n", .{ addresses.len, names.len });
    for (addresses, names) |addr, name| {
        try fbs.seekTo(addr);
        const func = try fbs.reader().readStructEndian(FunctionSig, .little);

        const n = try resolveAddress(.string, alloc, fbs, name);

        var syscall: u32 = 0;

        const magic: *[4]u8 = @ptrFromInt(@intFromPtr(&func));
        const as_bits: [4]u8 = magic.*;
        if (std.mem.eql(u8, &as_bits, "\x4c\x8b\xd1\xb8")) {
            try fbs.seekTo(addr + @sizeOf([4]u8));
            syscall = try fbs.reader().readInt(u32, .little);
            try list.append(FunctionInformation{ .name = n, .syscall = syscall });
            i += 1;
        } else {
            alloc.free(n);
            continue;
        }
    }

    return i;
}

const TypeOfAddress = enum {
    /// Read a C String
    string,
    /// Read a simple address
    address,

    pub fn ResolveToType(comptime self: TypeOfAddress) type {
        return switch (self) {
            inline .string => []u8,
            inline .address => u32,
        };
    }
};

/// On address_type == .string, then the caller owns the memory
fn resolveAddress(
    comptime address_type: TypeOfAddress,
    alloc: std.mem.Allocator,
    fbs: *Buffer,
    address: u32,
) !address_type.ResolveToType() {
    switch (address_type) {
        .string => {
            try fbs.seekTo(address);

            // i would assume no function has more than 100 characters.
            return fbs.reader().readUntilDelimiterAlloc(alloc, 0, 100);
        },
        .address => {},
    }
    return 0;
}
