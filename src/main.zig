const std = @import("std");
const syscalls = @import("syscalls");
const args = @import("args");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    const options = args.parseForCurrentProcess(Args, alloc, .print) catch return error.ArgsFailed;
    defer options.deinit();

    const dlls = [_][:0]const u8{
        "ntdll.dll",
        "adhsvc.dll",
    };

    const parsed = options.options;

    if (parsed.help) {
        try args.printHelp(Args, options.executable_name orelse "syscall-dumper.exe", std.io.getStdOut().writer());
        return;
    }

    var info: [dlls.len]syscalls.DllInfo = undefined;
    inline for (&info, dlls) |*i, dll| {
        i.* = try syscalls.fillInformation(
            alloc,
            parsed.dll,
            dll,
            null,
        );
    }
    defer for (info) |i| i.deinit();

    const file = try std.fs.cwd().createFile(parsed.file, .{
        .read = true,
    });
    defer file.close();

    var as_json = std.mem.zeroes(Json(&dlls));
    inline for (dlls, 0..) |dll, i| {
        const this = &@field(as_json, dll[0 .. std.mem.indexOfScalar(u8, dll, '.') orelse dll.len]);
        this.* = &info[i].fi;
        for (this.*.?.*, 0..) |val, j| {
            std.debug.print("{d}: {s} -> 0x{X}\n", .{ j, val.name, val.syscall });
        }
    }

    const stringified = try std.json.stringifyAlloc(alloc, as_json, .{ .whitespace = .indent_4 });
    defer alloc.free(stringified);

    try file.writeAll(stringified);
}

fn Json(comptime dlls: []const []const u8) type {
    var fields: [dlls.len]std.builtin.Type.StructField = undefined;
    inline for (dlls, 0..) |dll, i| {
        const len = comptime std.mem.indexOfScalar(u8, dll, '.') orelse dll.len;
        const field_name: [:0]const u8 = @ptrCast(dll[0..len]);
        fields[i] = std.builtin.Type.StructField{
            .name = field_name,
            .type = ?*[]syscalls.FunctionInformation,
            .default_value = null,
            .is_comptime = false,
            .alignment = @alignOf(syscalls.DllInfo),
        };
    }

    return @Type(std.builtin.Type{ .Struct = .{
        .layout = .auto,
        .fields = &fields,
        .decls = &.{},
        .is_tuple = false,
    } });
}

const Args = struct {
    dll: []const u8 = "",
    file: []const u8 = "",
    help: bool = false,

    pub const shorthands = .{
        .d = "dll",
        .f = "file",
        .h = "help",
    };

    pub const meta = .{
        .option_docs = .{
            .dll = "The path where the .DLLs are located",
            .file = "The file to dump to",
            .help = "This shows this screen",
        },
    };
};
