const std = @import("std");
const syscalls = @import("syscalls");
const args = @import("args");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const alloc = arena.allocator();
    const options = args.parseForCurrentProcess(Args, alloc, .print) catch return error.ArgsFailed;
    defer options.deinit();

    const parsed = options.options;

    const exe_name = options.executable_name orelse "syscall-dumper.exe";
    const out_text = try std.fmt.allocPrint(
        alloc,
        \\{s} [DLLs]
        \\Example: {s} -d "C:\Windows\System32" -f dump.txt ntdll.dll adhsvc.dll
    ,
        .{ exe_name, exe_name },
    );
    defer alloc.free(out_text);

    if (parsed.help) {
        try args.printHelp(Args, out_text, std.io.getStdOut().writer());
        return;
    }

    const parsed_dlls = parsed.dll orelse {
        std.log.err("DLL argument not found.", .{});
        try args.printHelp(Args, out_text, std.io.getStdOut().writer());
        return;
    };

    const parsed_file = parsed.file orelse {
        std.log.err("File to write to not found.", .{});
        try args.printHelp(Args, out_text, std.io.getStdOut().writer());
        return;
    };

    var info: [2]?*syscalls.DllInfo = .{ null, null };
    for (options.positionals, 0..) |dll, i| {
        std.debug.print("name: {s}\n", .{dll});
        info[i] = try syscalls.fillInformation(
            alloc,
            parsed_dlls,
            dll,
            .syscalls,
            null,
        );
    }
    defer for (info) |i| {
        if (i) |inf| {
            inf.deinit();
            alloc.destroy(inf);
        }
    };

    var jsons = try alloc.alloc(Json, options.positionals.len);
    defer alloc.free(jsons);
    for (0..options.positionals.len) |i| {
        jsons[i] = .{
            .name = info[i].?.dll.name,
            .function_info = info[i].?.dll.fi,
        };
    }

    const stringified = try std.json.stringifyAlloc(alloc, jsons, .{ .whitespace = .indent_4 });
    defer alloc.free(stringified);

    const file = try std.fs.cwd().createFile(parsed_file, .{
        .read = true,
    });
    defer file.close();

    try file.writeAll(stringified);
}

const Json = struct {
    name: []const u8,
    function_info: []syscalls.FunctionInformation,
};

const Args = struct {
    dll: ?[]const u8 = null,
    file: ?[]const u8 = null,
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
