//! hub-service-zig echo example: post echo (identity), post echo/upper
//! (uppercase), and an app at echo/ui with textField + cell + button.
//! Run against a live hub (hub-lite on 1997).

const std = @import("std");
const hub_service = @import("hub_service");

const Service = hub_service.Service;
const Value = std.json.Value;

fn echoHandler(request: hub_service.PostRequest(?*Service, Value, void)) !?Value {
    return request.body;
}

fn upperHandler(request: hub_service.PostRequest(?*Service, Value, void)) !?Value {
    const svc = request.state.*.?;
    const text_value = switch (request.body) {
        .string => |s| s,
        else => return error.InvalidBody,
    };
    return .{ .string = try std.ascii.allocUpperString(svc.allocator, text_value) };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var svc = try Service.init(allocator, .{
        .name = "Echo",
        .icon = try hub_service.icon(allocator, "speaker.wave.2", "E"),
    });

    _ = try svc.post("echo", echoHandler, null);
    _ = try svc.post("echo/upper", upperHandler, null);
    _ = try svc.app(.{
        .header = .{ .name = "Echo", .path = "echo/ui" },
        .body = &.{
            .{ .string = "Hello from Zig" },
            try hub_service.textField(
                allocator,
                "echo",
                "Text to echo",
                try hub_service.action(allocator, "echo/upper", .{ .string = "value" }, .{ .string = "value" }),
            ),
            try hub_service.cell(allocator, .{ .string = "$Echo" }, .{ .string = "value" }),
            try hub_service.button(
                allocator,
                "Upper",
                try hub_service.action(allocator, "echo/upper", .{ .string = "value" }, .{ .string = "value" }),
            ),
        },
    });

    _ = try svc.start();
    std.debug.print("echo service started (hub-lite :1997)\n", .{});
    while (true) std.Thread.sleep(1_000_000_000);
}
