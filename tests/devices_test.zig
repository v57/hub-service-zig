//! Device layer tests: Docs/Devices/vectors.json, hub key pins and the
//! connect flow against an in-process fake hub (a channel-zig server).

const std = @import("std");
const hub_service = @import("hub_service");
const channel = hub_service.channel;
const test_options = @import("test_options");

const testing = std.testing;
const Service = hub_service.Service;
const Value = std.json.Value;

const HUB_KEY = "MCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";

fn loadVectors() !std.json.Parsed(Value) {
    const text = try std.fs.cwd().readFileAlloc(testing.allocator, test_options.vectors_path, 1 << 20);
    defer testing.allocator.free(text);
    return std.json.parseFromSlice(Value, testing.allocator, text, .{ .allocate = .alloc_always });
}

fn vector(root: Value, path: []const []const u8) Value {
    var value = root;
    for (path) |key| value = value.object.get(key).?;
    return value;
}

fn vectorText(root: Value, path: []const []const u8) []const u8 {
    return vector(root, path).string;
}

/// A temp dir path (owned) and its handle; clean up with `tmp.cleanup()`.
fn tmpPath(tmp: *std.testing.TmpDir, name: []const u8) ![]u8 {
    const dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(dir);
    return std.fs.path.join(testing.allocator, &.{ dir, name });
}

test "vectors: auth v0 and v1 tokens" {
    var vectors = try loadVectors();
    defer vectors.deinit();
    const root = vectors.value;
    const key_file = vectorText(root, &.{ "keys", "service", "keyFile" });
    const expiry = vector(root, &.{ "auth", "expiry" }).integer;

    const v0 = try hub_service.authToken(testing.allocator, key_file, null, expiry);
    defer testing.allocator.free(v0);
    try testing.expectEqualStrings(vectorText(root, &.{ "auth", "v0", "header" }), v0);

    const v1 = try hub_service.authToken(testing.allocator, key_file, vectorText(root, &.{ "keys", "hub", "publicKey" }), expiry);
    defer testing.allocator.free(v1);
    try testing.expectEqualStrings(vectorText(root, &.{ "auth", "v1", "header" }), v1);
}

test "keychain: hub key pins live beside the key file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth_path = try tmpPath(&tmp, "auth");
    defer testing.allocator.free(auth_path);

    var kc = try hub_service.Keychain.init(testing.allocator, auth_path);
    defer kc.deinit();
    try testing.expect((try kc.hubKey("ws://127.0.0.1:1997")) == null);

    try kc.pinHubKey("ws://127.0.0.1:1997", "HUBKEY1");
    try kc.pinHubKey("ws://example:1997", "HUBKEY2");
    const key = (try kc.hubKey("ws://127.0.0.1:1997")).?;
    defer testing.allocator.free(key);
    try testing.expectEqualStrings("HUBKEY1", key);
    try tmp.dir.access("hubs.json", .{});

    try kc.forgetHubKey("ws://127.0.0.1:1997");
    try testing.expect((try kc.hubKey("ws://127.0.0.1:1997")) == null);
    const other = (try kc.hubKey("ws://example:1997")).?;
    defer testing.allocator.free(other);
    try testing.expectEqualStrings("HUBKEY2", other);
}

test "keychain: signForHub binds the hub key; files are 0600" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth_path = try tmpPath(&tmp, "auth");
    defer testing.allocator.free(auth_path);

    var kc = try hub_service.Keychain.init(testing.allocator, auth_path);
    defer kc.deinit();
    const token = try kc.signForHub("HUBKEY", hub_service.AUTH_EXPIRY);
    defer testing.allocator.free(token);

    const expiry_text = token[std.mem.lastIndexOfScalar(u8, token, '.').? + 1 ..];
    const expiry = try std.fmt.parseInt(i64, expiry_text, 10);
    const now = std.time.timestamp();
    try testing.expect(expiry >= now + 58 and expiry <= now + 60);

    const key_file = try tmp.dir.readFileAlloc(testing.allocator, "auth", 1 << 10);
    defer testing.allocator.free(key_file);
    const expected = try hub_service.authToken(testing.allocator, key_file, "HUBKEY", expiry);
    defer testing.allocator.free(expected);
    try testing.expectEqualStrings(expected, token);

    const stat = try tmp.dir.statFile("auth");
    try testing.expectEqual(@as(std.fs.File.Mode, 0o600), stat.mode & 0o777);
}

// --- fake hub ---------------------------------------------------------------

const HubState = struct {};

const Connect = struct {
    v: [4]u8 = undefined,
    v_len: usize = 0,
    auth: [512]u8 = undefined,
    auth_len: usize = 0,
    device: [2048]u8 = undefined,
    device_len: usize = 0,

    fn get(buffer: []const u8, len: usize) []const u8 {
        return buffer[0..len];
    }
};

var connects: [8]Connect = undefined;
var connect_count = std.atomic.Value(usize).init(0);
var hub_sender: ?channel.Sender(HubState) = null;

fn copyHeader(headers: *const std.StringHashMapUnmanaged([]const u8), name: []const u8, out: []u8) usize {
    const value = headers.get(name) orelse return 0;
    const n = @min(value.len, out.len);
    @memcpy(out[0..n], value[0..n]);
    return n;
}

fn recordConnect(headers: *const std.StringHashMapUnmanaged([]const u8)) !HubState {
    const index = connect_count.load(.acquire);
    if (index < connects.len) {
        var entry = &connects[index];
        entry.v_len = copyHeader(headers, "v", &entry.v);
        entry.auth_len = copyHeader(headers, "auth", &entry.auth);
        entry.device_len = copyHeader(headers, "device", &entry.device);
    }
    connect_count.store(index + 1, .release);
    return .{};
}

fn rememberSender(_: *HubState, sender: channel.Sender(HubState)) void {
    hub_sender = sender;
}

fn replyNull(_: channel.PostRequest(HubState, Value, void)) !?Value {
    return null;
}

fn replyInfo(_: channel.PostRequest(HubState, void, void)) !?struct { key: []const u8, protocol: i64, pro: bool, mode: []const u8 } {
    return .{ .key = HUB_KEY, .protocol = 1, .pro = true, .mode = "default-allow" };
}

const FakeHub = struct {
    ch: channel.Channel(HubState),
    server: channel.Server(HubState),

    fn start(self: *FakeHub, answers_info: bool) !void {
        connect_count.store(0, .release);
        hub_sender = null;
        self.ch = channel.Channel(HubState).init(testing.allocator);
        _ = try self.ch.post("hub/service/update", replyNull);
        _ = try self.ch.post("hub/profile/update", replyNull);
        if (answers_info) _ = try self.ch.post("hub/info", replyInfo);
        self.server = try self.ch.listen(testing.allocator, 0, .{ .state = recordConnect, .on_connect = rememberSender });
    }

    fn deinit(self: *FakeHub) void {
        self.server.deinit();
        self.ch.deinit();
    }

    /// Waits until `count` connections arrived (or `limit_ms` passes), then a
    /// little longer so the service finishes its updates.
    fn wait(_: *FakeHub, count: usize, limit_ms: u64) void {
        var waited: u64 = 0;
        while (waited < limit_ms and connect_count.load(.acquire) < count) : (waited += 1) {
            std.Thread.sleep(std.time.ns_per_ms);
        }
        std.Thread.sleep(300 * std.time.ns_per_ms);
    }
};

const Fixture = struct {
    tmp: std.testing.TmpDir,
    auth_path: []u8,
    device_path: []u8,

    fn init() !Fixture {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const auth_path = try tmpPath(&tmp, "auth");
        errdefer testing.allocator.free(auth_path);
        // The device key sits in the temp dir, never in ~/.hub.
        const device_path = try tmpPath(&tmp, "device.key");
        return .{ .tmp = tmp, .auth_path = auth_path, .device_path = device_path };
    }

    fn deinit(self: *Fixture) void {
        testing.allocator.free(self.auth_path);
        testing.allocator.free(self.device_path);
        self.tmp.cleanup();
    }

    fn service(self: *Fixture, hub: *FakeHub) !Service {
        return Service.init(testing.allocator, .{
            .address = .{ .port = hub.server.port() },
            .key_path = self.auth_path,
        });
    }
};

test "fake hub: learns and pins the hub key, then connects with v1" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var hub: FakeHub = undefined;
    try hub.start(true);
    defer hub.deinit();

    var svc = try fixture.service(&hub);
    defer svc.deinit();
    _ = try svc.start();
    hub.wait(2, 5000);
    svc.stop();

    try testing.expectEqual(@as(usize, 2), connect_count.load(.acquire));
    try testing.expectEqualStrings("0", Connect.get(&connects[0].v, connects[0].v_len));
    try testing.expectEqualStrings("1", Connect.get(&connects[1].v, connects[1].v_len));

    const address = try svc.addressUrl(testing.allocator);
    defer testing.allocator.free(address);
    const pinned = (try svc.keychain.hubKey(address)).?;
    defer testing.allocator.free(pinned);
    try testing.expectEqualStrings(HUB_KEY, pinned);

    // The v1 token signs hub1:<hub key>:<expiry> with the service key.
    const token = Connect.get(&connects[1].auth, connects[1].auth_len);
    const expiry = try std.fmt.parseInt(i64, token[std.mem.lastIndexOfScalar(u8, token, '.').? + 1 ..], 10);
    const key_file = try fixture.tmp.dir.readFileAlloc(testing.allocator, "auth", 1 << 10);
    defer testing.allocator.free(key_file);
    const expected = try hub_service.authToken(testing.allocator, key_file, HUB_KEY, expiry);
    defer testing.allocator.free(expected);
    try testing.expectEqualStrings(expected, token);
}

test "fake hub: a pinned hub connects once with v1" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var hub: FakeHub = undefined;
    try hub.start(true);
    defer hub.deinit();

    var svc = try fixture.service(&hub);
    defer svc.deinit();
    const address = try svc.addressUrl(testing.allocator);
    defer testing.allocator.free(address);
    try svc.keychain.pinHubKey(address, HUB_KEY);
    _ = try svc.start();
    hub.wait(2, 500);
    svc.stop();

    try testing.expectEqual(@as(usize, 1), connect_count.load(.acquire));
    try testing.expectEqualStrings("1", Connect.get(&connects[0].v, connects[0].v_len));
}

test "fake hub: hub-lite stays on v0" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var hub: FakeHub = undefined;
    try hub.start(false);
    defer hub.deinit();

    var svc = try fixture.service(&hub);
    defer svc.deinit();
    _ = try svc.start();
    hub.wait(2, 500);
    svc.stop();

    try testing.expectEqual(@as(usize, 1), connect_count.load(.acquire));
    try testing.expectEqualStrings("0", Connect.get(&connects[0].v, connects[0].v_len));
    try testing.expectError(error.FileNotFound, fixture.tmp.dir.access("hubs.json", .{}));
}
