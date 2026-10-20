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

fn checkCertificate(name: []const u8, instance: []const u8, device_name: []const u8, platform: []const u8, parent: ?[]const u8) !void {
    var vectors = try loadVectors();
    defer vectors.deinit();
    const root = vectors.value;
    const certificate = hub_service.device.Certificate{
        .device = vectorText(root, &.{ "keys", "device", "publicKey" }),
        .service = vectorText(root, &.{ "keys", "service", "publicKey" }),
        .instance = instance,
        .deviceName = device_name,
        .platform = platform,
        .parent = parent,
        .iat = 1792500000,
        .exp = 1793104800,
    };
    const text = try certificate.json(testing.allocator);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings(vectorText(root, &.{ name, "json" }), text);
    const header = try hub_service.device.encodeCertificate(testing.allocator, vectorText(root, &.{ "keys", "device", "keyFile" }), certificate);
    defer testing.allocator.free(header);
    try testing.expectEqualStrings(vectorText(root, &.{ name, "header" }), header);
}

test "vectors: certificate" {
    try checkCertificate("certificate", "s3-local/Backup Disk", "Mac Studio", "macos", null);
}

test "vectors: child certificate" {
    try checkCertificate("childCertificate", "builder", "builder", "linux", "Mac Studio");
}

test "vectors: device id and safety code" {
    var vectors = try loadVectors();
    defer vectors.deinit();
    const root = vectors.value;
    const key = vectorText(root, &.{ "keys", "device", "publicKey" });
    try testing.expectEqualStrings(vectorText(root, &.{ "keys", "device", "deviceId" }), &(try hub_service.device.deviceId(key)));
    try testing.expectEqualStrings(vectorText(root, &.{ "keys", "device", "safetyCode" }), &(try hub_service.device.safetyCode(key)));
}

/// The certificate JSON inside a `device` header.
fn certificatePayload(header: []const u8) !std.json.Parsed(Value) {
    const payload = header[0..std.mem.indexOfScalar(u8, header, '.').?];
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const text = try testing.allocator.alloc(u8, try decoder.calcSizeForSlice(payload));
    defer testing.allocator.free(text);
    try decoder.decode(text, payload);
    return std.json.parseFromSlice(Value, testing.allocator, text, .{ .allocate = .alloc_always });
}

test "device: key file is created 0600 in a 0700 directory" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(&tmp, "hub/device.key");
    defer testing.allocator.free(path);

    var key = try hub_service.device.DeviceKey.init(testing.allocator, path);
    defer key.deinit();
    const first = try key.publicKey();
    defer testing.allocator.free(first);
    try testing.expectEqual(@as(std.fs.File.Mode, 0o600), (try tmp.dir.statFile("hub/device.key")).mode & 0o777);
    var dir = try tmp.dir.openDir("hub", .{});
    defer dir.close();
    try testing.expectEqual(@as(std.fs.File.Mode, 0o700), (try dir.stat()).mode & 0o777);

    var again = try hub_service.device.DeviceKey.init(testing.allocator, path);
    defer again.deinit();
    const second = try again.publicKey();
    defer testing.allocator.free(second);
    try testing.expectEqualStrings(first, second);
}

test "device: certificate renews with a day left" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var svc = try Service.init(testing.allocator, .{
        .key_path = fixture.auth_path,
        .device_key_path = fixture.device_path,
        .instance = "s3-local/Backup Disk",
        .device_name = "Mac Studio",
        .parent = "Host",
    });
    defer svc.deinit();
    const now: i64 = 1_792_500_000;

    const first = try testing.allocator.dupe(u8, (try svc.currentCertificate(now)).?);
    defer testing.allocator.free(first);
    // 2 days left: kept.
    try testing.expectEqualStrings(first, (try svc.currentCertificate(now + 5 * 86_400)).?);
    // 12 hours left: renewed, issued at the new time.
    const later = now + 6 * 86_400 + 43_200;
    const renewed = (try svc.currentCertificate(later)).?;
    try testing.expect(!std.mem.eql(u8, first, renewed));
    var renewed_json = try certificatePayload(renewed);
    defer renewed_json.deinit();
    try testing.expectEqual(later, renewed_json.value.object.get("iat").?.integer);

    var parsed = try certificatePayload(first);
    defer parsed.deinit();
    const fields = parsed.value.object;
    const service_key = try svc.keychain.publicKey();
    defer testing.allocator.free(service_key);
    const device_key = try svc.device_key.?.publicKey();
    defer testing.allocator.free(device_key);
    try testing.expectEqual(@as(i64, 1), fields.get("v").?.integer);
    try testing.expectEqualStrings(device_key, fields.get("device").?.string);
    try testing.expectEqualStrings(service_key, fields.get("service").?.string);
    try testing.expectEqualStrings("s3-local/Backup Disk", fields.get("instance").?.string);
    try testing.expectEqualStrings("Mac Studio", fields.get("deviceName").?.string);
    try testing.expectEqualStrings(hub_service.device.platform(), fields.get("platform").?.string);
    try testing.expectEqualStrings("Host", fields.get("parent").?.string);
    try testing.expectEqual(now + hub_service.device.CERTIFICATE_LIFETIME, fields.get("exp").?.integer);
}

fn noopHandler(request: hub_service.PostRequest(?*Service, Value, void)) !?Value {
    return request.body;
}

fn expectInstance(svc: *const Service, expected: []const u8) !void {
    const instance = try svc.instance(testing.allocator);
    defer testing.allocator.free(instance);
    try testing.expectEqualStrings(expected, instance);
}

test "device: instance defaults" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    // zig build runs the tests in the package directory; $HUB_INSTANCE is unset here.
    if (std.process.getEnvVarOwned(testing.allocator, "HUB_INSTANCE")) |value| {
        testing.allocator.free(value);
    } else |_| {
        var svc = try Service.init(testing.allocator, .{ .key_path = fixture.auth_path, .disable_device = true });
        defer svc.deinit();
        _ = try svc.post("s3/read", noopHandler, null);
        try expectInstance(&svc, "hub-service-zig");

        var named = try Service.init(testing.allocator, .{ .key_path = fixture.auth_path, .disable_device = true, .name = "Backup Disk" });
        defer named.deinit();
        try expectInstance(&named, "Backup Disk");
    }
    {
        var svc = try Service.init(testing.allocator, .{ .key_path = fixture.auth_path, .disable_device = true, .name = "Backup Disk", .instance = "s3-local/Backup Disk" });
        defer svc.deinit();
        try expectInstance(&svc, "s3-local/Backup Disk");
        try testing.expect((try svc.currentCertificate(0)) == null);
    }
    try testing.expectEqualStrings("ab", hub_service.device.truncate("ab\xc3\xa9", 3));
}

test "device: a caller-provided key reads no file" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var svc = try Service.init(testing.allocator, .{
        .key_path = fixture.auth_path,
        .device_key_path = fixture.device_path,
        .device_key = "MC4CAQAwBQYDK2VwBCIEIAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDMCowBQYDK2VwAyEA7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=",
        .instance = "x",
    });
    defer svc.deinit();
    var parsed = try certificatePayload((try svc.currentCertificate(1)).?);
    defer parsed.deinit();
    try testing.expectEqualStrings("MCowBQYDK2VwAyEA7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=", parsed.value.object.get("device").?.string);
    try testing.expectError(error.FileNotFound, fixture.tmp.dir.access("device.key", .{}));
}

test "pin addresses are normalized" {
    const cases = [_][2][]const u8{
        .{ "1997", "ws://localhost:1997" },
        .{ "WSS://Hub.Example.COM/", "wss://hub.example.com" },
        .{ "ws://Host:80/Path/", "ws://host:80/Path" },
    };
    for (cases) |case| {
        const address = try hub_service.normalizeHubAddress(testing.allocator, case[0]);
        defer testing.allocator.free(address);
        try testing.expectEqualStrings(case[1], address);
    }
    var svc = try Service.init(testing.allocator, .{ .address = .{ .port = 1997 }, .disable_device = true });
    defer svc.deinit();
    const address = try svc.pinAddress(testing.allocator);
    defer testing.allocator.free(address);
    try testing.expectEqualStrings("ws://localhost:1997", address);
}

test "vectors: caller" {
    var vectors = try loadVectors();
    defer vectors.deinit();
    const root = vectors.value;
    const caller = hub_service.Caller.fromContext(vector(root, &.{ "caller", "context" })).?;
    try testing.expectEqualStrings(vectorText(root, &.{ "keys", "service", "publicKey" }), caller.key.?);
    try testing.expectEqualStrings(vectorText(root, &.{ "keys", "device", "deviceId" }), caller.device.?.id);
    try testing.expectEqualStrings("Mac Studio", caller.device.?.name);
    try testing.expectEqual(@as(usize, 1), caller.groups.len);
    try testing.expect(caller.inGroup("owners"));
    try testing.expect(caller.owner);
    try testing.expect(caller.via == null and caller.claimed == null);
    try testing.expectEqualStrings(vectorText(root, &.{ "keys", "hub", "publicKey" }), caller.hub_key.?);
}

fn parseContext(text: []const u8) !std.json.Parsed(Value) {
    return std.json.parseFromSlice(Value, testing.allocator, text, .{ .allocate = .alloc_always });
}

test "caller: absent, anonymous and through a merged hub" {
    {
        var context = try parseContext("{\"service\":\"abc\"}");
        defer context.deinit();
        try testing.expect(hub_service.Caller.fromContext(context.value) == null);
    }
    try testing.expect(hub_service.Caller.fromContext(.null) == null);
    {
        var context = try parseContext("{\"hub\":{\"caller\":{\"groups\":[],\"owner\":false},\"hubKey\":\"H\"}}");
        defer context.deinit();
        const caller = hub_service.Caller.fromContext(context.value).?;
        try testing.expect(caller.key == null and caller.device == null and !caller.owner);
        try testing.expectEqualStrings("H", caller.hub_key.?);
    }
    {
        var context = try parseContext("{\"hub\":{\"caller\":{\"key\":\"M\",\"groups\":[\"g1\",\"g2\"],\"owner\":false,\"via\":\"V\",\"claimed\":{\"key\":\"K\",\"owner\":true}},\"hubKey\":\"H\"}}");
        defer context.deinit();
        const caller = hub_service.Caller.fromContext(context.value).?;
        try testing.expectEqualStrings("M", caller.key.?);
        try testing.expect(caller.inGroup("g2") and !caller.inGroup("owners"));
        try testing.expectEqualStrings("V", caller.via.?);
        try testing.expectEqualStrings("K", caller.claimed.?.object.get("key").?.string);
    }
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
            .device_key_path = self.device_path,
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

    const address = try svc.pinAddress(testing.allocator);
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
    const address = try svc.pinAddress(testing.allocator);
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

test "fake hub: every connect carries the device certificate" {
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
    const first = Connect.get(&connects[0].device, connects[0].device_len);
    // Same certificate on the reconnect (renewed only with a day left).
    try testing.expectEqualStrings(first, Connect.get(&connects[1].device, connects[1].device_len));
    var parsed = try certificatePayload(first);
    defer parsed.deinit();
    const service_key = try svc.keychain.publicKey();
    defer testing.allocator.free(service_key);
    try testing.expectEqualStrings(service_key, parsed.value.object.get("service").?.string);
}

test "fake hub: disabled device mode sends no certificate" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var hub: FakeHub = undefined;
    try hub.start(false);
    defer hub.deinit();

    var svc = try Service.init(testing.allocator, .{
        .address = .{ .port = hub.server.port() },
        .key_path = fixture.auth_path,
        .disable_device = true,
    });
    defer svc.deinit();
    _ = try svc.start();
    hub.wait(1, 5000);
    svc.stop();

    try testing.expectEqual(@as(usize, 1), connect_count.load(.acquire));
    try testing.expectEqual(@as(usize, 0), connects[0].device_len);
    try testing.expectError(error.FileNotFound, fixture.tmp.dir.access("device.key", .{}));
}

fn whoHandler(request: hub_service.PostRequest(?*Service, Value, Value)) !?Value {
    const caller = hub_service.Caller.fromContext(request.context) orelse return .null;
    return .{ .string = if (caller.owner) caller.device.?.name else caller.key orelse "-" };
}

fn whoStream(_: Value, emit: hub_service.Emit) !void {
    const caller = emit.caller() orelse return emit.emit(.null);
    try emit.emit(.{ .string = caller.key orelse "-" });
}

test "fake hub: handlers see the caller" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var hub: FakeHub = undefined;
    try hub.start(false);
    defer hub.deinit();

    var svc = try fixture.service(&hub);
    defer svc.deinit();
    _ = try svc.post("who", whoHandler, null);
    _ = try svc.stream("who/stream", whoStream, null);
    _ = try svc.start();
    hub.wait(1, 5000);

    var sender = hub_sender.?;
    const Context = struct { hub: struct {
        caller: struct { key: []const u8, device: struct { id: []const u8, name: []const u8 }, groups: []const []const u8, owner: bool },
        hubKey: []const u8,
    } };
    const context = Context{ .hub = .{
        .caller = .{ .key = "K", .device = .{ .id = "d", .name = "Mac Studio" }, .groups = &.{"owners"}, .owner = true },
        .hubKey = HUB_KEY,
    } };
    {
        var reply = try sender.sendWithContext(testing.allocator, []const u8, "who", 7, context);
        defer reply.deinit(testing.allocator);
        try testing.expectEqualStrings("Mac Studio", reply.ok.?);
    }
    {
        // A call without hub context has no caller (and still succeeds).
        var reply = try sender.send(testing.allocator, ?[]const u8, "who", 7);
        defer reply.deinit(testing.allocator);
        try testing.expect(reply == .ok and reply.ok.? == null);
    }
    {
        var values = try sender.values(testing.allocator, i64, []const u8, Context, "who/stream", 7, context);
        defer values.close();
        var next = try values.next(testing.allocator);
        defer next.deinit(testing.allocator);
        try testing.expectEqualStrings("K", next.item);
    }
    svc.stop();
}
