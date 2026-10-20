//! Hub Network share publishing against a fake hub-net agent (HTTP on a Unix
//! socket, in a thread) and an in-process fake hub (a channel-zig server).

const std = @import("std");
const hub_service = @import("hub_service");
const channel = hub_service.channel;

const testing = std.testing;
const Service = hub_service.Service;
const Value = std.json.Value;
const NetworkShare = hub_service.NetworkShare;

// --- fake agent -------------------------------------------------------------

const Agent = struct {
    server: std.net.Server,
    thread: std.Thread,
    stop: std.atomic.Value(bool) = .init(false),
    attest_status: std.atomic.Value(u16) = .init(200),
    ttl: std.atomic.Value(i64) = .init(300),
    chunked: std.atomic.Value(bool) = .init(false),
    bad_signatures: std.atomic.Value(usize) = .init(0),

    fn start(self: *Agent, path: []const u8) !void {
        self.* = .{ .server = undefined, .thread = undefined };
        const address = try std.net.Address.initUnix(path);
        self.server = try address.listen(.{ .force_nonblocking = true });
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn deinit(self: *Agent) void {
        self.stop.store(true, .release);
        self.thread.join();
        self.server.deinit();
    }

    fn run(self: *Agent) void {
        while (!self.stop.load(.acquire)) {
            const connection = self.server.accept() catch {
                std.Thread.sleep(2 * std.time.ns_per_ms);
                continue;
            };
            defer connection.stream.close();
            self.handle(connection.stream) catch {};
        }
    }

    fn handle(self: *Agent, stream: std.net.Stream) !void {
        var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        // The accepted socket inherits O_NONBLOCK on some systems.
        const flags = try std.posix.fcntl(stream.handle, std.posix.F.GETFL, 0);
        _ = try std.posix.fcntl(stream.handle, std.posix.F.SETFL, flags & ~@as(usize, 1 << @bitOffsetOf(std.posix.O, "NONBLOCK")));

        var request = std.ArrayListUnmanaged(u8){};
        var buffer: [4096]u8 = undefined;
        const head, const body = while (true) {
            const n = try std.posix.read(stream.handle, &buffer);
            if (n == 0) return;
            try request.appendSlice(arena, buffer[0..n]);
            const split = std.mem.indexOf(u8, request.items, "\r\n\r\n") orelse continue;
            const length_at = std.ascii.indexOfIgnoreCase(request.items[0..split], "content-length:") orelse continue;
            const length_end = std.mem.indexOfPos(u8, request.items, length_at, "\r\n").?;
            const length = try std.fmt.parseInt(usize, std.mem.trim(u8, request.items[length_at + 15 .. length_end], " "), 10);
            if (request.items.len >= split + 4 + length) break .{ request.items[0..split], request.items[split + 4 .. split + 4 + length] };
        };
        const json = try std.json.parseFromSliceLeaky(Value, arena, body, .{});
        var status: u16 = 200;
        var reply: []const u8 = "";
        if (std.mem.startsWith(u8, head, "POST /challenge ")) {
            reply = "{\"version\":1,\"nonce\":\"bm9uY2U\",\"key\":\"agent-key\"}";
        } else if (std.mem.startsWith(u8, head, "POST /attest ")) {
            const key = json.object.get("serviceKey").?.string;
            const signature = json.object.get("signature").?.string;
            if (!verify(key, "bm9uY2U", signature)) {
                _ = self.bad_signatures.fetchAdd(1, .monotonic);
                status = 401;
                reply = "{\"error\":\"bad signature\"}\n";
            } else if (self.attest_status.load(.acquire) != 200) {
                status = self.attest_status.load(.acquire);
                reply = "{\"error\":\"denied\"}\n";
            } else {
                const now = std.time.timestamp();
                const target = try std.json.Stringify.valueAlloc(arena, json.object.get("target").?, .{});
                reply = try std.fmt.allocPrint(arena,
                    \\{{"version":1,"attestationId":"att","serviceKey":"{s}","key":"agent-key","shareName":"{s}","protocol":"{s}","target":{s},"issuedAt":"{s}","expiresAt":"{s}","signature":"c2ln","extra":"kept"}}
                , .{ key, json.object.get("shareName").?.string, json.object.get("protocol").?.string, target, try iso(arena, now - 1), try iso(arena, now + self.ttl.load(.acquire)) });
            }
        } else {
            status = 404;
            reply = "not found";
        }
        const response = if (self.chunked.load(.acquire))
            try std.fmt.allocPrint(arena, "HTTP/1.1 {d} X\r\nTransfer-Encoding: chunked\r\n\r\n{x}\r\n{s}\r\n0\r\n\r\n", .{ status, reply.len, reply })
        else
            try std.fmt.allocPrint(arena, "HTTP/1.1 {d} X\r\nContent-Length: {d}\r\n\r\n{s}", .{ status, reply.len, reply });
        try stream.writeAll(response);
    }
};

fn verify(spki_b64: []const u8, data: []const u8, signature_b64: []const u8) bool {
    var spki: [44]u8 = undefined;
    var signature: [64]u8 = undefined;
    std.base64.standard.Decoder.decode(&spki, spki_b64) catch return false;
    std.base64.standard.Decoder.decode(&signature, signature_b64) catch return false;
    const key = std.crypto.sign.Ed25519.PublicKey.fromBytes(spki[12..44].*) catch return false;
    std.crypto.sign.Ed25519.Signature.fromBytes(signature).verify(data, key) catch return false;
    return true;
}

fn iso(allocator: std.mem.Allocator, seconds: i64) ![]u8 {
    const epoch = std.time.epoch.EpochSeconds{ .secs = @intCast(seconds) };
    const day = epoch.getEpochDay().calculateYearDay();
    const month_day = day.calculateMonthDay();
    const time = epoch.getDaySeconds();
    return std.fmt.allocPrint(allocator, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.123456789Z", .{
        day.year,                       month_day.month.numeric(),        month_day.day_index + 1,
        time.getHoursIntoDay(), time.getMinutesIntoHour(), time.getSecondsIntoMinute(),
    });
}

// --- fake hub ---------------------------------------------------------------

const HubState = struct {};

var hub_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
var hub_mutex: std.Thread.Mutex = .{};
var replace_count: usize = 0;
var last_replace: []const u8 = "";

fn replyNull(_: channel.PostRequest(HubState, Value, void)) !?Value {
    return null;
}

fn replyReplace(request: channel.PostRequest(HubState, Value, void)) !?Value {
    hub_mutex.lock();
    defer hub_mutex.unlock();
    const arena = hub_arena.allocator();
    replace_count += 1;
    last_replace = try std.json.Stringify.valueAlloc(arena, request.body, .{});
    var publications = std.json.Array.init(arena);
    for (request.body.object.get("shares").?.array.items, 0..) |share, index| {
        var publication = std.json.ObjectMap.init(arena);
        try publication.put("version", .{ .integer = 1 });
        try publication.put("resourceId", .{ .string = try std.fmt.allocPrint(arena, "hnr1_{s}", .{share.object.get("name").?.string}) });
        try publication.put("authority", .{ .string = "share.hub.invalid" });
        try publication.put("providerId", .{ .string = "provider" });
        try publication.put("protocol", .{ .string = try arena.dupe(u8, share.object.get("protocol").?.string) });
        try publication.put("overlayAddress", .{ .string = "100.96.0.2" });
        try publication.put("port", .{ .integer = 4000 + @as(i64, @intCast(index)) });
        try publications.append(.{ .object = publication });
    }
    var reply = std.json.ObjectMap.init(arena);
    try reply.put("shares", .{ .array = publications });
    return .{ .object = reply };
}

fn lastReplace() !std.json.Parsed(Value) {
    hub_mutex.lock();
    defer hub_mutex.unlock();
    return std.json.parseFromSlice(Value, testing.allocator, last_replace, .{});
}

fn replaceCount() usize {
    hub_mutex.lock();
    defer hub_mutex.unlock();
    return replace_count;
}

const Fixture = struct {
    tmp: std.testing.TmpDir,
    dir: []u8,
    agent_path: []u8,
    ch: channel.Channel(HubState),
    server: channel.Server(HubState),
    svc: Service,

    fn init(self: *Fixture) !void {
        hub_mutex.lock();
        replace_count = 0;
        last_replace = "";
        hub_mutex.unlock();
        self.tmp = std.testing.tmpDir(.{});
        // Short: Unix socket paths are limited to ~104 bytes.
        self.dir = try std.fmt.allocPrint(testing.allocator, "/tmp/hszn-{x}", .{std.crypto.random.int(u32)});
        try std.fs.cwd().makePath(self.dir);
        self.agent_path = try std.fs.path.join(testing.allocator, &.{ self.dir, "agent.sock" });
        self.ch = channel.Channel(HubState).init(testing.allocator);
        _ = try self.ch.post("hub/service/update", replyNull);
        _ = try self.ch.post("network/shares/replace", replyReplace);
        self.server = try self.ch.listen(testing.allocator, 0, .{});
        const auth = try std.fs.path.join(testing.allocator, &.{ self.dir, "auth" });
        defer testing.allocator.free(auth);
        const device_key = try std.fs.path.join(testing.allocator, &.{ self.dir, "device.key" });
        defer testing.allocator.free(device_key);
        self.svc = try Service.init(testing.allocator, .{
            .address = .{ .port = self.server.port() },
            .key_path = auth,
            .device_key_path = device_key,
            .agent_socket = self.agent_path,
        });
    }

    fn deinit(self: *Fixture) void {
        self.svc.deinit();
        self.server.deinit();
        self.ch.deinit();
        std.fs.cwd().deleteTree(self.dir) catch {};
        testing.allocator.free(self.agent_path);
        testing.allocator.free(self.dir);
        self.tmp.cleanup();
    }

    fn waitConnected(self: *Fixture) void {
        var waited: usize = 0;
        while (waited < 5000) : (waited += 1) {
            self.svc.mutex.lock();
            const connected = self.svc.client != null and self.svc.client.?.isConnected();
            self.svc.mutex.unlock();
            if (connected) break;
            std.Thread.sleep(std.time.ns_per_ms);
        }
        std.Thread.sleep(200 * std.time.ns_per_ms);
    }
};

test "shares: declared shares are published on connect" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var agent: Agent = undefined;
    try agent.start(fixture.agent_path);
    defer agent.deinit();

    try fixture.svc.share(.{ .name = "s3", .protocol = "tcp", .host = "127.0.0.1", .port = 9001, .policy_json = "{ \"mode\": \"group\", \"group\": \"editors\" }" });
    _ = try fixture.svc.start();
    var waited: usize = 0;
    while (replaceCount() == 0 and waited < 5000) : (waited += 1) std.Thread.sleep(std.time.ns_per_ms);
    std.Thread.sleep(100 * std.time.ns_per_ms);
    fixture.svc.stop();

    try testing.expectEqual(@as(usize, 1), replaceCount());
    try testing.expectEqual(@as(usize, 0), agent.bad_signatures.load(.acquire));
    var body = try lastReplace();
    defer body.deinit();
    const wire = body.value.object.get("shares").?.array.items[0].object;
    try testing.expectEqualStrings("s3", wire.get("name").?.string);
    try testing.expectEqual(@as(i64, 1), wire.get("version").?.integer);
    try testing.expectEqualStrings("editors", wire.get("policy").?.object.get("group").?.string);
    const service_key = try fixture.svc.keychain.publicKey();
    defer testing.allocator.free(service_key);
    try testing.expectEqualStrings(service_key, wire.get("attestation").?.object.get("serviceKey").?.string);
    // Forwarded verbatim, unknown fields included.
    try testing.expectEqualStrings("kept", wire.get("attestation").?.object.get("extra").?.string);

    const publications = try fixture.svc.sharePublications(testing.allocator);
    defer testing.allocator.free(publications);
    try testing.expect(std.mem.indexOf(u8, publications, "\"resourceId\":\"hnr1_s3\"") != null);
    try testing.expect(std.mem.indexOf(u8, publications, "\"overlayAddress\":\"100.96.0.2\"") != null);
}

test "shares: publish, update and remove" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var agent: Agent = undefined;
    try agent.start(fixture.agent_path);
    defer agent.deinit();
    agent.chunked.store(true, .release);

    var web = NetworkShare{ .name = "web", .protocol = "tcp", .host = "localhost", .port = 8080, .policy_json = "{\"mode\":\"hub\"}" };
    try testing.expectError(error.ServiceNotStarted, fixture.svc.publishShare(web));
    _ = try fixture.svc.start();
    fixture.waitConnected();
    try testing.expectEqual(@as(usize, 0), replaceCount());

    try fixture.svc.publishShare(web);
    try fixture.svc.publishShare(.{ .name = "api", .protocol = "udp", .host = "localhost", .port = 9090 });
    try testing.expectEqual(@as(usize, 2), replaceCount());
    {
        var body = try lastReplace();
        defer body.deinit();
        const shares = body.value.object.get("shares").?.array.items;
        try testing.expectEqual(@as(usize, 2), shares.len);
        // Name order; the default policy is private.
        try testing.expectEqualStrings("api", shares[0].object.get("name").?.string);
        try testing.expectEqualStrings("private", shares[0].object.get("policy").?.object.get("mode").?.string);
    }

    web.port = 8081;
    try fixture.svc.publishShare(web);
    {
        var body = try lastReplace();
        defer body.deinit();
        const shares = body.value.object.get("shares").?.array.items;
        try testing.expectEqual(@as(i64, 8081), shares[1].object.get("target").?.object.get("port").?.integer);
    }

    try fixture.svc.removeShare("web");
    {
        var body = try lastReplace();
        defer body.deinit();
        try testing.expectEqual(@as(usize, 1), body.value.object.get("shares").?.array.items.len);
    }
    const publications = try fixture.svc.sharePublications(testing.allocator);
    defer testing.allocator.free(publications);
    try testing.expect(std.mem.indexOf(u8, publications, "hnr1_api") != null);
    try testing.expect(std.mem.indexOf(u8, publications, "hnr1_web") == null);

    try testing.expectError(error.ShareFailed, fixture.svc.removeShare("web"));
    try testing.expectEqualStrings("Share 'web' not found", fixture.svc.shareError());
    fixture.svc.stop();
}

test "shares: agent failures roll back" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    _ = try fixture.svc.start();
    fixture.waitConnected();
    const web = NetworkShare{ .name = "web", .protocol = "tcp", .host = "localhost", .port = 8080 };

    // No agent.
    try testing.expectError(error.ShareFailed, fixture.svc.publishShare(web));
    try testing.expect(std.mem.indexOf(u8, fixture.svc.shareError(), "unavailable") != null);

    var agent: Agent = undefined;
    try agent.start(fixture.agent_path);
    defer agent.deinit();

    // The agent refuses.
    agent.attest_status.store(403, .release);
    try testing.expectError(error.ShareFailed, fixture.svc.publishShare(web));
    try testing.expectEqualStrings("Hub Network agent rejected attestation (403): {\"error\":\"denied\"}", fixture.svc.shareError());

    // An attestation that is already expired.
    agent.attest_status.store(200, .release);
    agent.ttl.store(-5, .release);
    try testing.expectError(error.ShareFailed, fixture.svc.publishShare(web));
    try testing.expectEqualStrings("Local-agent attestation is expired", fixture.svc.shareError());
    try testing.expectEqual(@as(usize, 0), replaceCount());

    // Nothing above stayed declared.
    agent.ttl.store(300, .release);
    try fixture.svc.publishShare(.{ .name = "api", .protocol = "tcp", .host = "localhost", .port = 9090 });
    const publications = try fixture.svc.sharePublications(testing.allocator);
    defer testing.allocator.free(publications);
    try testing.expect(std.mem.indexOf(u8, publications, "hnr1_api") != null);
    try testing.expect(std.mem.indexOf(u8, publications, "hnr1_web") == null);
    fixture.svc.stop();
}

test "shares: invalid shares" {
    var svc = try Service.init(testing.allocator, .{ .disable_device = true });
    defer svc.deinit();
    try testing.expectError(error.ShareFailed, svc.share(.{ .name = "x", .protocol = "sctp", .host = "localhost", .port = 1 }));
    try testing.expectEqualStrings("Invalid Hub Network protocol", svc.shareError());
    try testing.expectError(error.ShareFailed, svc.share(.{ .name = "a\nb", .protocol = "tcp", .host = "localhost", .port = 1 }));
    try testing.expectError(error.ShareFailed, svc.share(.{ .name = "x", .protocol = "tcp", .host = "localhost", .port = 0 }));
    try testing.expectError(error.ShareFailed, svc.share(.{ .name = "x", .protocol = "tcp", .host = "localhost", .port = 1, .policy_json = "{\"mode\":\"keys\",\"keys\":[]}" }));
    try testing.expectEqualStrings("Invalid Hub Network policy", svc.shareError());
}

test "shares: ISO times" {
    const parse = hub_service.network.parseIsoMs;
    try testing.expectEqual(@as(?i64, 0), parse("1970-01-01T00:00:00Z"));
    try testing.expectEqual(@as(?i64, 1_792_527_120_500), parse("2026-10-20T20:12:00.5Z"));
    try testing.expectEqual(@as(?i64, 1_792_527_120_500), parse("2026-10-20T23:12:00.500123+03:00"));
    try testing.expectEqual(@as(?i64, null), parse("2026-10-20T20:12:00"));
    try testing.expectEqual(@as(?i64, null), parse("yesterday"));
    const text = try iso(testing.allocator, 1_792_527_120);
    defer testing.allocator.free(text);
    try testing.expectEqual(@as(?i64, 1_792_527_120_123), parse(text));
}
