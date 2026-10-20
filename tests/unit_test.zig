//! Unit tests for hub-service-zig (mirrors hub-service-go/service_test.go).
//! Run with: zig build test (or scripts/test).

const std = @import("std");
const hub_service = @import("hub_service");

const testing = std.testing;

test {
    _ = @import("devices_test.zig");
    _ = @import("network_test.zig");
}
const Service = hub_service.Service;
const Value = std.json.Value;

fn testEchoHandler(request: hub_service.PostRequest(?*Service, Value, void)) !?Value {
    return request.body;
}

fn testStreamHandler(body: Value, emit: hub_service.Emit) !void {
    try emit.emit(body);
}

test "services list includes registered paths, sorted by path" {
    var svc = try Service.init(testing.allocator, .{});
    defer svc.deinit();

    _ = try svc.post("echo/upper", testEchoHandler, null);
    _ = try svc.post("echo", testEchoHandler, null);
    _ = try svc.stream("echo/values", testStreamHandler, null);
    _ = try svc.app(.{
        .header = .{ .name = "Echo", .path = "echo/ui" },
        .body = &.{},
    });

    const payload = try svc.updateValue();
    defer hub_service.valueDeinit(testing.allocator, payload);

    const services = payload.object.get("services").?.array;
    try testing.expectEqual(@as(usize, 4), services.items.len);
    const want_paths = [_][]const u8{ "echo", "echo/ui", "echo/upper", "echo/values" };
    for (want_paths, 0..) |expected, i| {
        try testing.expectEqualStrings(expected, services.items[i].object.get("path").?.string);
    }

    const apps = payload.object.get("apps").?.array;
    try testing.expectEqual(@as(usize, 1), apps.items.len);
    try testing.expectEqualStrings("app", apps.items[0].object.get("type").?.string);
    try testing.expectEqualStrings("Echo", apps.items[0].object.get("name").?.string);
    try testing.expectEqualStrings("echo/ui", apps.items[0].object.get("path").?.string);
}

test "settings apply to update payload; group auto-fills from first path segment" {
    var svc = try Service.init(testing.allocator, .{});
    defer svc.deinit();

    _ = try svc.post("echo", testEchoHandler, .{
        .permissions = .{ .name = "Echo", .allows = true },
        .limit = 5,
    });

    const payload = try svc.updateValue();
    defer hub_service.valueDeinit(testing.allocator, payload);

    const services = payload.object.get("services").?.array;
    try testing.expectEqual(@as(usize, 1), services.items.len);
    const entry = services.items[0].object;
    try testing.expectEqual(@as(i64, 5), entry.get("limit").?.integer);
    const perms = entry.get("permissions").?.object;
    try testing.expectEqualStrings("echo", perms.get("group").?.string);
    try testing.expectEqualStrings("Echo", perms.get("name").?.string);
    try testing.expectEqual(true, perms.get("allows").?.bool);
}

test "profile only when name or icon set" {
    var plain = try Service.init(testing.allocator, .{});
    defer plain.deinit();
    try testing.expect(plain.profile == null);

    var named = try Service.init(testing.allocator, .{ .name = "Echo" });
    defer named.deinit();
    try testing.expect(named.profile != null);
    try testing.expectEqualStrings("Echo", named.profile.?.name.?);
    try testing.expect(named.profile.?.icon == null);
}

test "profile value JSON matches wire contract" {
    const icon_value = try hub_service.icon(testing.allocator, "speaker.wave.2", "E");
    defer hub_service.valueDeinit(testing.allocator, icon_value);

    var svc = try Service.init(testing.allocator, .{ .name = "Echo", .icon = icon_value });
    defer svc.deinit();

    const payload = try svc.profileValue();
    defer hub_service.valueDeinit(testing.allocator, payload);

    const json_buf = try std.json.Stringify.valueAlloc(testing.allocator, payload, .{});
    defer testing.allocator.free(json_buf);
    try testing.expectEqualStrings("{\"name\":\"Echo\",\"icon\":{\"symbol\":\"speaker.wave.2\",\"text\":\"E\"}}", json_buf);
}

test "update payload JSON matches wire contract exactly" {
    var svc = try Service.init(testing.allocator, .{});
    defer svc.deinit();

    _ = try svc.post("echo", testEchoHandler, .{
        .permissions = .{ .name = "Echo", .allows = true },
        .limit = 5,
    });

    const payload = try svc.updateValue();
    defer hub_service.valueDeinit(testing.allocator, payload);

    const json_buf = try std.json.Stringify.valueAlloc(testing.allocator, payload, .{});
    defer testing.allocator.free(json_buf);
    try testing.expectEqualStrings(
        "{\"services\":[{\"path\":\"echo\",\"permissions\":{\"group\":\"echo\",\"name\":\"Echo\",\"allows\":true},\"limit\":5}],\"apps\":[]}",
        json_buf,
    );
}

test "send and values before start error" {
    var svc = try Service.init(testing.allocator, .{});
    defer svc.deinit();

    try testing.expectError(error.ServiceNotStarted, svc.send(testing.allocator, "echo", .{ .string = "x" }));
    try testing.expectError(error.ServiceNotStarted, svc.values(testing.allocator, "echo", null));
}

test "app interface has all 5 keys with matching header" {
    var svc = try Service.init(testing.allocator, .{});
    defer svc.deinit();

    _ = try svc.app(.{
        .header = .{ .name = "Echo", .path = "echo/ui" },
        .body = &.{ .{ .string = "hi" } },
    });

    const iface = svc.app_values.get("echo/ui").?;
    try testing.expectEqual(@as(usize, 5), iface.object.count());
    try testing.expect(iface.object.get("header") != null);
    try testing.expect(iface.object.get("body") != null);
    try testing.expect(iface.object.get("top") != null);
    try testing.expect(iface.object.get("bottom") != null);
    try testing.expect(iface.object.get("data") != null);

    const header = iface.object.get("header").?.object;
    try testing.expectEqualStrings("app", header.get("type").?.string);
    try testing.expectEqualStrings("Echo", header.get("name").?.string);
    try testing.expectEqualStrings("echo/ui", header.get("path").?.string);

    const body = iface.object.get("body").?;
    try testing.expect(body == .array);
    try testing.expectEqual(@as(usize, 1), body.array.items.len);
    try testing.expectEqualStrings("hi", body.array.items[0].string);

    try testing.expect(iface.object.get("top").? == .null);
    try testing.expect(iface.object.get("bottom").? == .null);

    const data = iface.object.get("data").?;
    try testing.expect(data == .object);
    try testing.expectEqual(@as(usize, 0), data.object.count());
}

test "element helpers build the wire shapes" {
    const act_value = try hub_service.action(testing.allocator, "echo/upper", .{ .string = "value" }, .{ .string = "value" });
    defer hub_service.valueDeinit(testing.allocator, act_value);

    const btn = try hub_service.button(testing.allocator, "Upper", act_value);
    defer hub_service.valueDeinit(testing.allocator, btn);
    try testing.expectEqualStrings("button", btn.object.get("type").?.string);
    try testing.expectEqualStrings("Upper", btn.object.get("title").?.string);
    const act = btn.object.get("action").?.object;
    try testing.expectEqualStrings("echo/upper", act.get("path").?.string);
    try testing.expectEqualStrings("value", act.get("body").?.string);
    try testing.expectEqualStrings("value", act.get("output").?.string);

    const tf = try hub_service.textField(testing.allocator, "echo", "Text to echo", null);
    defer hub_service.valueDeinit(testing.allocator, tf);
    try testing.expectEqualStrings("textField", tf.object.get("type").?.string);
    try testing.expect(tf.object.get("action") == null);

    const sp = try hub_service.spacer(testing.allocator);
    defer hub_service.valueDeinit(testing.allocator, sp);
    try testing.expectEqualStrings("spacer", sp.object.get("type").?.string);
}

// --- hub-pro keychain (TS parity with hub-service/keychain.ts) ---------------

// Key generated by the TS reference keychain (hub-service/keychain.ts):
// base64(48-byte PKCS8 DER private || 44-byte SPKI DER public).
const TS_AUTH =
    "MC4CAQAwBQYDK2VwBCIEINguo0cc0FACJ0oRV3V/+ZqIyj04ON5wdMJGH4a/do8CMCowBQYDK2VwAyEAHZSDpmbLRjLrOyNMugsStFqK5EYcNluUekE4di+FalQ=";
const TS_PUB =
    "MCowBQYDK2VwAyEAHZSDpmbLRjLrOyNMugsStFqK5EYcNluUekE4di+FalQ=";

fn tmpAuthPath(allocator: std.mem.Allocator) ![]u8 {
    var tmp = std.testing.tmpDir(.{});
    errdefer tmp.cleanup();
    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);
    return std.fmt.allocPrint(allocator, "{s}/auth", .{tmp_path});
}

fn decodeBase64(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const size = try decoder.calcSizeForSlice(encoded);
    const out = try allocator.alloc(u8, size);
    errdefer allocator.free(out);
    try decoder.decode(out, encoded);
    return out;
}

test "keychain: token shape (key.<pub>.<sig>.<decimal expiry>) and signature verifies" {
    const auth_path = try tmpAuthPath(testing.allocator);
    defer testing.allocator.free(auth_path);

    var kc = try hub_service.Keychain.init(testing.allocator, auth_path);
    defer kc.deinit();

    const token = try kc.sign(30);
    defer testing.allocator.free(token);

    var parts = std.mem.splitScalar(u8, token, '.');
    try testing.expectEqualStrings("key", parts.next().?);
    const pub_b64 = parts.next().?;
    const sig_b64 = parts.next().?;
    const expiry = parts.next().?;
    try testing.expect(parts.next() == null);

    // pub part is the base64 of the 44-byte SPKI DER (== publicKey()).
    const pub_key = try kc.publicKey();
    defer testing.allocator.free(pub_key);
    try testing.expectEqualStrings(pub_key, pub_b64);

    // expiry is a DECIMAL epoch-seconds string in the future (TS parity).
    try testing.expect(expiry.len > 0);
    for (expiry) |c| try testing.expect(std.ascii.isDigit(c));
    const expiry_i = try std.fmt.parseInt(i64, expiry, 10);
    try testing.expect(expiry_i >= std.time.timestamp());

    // Signature is 64 bytes over the expiry string and verifies against the
    // raw public key (last 32 bytes of the SPKI DER).
    const spki = try decodeBase64(testing.allocator, pub_b64);
    defer testing.allocator.free(spki);
    try testing.expectEqual(@as(usize, hub_service.PUBLIC_DER_LENGTH), spki.len);
    const raw_pub: [32]u8 = spki[12..][0..32].*;

    const sig = try decodeBase64(testing.allocator, sig_b64);
    defer testing.allocator.free(sig);
    try testing.expectEqual(@as(usize, 64), sig.len);
    const signature = std.crypto.sign.Ed25519.Signature.fromBytes(sig[0..64].*);
    const public_key = try std.crypto.sign.Ed25519.PublicKey.fromBytes(raw_pub);
    try std.crypto.sign.Ed25519.Signature.verify(signature, expiry, public_key);
}

test "keychain: auth file round-trip (generate, reload, same key)" {
    const auth_path = try tmpAuthPath(testing.allocator);
    defer testing.allocator.free(auth_path);

    var kc1 = try hub_service.Keychain.init(testing.allocator, auth_path);
    defer kc1.deinit();
    const pub1 = try kc1.publicKey();
    defer testing.allocator.free(pub1);

    // The file was generated in the cwd at auth_path.
    try std.fs.cwd().access(auth_path, .{});

    // A second instance loads the same file and reproduces the key.
    var kc2 = try hub_service.Keychain.init(testing.allocator, auth_path);
    defer kc2.deinit();
    const pub2 = try kc2.publicKey();
    defer testing.allocator.free(pub2);
    try testing.expectEqualStrings(pub1, pub2);
}

test "keychain: loads a TS-generated auth file and reproduces its public key" {
    const auth_path = try tmpAuthPath(testing.allocator);
    defer testing.allocator.free(auth_path);
    try std.fs.cwd().writeFile(.{ .sub_path = auth_path, .data = TS_AUTH });

    var kc = try hub_service.Keychain.init(testing.allocator, auth_path);
    defer kc.deinit();

    const pub_key_ts = try kc.publicKey();
    defer testing.allocator.free(pub_key_ts);
    try testing.expectEqualStrings(TS_PUB, pub_key_ts);

    const token = try kc.sign(10);
    defer testing.allocator.free(token);
    var parts = std.mem.splitScalar(u8, token, '.');
    _ = parts.next().?; // "key"
    try testing.expectEqualStrings(TS_PUB, parts.next().?);
    const sig_b64 = parts.next().?;
    const expiry = parts.next().?;

    // Signature verifies against the TS public key (raw = last 32 SPKI bytes).
    const spki = try decodeBase64(testing.allocator, TS_PUB);
    defer testing.allocator.free(spki);
    const raw_pub: [32]u8 = spki[12..][0..32].*;
    const sig = try decodeBase64(testing.allocator, sig_b64);
    defer testing.allocator.free(sig);
    const signature = std.crypto.sign.Ed25519.Signature.fromBytes(sig[0..64].*);
    const public_key = try std.crypto.sign.Ed25519.PublicKey.fromBytes(raw_pub);
    try std.crypto.sign.Ed25519.Signature.verify(signature, expiry, public_key);
}
