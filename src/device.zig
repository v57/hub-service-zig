//! Device key and service certificates (Docs/Devices/protocol.md sections 1
//! and 3).
//!
//! The device key is one ed25519 key per OS instance, in the same file format
//! as the `auth` key. It lives in ~/.hub/device.key (directory 0700, file
//! 0600), /var/lib/hub/device.key for root, or $HUB_DEVICE_KEY, and is
//! created atomically on first use.
//!
//! The device signs a certificate for each service key it runs, sent in the
//! `device` handshake header as `<payload>.<signature>`: payload is the
//! base64url (no padding) of the certificate JSON, and the signature is the
//! device key's base64 ed25519 signature over the payload characters. The
//! service renews it at connect when less than a day of its 7 days is left.

const std = @import("std");
const builtin = @import("builtin");
const keychain = @import("keychain.zig");

const Allocator = std.mem.Allocator;

/// Default certificate lifetime: 7 days.
pub const CERTIFICATE_LIFETIME: i64 = 604_800;
/// A certificate with less than this left is renewed at connect: 1 day.
pub const CERTIFICATE_RENEW: i64 = 86_400;

/// The certificate fields, serialized in this order; null optional fields
/// are left out.
pub const Certificate = struct {
    v: u8 = 1,
    /// Device SPKI.
    device: []const u8,
    /// Service SPKI, the key in `auth`.
    service: []const u8,
    /// 1-128 bytes, unique per device by convention.
    instance: []const u8,
    /// Suggested device name, at most 64 bytes.
    deviceName: ?[]const u8 = null,
    /// macos, ios, linux, windows, android, other...
    platform: ?[]const u8 = null,
    /// Declared parent device name for containers and VMs.
    parent: ?[]const u8 = null,
    /// Reserved: hub SPKI for per-hub device keys.
    hub: ?[]const u8 = null,
    iat: i64,
    exp: i64,

    /// The certificate JSON with no whitespace. Owned; free it.
    pub fn json(self: Certificate, allocator: Allocator) ![]u8 {
        return std.json.Stringify.valueAlloc(allocator, self, .{ .emit_null_optional_fields = false });
    }
};

fn encodeWithKey(allocator: Allocator, key: keychain.KeyBytes, certificate: Certificate) ![]u8 {
    const text = try certificate.json(allocator);
    defer allocator.free(text);
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const payload = try allocator.alloc(u8, encoder.calcSize(text.len));
    defer allocator.free(payload);
    _ = encoder.encode(payload, text);
    const signature = try keychain.signBase64(allocator, key, payload);
    defer allocator.free(signature);
    return std.fmt.allocPrint(allocator, "{s}.{s}", .{ payload, signature });
}

/// The `device` header value for `certificate`, signed with the key file
/// text `device_key_file` (for tests and tools). Owned; free it.
pub fn encodeCertificate(allocator: Allocator, device_key_file: []const u8, certificate: Certificate) ![]u8 {
    return encodeWithKey(allocator, try keychain.parseKeyFile(device_key_file), certificate);
}

fn spkiDigest(spki: []const u8) ![64]u8 {
    var der: [keychain.PUBLIC_DER_LENGTH]u8 = undefined;
    const decoder = std.base64.standard.Decoder;
    if (try decoder.calcSizeForSlice(spki) != der.len) return error.BadPublicKey;
    try decoder.decode(&der, spki);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&der, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

/// Device id: the first 32 lowercase hex characters of SHA-256(SPKI DER).
pub fn deviceId(spki: []const u8) ![32]u8 {
    return (try spkiDigest(spki))[0..32].*;
}

/// The safety code shown when approving a device: "ddd ddd".
pub fn safetyCode(spki: []const u8) ![7]u8 {
    const digest = try spkiDigest(spki);
    const n = try std.fmt.parseInt(u32, digest[0..8], 16) % 1_000_000;
    var out: [7]u8 = undefined;
    _ = try std.fmt.bufPrint(&out, "{d:0>3} {d:0>3}", .{ n / 1000, n % 1000 });
    return out;
}

/// This OS as a certificate platform.
pub fn platform() []const u8 {
    return switch (builtin.os.tag) {
        .macos => "macos",
        .ios => "ios",
        .tvos => "tvos",
        .watchos => "watchos",
        .visionos => "visionos",
        .linux => if (builtin.abi.isAndroid()) "android" else "linux",
        .windows => "windows",
        else => "other",
    };
}

/// False when $HUB_DEVICE turns device mode off (0, off, false, no).
pub fn modeEnabled(allocator: Allocator) bool {
    const value = std.process.getEnvVarOwned(allocator, "HUB_DEVICE") catch return true;
    defer allocator.free(value);
    for ([_][]const u8{ "0", "off", "false", "no" }) |off| {
        if (std.ascii.eqlIgnoreCase(value, off)) return false;
    }
    return true;
}

/// The default device name: $HUB_DEVICE_NAME, else the macOS computer name
/// (scutil --get ComputerName), else the host name. Owned; free it.
pub fn defaultName(allocator: Allocator) !?[]u8 {
    if (std.process.getEnvVarOwned(allocator, "HUB_DEVICE_NAME")) |name| {
        if (name.len > 0) return name;
        allocator.free(name);
    } else |_| {}
    if (builtin.os.tag == .macos) {
        if (std.process.Child.run(.{ .allocator = allocator, .argv = &.{ "scutil", "--get", "ComputerName" } })) |result| {
            defer allocator.free(result.stdout);
            defer allocator.free(result.stderr);
            const name = std.mem.trim(u8, result.stdout, " \r\n\t");
            if (result.term == .Exited and result.term.Exited == 0 and name.len > 0) return try allocator.dupe(u8, name);
        } else |_| {}
    }
    var buffer: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const host = hostName(&buffer) orelse return null;
    return try allocator.dupe(u8, host);
}

/// The host name without a trailing ".local", in `buffer`; null when
/// unavailable.
pub fn hostName(buffer: *[std.posix.HOST_NAME_MAX]u8) ?[]const u8 {
    if (builtin.os.tag == .windows) return null;
    const name = std.posix.gethostname(buffer) catch return null;
    const trimmed = if (std.mem.endsWith(u8, name, ".local")) name[0 .. name.len - 6] else name;
    return if (trimmed.len == 0) null else trimmed;
}

/// $HUB_DEVICE_KEY, /var/lib/hub/device.key for root, else
/// ~/.hub/device.key; null without a home directory. Owned; free it.
pub fn defaultPath(allocator: Allocator) !?[]u8 {
    if (std.process.getEnvVarOwned(allocator, "HUB_DEVICE_KEY")) |path| {
        if (path.len > 0) return path;
        allocator.free(path);
    } else |_| {}
    if (builtin.os.tag != .windows and std.posix.system.getuid() == 0) {
        return try allocator.dupe(u8, "/var/lib/hub/device.key");
    }
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return null;
    defer allocator.free(home);
    if (home.len == 0) return null;
    return try std.fs.path.join(allocator, &.{ home, ".hub", "device.key" });
}

/// Cuts `text` to at most `max` bytes without splitting a UTF-8 sequence.
pub fn truncate(text: []const u8, max: usize) []const u8 {
    if (text.len <= max) return text;
    var end = max;
    while (end > 0 and (text[end] & 0xC0) == 0x80) end -= 1;
    return text[0..end];
}

/// The device key file (created on first use, cached once loaded).
pub const DeviceKey = struct {
    allocator: Allocator,
    path: []u8,
    key: ?keychain.KeyBytes = null,

    pub fn init(allocator: Allocator, path: []const u8) !DeviceKey {
        return .{ .allocator = allocator, .path = try allocator.dupe(u8, path) };
    }

    /// A caller-provided device key (key file text) for apps that keep it in
    /// their own store; no file is read or created. Its path is empty.
    pub fn fromKeyFile(allocator: Allocator, key_file: []const u8) !DeviceKey {
        return .{ .allocator = allocator, .path = try allocator.dupe(u8, ""), .key = try keychain.parseKeyFile(key_file) };
    }

    pub fn deinit(self: *DeviceKey) void {
        self.allocator.free(self.path);
        self.* = undefined;
    }

    pub fn load(self: *DeviceKey) !keychain.KeyBytes {
        if (self.key) |key| return key;
        const key = try keychain.loadOrGenerate(self.allocator, self.path, true);
        self.key = key;
        return key;
    }

    /// The device public key (SPKI base64), creating the key file when
    /// missing. Owned; free it.
    pub fn publicKey(self: *DeviceKey) ![]u8 {
        return keychain.publicKeyBase64(self.allocator, try self.load());
    }

    /// The `device` header value for `certificate`. Owned; free it.
    pub fn sign(self: *DeviceKey, certificate: Certificate) ![]u8 {
        return encodeWithKey(self.allocator, try self.load(), certificate);
    }
};
