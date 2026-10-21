//! hub-server keychain: load-or-generate the `auth` ed25519 key file, sign auth
//! tokens and pin hub keys (TS parity with hub-service/keychain.ts and
//! Docs/Devices/protocol.md section 2).
//!
//! The key file (`auth` in the working directory by default, or $HUBKEY) is
//! the base64 encoding of the 48-byte PKCS8 DER ed25519 private key followed
//! by the 44-byte SPKI DER public key (92 bytes total, 124 base64 chars).
//!
//! signForHub(hub_key, expires) produces `key.<pub>.<sig>.<expiry>`:
//!   pub    = base64 of the 44-byte SPKI public key (bytes 48..92 of the file)
//!   sig    = base64 ed25519 signature over
//!              v0 (hub_key null): `<expiry>`
//!              v1: `hub1:<hub SPKI>:<expiry>` (only valid on that hub)
//!   expiry = DECIMAL epoch-seconds string of now + expires (default 60;
//!            hub-server rejects it once 30 s past or more than 330 s ahead)
//!
//! The hub verifies the signature against the embedded public key and treats
//! the key as the connection identity (owner/host/group permissions).
//!
//! Hub key pins live in `hubs.json` beside the key file:
//! `{"<address>": "<hub SPKI>"}`.

const std = @import("std");

pub const Allocator = std.mem.Allocator;

/// Seconds a fresh token stays valid (protocol.md: SDK default now + 60).
pub const AUTH_EXPIRY = 60;

/// TS keychain layout: PKCS8 DER private key (48 bytes for ed25519) followed
/// by SPKI DER public key (44 bytes for ed25519).
pub const PRIVATE_DER_LENGTH = 48;
pub const PUBLIC_DER_LENGTH = 44;
pub const KEY_FILE_LENGTH = PRIVATE_DER_LENGTH + PUBLIC_DER_LENGTH;

/// Fixed DER prefixes for ed25519 keys (RFC 8410):
/// PKCS8: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 },
///                   OCTET STRING { OCTET STRING { 32-byte seed } } }
/// SPKI:  SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { pub } }
const PKCS8_PREFIX = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20";
const SPKI_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

const Ed25519 = std.crypto.sign.Ed25519;

/// The decoded 92 key-file bytes.
pub const KeyBytes = [KEY_FILE_LENGTH]u8;

pub const Keychain = struct {
    allocator: Allocator,
    /// Key file path (owned); default "auth" in the cwd, or $HUBKEY.
    path: []u8,
    /// Cached decoded key-file bytes (92), lazily loaded; owned.
    key_bytes: ?[]u8 = null,

    pub fn init(allocator: Allocator, path: []const u8) !Keychain {
        return .{
            .allocator = allocator,
            .path = try allocator.dupe(u8, path),
        };
    }

    pub fn deinit(self: *Keychain) void {
        if (self.key_bytes) |bytes| self.allocator.free(bytes);
        self.allocator.free(self.path);
        self.* = undefined;
    }

    /// The service's public key: base64 of the 44-byte SPKI DER
    /// (bytes 48..92 of the key file). Owned; free it.
    pub fn publicKey(self: *Keychain) ![]u8 {
        const bytes = try self.loadBytes();
        return encodeBase64(self.allocator, bytes[PRIVATE_DER_LENGTH..KEY_FILE_LENGTH]);
    }

    /// A fresh v0 auth token: `key.<pub>.<sig>.<expiry>`. Owned; free it.
    pub fn sign(self: *Keychain, expires: i64) ![]u8 {
        return self.signForHub(null, expires);
    }

    /// A fresh token bound to `hub_key` (v1); null signs v0. Owned; free it.
    pub fn signForHub(self: *Keychain, hub_key: ?[]const u8, expires: i64) ![]u8 {
        const bytes = try self.loadBytes();
        return tokenFromKey(self.allocator, bytes[0..KEY_FILE_LENGTH].*, hub_key, std.time.timestamp() + expires);
    }

    /// The base64 signature of the service key over `data` (the hub-net
    /// agent's challenge nonce, for example). Owned; free it.
    pub fn signData(self: *Keychain, data: []const u8) ![]u8 {
        const bytes = try self.loadBytes();
        return signBase64(self.allocator, bytes[0..KEY_FILE_LENGTH].*, data);
    }

    /// The hub key pinned for `address`, or null. Owned; free it.
    pub fn hubKey(self: *Keychain, address: []const u8) !?[]u8 {
        var pins = try self.readPins();
        defer pins.deinit();
        const value = pins.value.object.get(address) orelse return null;
        if (value != .string) return null;
        return try self.allocator.dupe(u8, value.string);
    }

    /// Pins `hub_key` for `address` (replaces an earlier pin).
    pub fn pinHubKey(self: *Keychain, address: []const u8, hub_key: []const u8) !void {
        var pins = try self.readPins();
        defer pins.deinit();
        try pins.value.object.put(address, .{ .string = hub_key });
        try self.writePins(pins.value);
    }

    /// Removes the pin for `address`: connects use v0 again until hub/info
    /// pins the key again. Use it when the hub's key changed on purpose.
    pub fn forgetHubKey(self: *Keychain, address: []const u8) !void {
        var pins = try self.readPins();
        defer pins.deinit();
        if (!pins.value.object.orderedRemove(address)) return;
        try self.writePins(pins.value);
    }

    fn pinsPath(self: *Keychain) ![]u8 {
        const dir = std.fs.path.dirname(self.path) orelse ".";
        return std.fs.path.join(self.allocator, &.{ dir, "hubs.json" });
    }

    /// The pins as an object (empty when the file is missing or corrupt).
    fn readPins(self: *Keychain) !std.json.Parsed(std.json.Value) {
        const path = try self.pinsPath();
        defer self.allocator.free(path);
        const text = std.fs.cwd().readFileAlloc(self.allocator, path, 1 << 20) catch |err| switch (err) {
            error.FileNotFound => try self.allocator.dupe(u8, "{}"),
            else => return err,
        };
        defer self.allocator.free(text);
        if (std.json.parseFromSlice(std.json.Value, self.allocator, text, .{ .allocate = .alloc_always })) |parsed| {
            if (parsed.value == .object) return parsed;
            parsed.deinit();
        } else |_| {}
        return std.json.parseFromSlice(std.json.Value, self.allocator, "{}", .{});
    }

    fn writePins(self: *Keychain, pins: std.json.Value) !void {
        const path = try self.pinsPath();
        defer self.allocator.free(path);
        const text = try std.json.Stringify.valueAlloc(self.allocator, pins, .{});
        defer self.allocator.free(text);
        try writeAtomic(self.allocator, path, text);
    }

    /// Loads the key file (cached), generating and writing it if missing.
    /// Returns the decoded 92 key-file bytes.
    fn loadBytes(self: *Keychain) ![]u8 {
        if (self.key_bytes) |bytes| return bytes;
        const bytes = try loadOrGenerate(self.allocator, self.path, false);
        self.key_bytes = try self.allocator.dupe(u8, &bytes);
        return self.key_bytes.?;
    }
};

/// An auth token for an explicit key file text and expiry (for tests and
/// tools): `hub_key` null signs v0, otherwise v1. Owned; free it.
pub fn authToken(allocator: Allocator, key_file: []const u8, hub_key: ?[]const u8, expiry: i64) ![]u8 {
    return tokenFromKey(allocator, try parseKeyFile(key_file), hub_key, expiry);
}

fn tokenFromKey(allocator: Allocator, key: KeyBytes, hub_key: ?[]const u8, expiry: i64) ![]u8 {
    const data = if (hub_key) |hub|
        try std.fmt.allocPrint(allocator, "hub1:{s}:{d}", .{ hub, expiry })
    else
        try std.fmt.allocPrint(allocator, "{d}", .{expiry});
    defer allocator.free(data);
    const sig_b64 = try signBase64(allocator, key, data);
    defer allocator.free(sig_b64);
    const pub_b64 = try encodeBase64(allocator, key[PRIVATE_DER_LENGTH..KEY_FILE_LENGTH]);
    defer allocator.free(pub_b64);
    return std.fmt.allocPrint(allocator, "key.{s}.{s}.{d}", .{ pub_b64, sig_b64, expiry });
}

/// base64 ed25519 signature over `data` (deterministic, as TS). Owned.
pub fn signBase64(allocator: Allocator, key: KeyBytes, data: []const u8) ![]u8 {
    // PKCS8 DER: 16-byte prefix + 32-byte seed.
    const seed: [32]u8 = key[16..PRIVATE_DER_LENGTH].*;
    const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);
    const signature = try Ed25519.KeyPair.sign(key_pair, data, null);
    return encodeBase64(allocator, &signature.toBytes());
}

/// base64 SPKI of the key. Owned.
pub fn publicKeyBase64(allocator: Allocator, key: KeyBytes) ![]u8 {
    return encodeBase64(allocator, key[PRIVATE_DER_LENGTH..KEY_FILE_LENGTH]);
}

/// Decodes key file text (surrounding whitespace ignored) into 92 bytes.
pub fn parseKeyFile(text: []const u8) !KeyBytes {
    const trimmed = std.mem.trim(u8, text, " \r\n\t");
    const decoder = std.base64.standard.Decoder;
    if ((decoder.calcSizeForSlice(trimmed) catch return error.BadAuthFile) != KEY_FILE_LENGTH) return error.BadAuthFile;
    var bytes: KeyBytes = undefined;
    decoder.decode(&bytes, trimmed) catch return error.BadAuthFile;
    return bytes;
}

/// Loads the key file at `path`, generating it (atomically, mode 0600) when
/// missing. With `private_dirs` the parent directory is created 0700.
pub fn loadOrGenerate(allocator: Allocator, path: []const u8, private_dirs: bool) !KeyBytes {
    const contents = std.fs.cwd().readFileAlloc(allocator, path, 1 << 16) catch |err| switch (err) {
        error.FileNotFound => return generate(allocator, path, private_dirs),
        else => return err,
    };
    defer allocator.free(contents);
    return parseKeyFile(contents);
}

/// Generates a fresh keypair and writes the TS-layout key file.
fn generate(allocator: Allocator, path: []const u8, private_dirs: bool) !KeyBytes {
    const key_pair = Ed25519.KeyPair.generate();

    var file_bytes: KeyBytes = undefined;
    @memcpy(file_bytes[0..16], PKCS8_PREFIX);
    @memcpy(file_bytes[16..PRIVATE_DER_LENGTH], &key_pair.secret_key.seed());
    @memcpy(file_bytes[PRIVATE_DER_LENGTH..60], SPKI_PREFIX);
    @memcpy(file_bytes[60..KEY_FILE_LENGTH], &key_pair.public_key.toBytes());

    if (std.fs.path.dirname(path)) |dir| {
        try std.fs.cwd().makePath(dir);
        if (private_dirs) {
            var handle = try std.fs.cwd().openDir(dir, .{});
            defer handle.close();
            try handle.chmod(0o700);
        }
    }
    const encoded = try encodeBase64(allocator, &file_bytes);
    defer allocator.free(encoded);
    try writeAtomic(allocator, path, encoded);
    return file_bytes;
}

/// Writes `data` to a temp file beside `path` (mode 0600) and renames it.
pub fn writeAtomic(allocator: Allocator, path: []const u8, data: []const u8) !void {
    const tmp = try std.fmt.allocPrint(allocator, "{s}.tmp-{x}", .{ path, std.crypto.random.int(u64) });
    defer allocator.free(tmp);
    {
        var file = try std.fs.cwd().createFile(tmp, .{ .truncate = true, .mode = 0o600 });
        defer file.close();
        try file.writeAll(data);
    }
    std.fs.cwd().rename(tmp, path) catch |err| {
        std.fs.cwd().deleteFile(tmp) catch {};
        return err;
    };
}

pub fn encodeBase64(allocator: Allocator, data: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const size = encoder.calcSize(data.len);
    const out = try allocator.alloc(u8, size);
    errdefer allocator.free(out);
    _ = encoder.encode(out, data);
    return out;
}
