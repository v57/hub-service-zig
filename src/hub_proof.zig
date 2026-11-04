//! Auth v2's client side (Docs/Devices/protocol.md section 2): before every
//! connect the SDK asks hub/info on an anonymous connection with a fresh nonce,
//! and sends its token only if the hub proved the key it claims, over that nonce.

const std = @import("std");
const channel = @import("channel");
const keychain = @import("keychain.zig");

const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const Ed25519 = std.crypto.sign.Ed25519;

/// How a connection to an address travels. `refused` is plain ws:// beyond
/// loopback, the overlay and the LAN: it isn't dialed unless `allow_plaintext`
/// says so. The names are the protocol's (`@tagName`).
pub const HubTransport = enum { encrypted, loopback, overlay, localNetwork, refused };

/// Classifies an address before anything is dialed. A bare port is loopback,
/// and a host:port without a scheme reads as ws://.
pub fn hubTransportOf(address: []const u8) HubTransport {
    if (address.len > 0 and allDigits(address)) return .loopback;

    var scheme: []const u8 = "ws";
    var rest = address;
    if (std.mem.indexOf(u8, address, "://")) |end| {
        scheme = address[0..end];
        rest = address[end + 3..];
    }
    if (eqlLower(scheme, "wss") or eqlLower(scheme, "https") or eqlLower(scheme, "quic")) return .encrypted;
    if (!eqlLower(scheme, "ws") and !eqlLower(scheme, "http")) return .refused;

    // The authority without user info.
    var authority = rest[0 .. std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len];
    if (std.mem.indexOfScalar(u8, authority, '@')) |at| authority = authority[at + 1..];

    var buffer: [256]u8 = undefined;
    if (authority.len > 0 and authority[0] == '[') {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse authority.len;
        const inner = authority[1..close];
        if (inner.len > buffer.len) return .refused;
        const host = std.ascii.lowerString(&buffer, inner);
        if (std.mem.eql(u8, host, "::1")) return .loopback;
        for ([_][]const u8{ "fc", "fd", "fe8", "fe9", "fea", "feb" }) |prefix| {
            if (std.mem.startsWith(u8, host, prefix)) return .localNetwork;
        }
        return .refused;
    }

    const name = authority[0 .. std.mem.indexOfScalar(u8, authority, ':') orelse authority.len];
    if (name.len > buffer.len) return .refused;
    var host = std.ascii.lowerString(&buffer, name);
    if (host.len > 0 and host[host.len - 1] == '.') host = host[0 .. host.len - 1];

    if (parseIpv4(host)) |ip| {
        if (ip[0] == 127) return .loopback;
        if (ip[0] == 100 and ip[1] >= 64 and ip[1] <= 127) return .overlay;
        if (ip[0] == 10 or (ip[0] == 172 and ip[1] >= 16 and ip[1] <= 31) or (ip[0] == 192 and ip[1] == 168) or (ip[0] == 169 and ip[1] == 254)) {
            return .localNetwork;
        }
        return .refused;
    }
    if (std.mem.eql(u8, host, "localhost") or std.mem.endsWith(u8, host, ".localhost")) return .loopback;
    if (std.mem.endsWith(u8, host, ".hub.invalid")) return .overlay;
    if (std.mem.endsWith(u8, host, ".local")) return .localNetwork;
    return .refused;
}

fn allDigits(text: []const u8) bool {
    for (text) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

fn eqlLower(text: []const u8, lower: []const u8) bool {
    return std.ascii.eqlIgnoreCase(text, lower);
}

/// The first two of four decimal bytes, each one to three digits.
fn parseIpv4(host: []const u8) ?[2]u16 {
    var parts = std.mem.splitScalar(u8, host, '.');
    var bytes: [4]u16 = undefined;
    for (&bytes) |*byte| {
        const part = parts.next() orelse return null;
        if (part.len == 0 or part.len > 3 or !allDigits(part)) return null;
        byte.* = std.fmt.parseInt(u16, part, 10) catch return null;
        if (byte.* > 255) return null;
    }
    if (parts.next() != null) return null;
    return .{ bytes[0], bytes[1] };
}

/// The nonce for one hub/info: 32 fresh random bytes in base64url, no padding.
/// Owned; free it.
pub fn makeClientNonce(allocator: Allocator) ![]u8 {
    var bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&bytes);
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const out = try allocator.alloc(u8, encoder.calcSize(bytes.len));
    _ = encoder.encode(out, &bytes);
    return out;
}

/// The string a hub/info proof signs: `hubinfo1:<hub key>:<nonce>`. Owned.
pub fn hubInfoSignedData(allocator: Allocator, hub_key: []const u8, nonce: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "hubinfo1:{s}:{s}", .{ hub_key, nonce });
}

/// An answer to hub/info with a nonce; the fields borrow from what it was read
/// from.
pub const HubInfo = struct {
    key: []const u8,
    proof: []const u8,
    challenge: []const u8,

    /// The answer when key, proof and challenge are strings and the challenge is
    /// what the protocol allows: base64url characters, at most 128. It goes into
    /// a header, so anything else would add one.
    pub fn parse(value: Value) ?HubInfo {
        if (value != .object) return null;
        const key = value.object.get("key") orelse return null;
        const proof = value.object.get("proof") orelse return null;
        const challenge = value.object.get("challenge") orelse return null;
        if (key != .string or proof != .string or challenge != .string) return null;
        if (challenge.string.len == 0 or challenge.string.len > 128) return null;
        for (challenge.string) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return null;
        }
        return .{ .key = key.string, .proof = proof.string, .challenge = challenge.string };
    }

    /// True when the answer proves its key over `nonce`. A relayed answer passes
    /// too, so it never decides which credentials a hub gets.
    pub fn proves(self: HubInfo, allocator: Allocator, nonce: []const u8) bool {
        const data = hubInfoSignedData(allocator, self.key, nonce) catch return false;
        defer allocator.free(data);
        return verifyKey(self.key, data, self.proof);
    }
};

/// True when `signature` (standard base64) is a valid ed25519 signature by the
/// SPKI base64 `key` over `data`.
pub fn verifyKey(key: []const u8, data: []const u8, signature: []const u8) bool {
    const decoder = std.base64.standard.Decoder;
    if ((decoder.calcSizeForSlice(key) catch return false) != keychain.PUBLIC_DER_LENGTH) return false;
    if ((decoder.calcSizeForSlice(signature) catch return false) != Ed25519.Signature.encoded_length) return false;
    var spki: [keychain.PUBLIC_DER_LENGTH]u8 = undefined;
    decoder.decode(&spki, key) catch return false;
    if (!std.mem.startsWith(u8, &spki, keychain.SPKI_PREFIX)) return false;
    var bytes: [Ed25519.Signature.encoded_length]u8 = undefined;
    decoder.decode(&bytes, signature) catch return false;
    const public_key = Ed25519.PublicKey.fromBytes(spki[keychain.SPKI_PREFIX.len..].*) catch return false;
    Ed25519.Signature.fromBytes(bytes).verify(data, public_key) catch return false;
    return true;
}

/// What a hub proved. Owned; deinit it.
pub const ProvenHub = struct {
    key: []u8,
    challenge: []u8,

    pub fn deinit(self: ProvenHub, allocator: Allocator) void {
        allocator.free(self.key);
        allocator.free(self.challenge);
    }
};

const Anonymous = struct {};

/// Asks the hub at `address` (a port or a URL) for its key and a challenge on a
/// short anonymous connection, with a channel of its own, so it serves none of
/// the service's handlers. error.HubDidNotProveKey for any answer without a valid
/// proof. channel-zig has no call timeout, so a hub that accepts and never
/// answers holds this until it closes the connection.
pub fn askHub(allocator: Allocator, address: anytype) !ProvenHub {
    const nonce = try makeClientNonce(allocator);
    defer allocator.free(nonce);
    var ch = channel.Channel(Anonymous).init(allocator);
    defer ch.deinit();
    var client = try ch.connect(allocator, address, .{});
    defer client.deinit();
    var result = try client.send(allocator, Value, "hub/info", .{ .nonce = nonce });
    defer result.deinit(allocator);
    const value = switch (result) {
        .ok => |ok| ok orelse return error.HubDidNotProveKey,
        .remote_err => return error.HubDidNotProveKey,
    };
    const info = HubInfo.parse(value) orelse return error.HubDidNotProveKey;
    if (!info.proves(allocator, nonce)) return error.HubDidNotProveKey;
    const key = try allocator.dupe(u8, info.key);
    errdefer allocator.free(key);
    return .{ .key = key, .challenge = try allocator.dupe(u8, info.challenge) };
}
