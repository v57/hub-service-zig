//! hub-pro keychain: load-or-generate the `auth` ed25519 key file and sign
//! auth tokens (TS parity with hub-service/keychain.ts).
//!
//! The key file (`auth` in the working directory by default, or $HUBKEY) is
//! the base64 encoding of the 48-byte PKCS8 DER ed25519 private key followed
//! by the 44-byte SPKI DER public key (92 bytes total, 124 base64 chars).
//!
//! sign(expires=10) produces `key.<pub>.<sig>.<expiry>`:
//!   pub    = base64 of the 44-byte SPKI public key (bytes 48..92 of the file)
//!   sig    = base64 ed25519 signature over the expiry string
//!   expiry = DECIMAL epoch-seconds string of now + expires (TS parity;
//!            hub-pro reads it as base-36, so the decimal form never trips)
//!
//! The hub verifies the signature against the embedded public key and treats
//! the key as the connection identity (owner/host/group permissions).

const std = @import("std");

pub const Allocator = std.mem.Allocator;

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

    /// A fresh auth token: `key.<pub>.<sig>.<expiry>`. Owned; free it.
    pub fn sign(self: *Keychain, expires: i64) ![]u8 {
        const bytes = try self.loadBytes();
        // PKCS8 DER: 16-byte prefix + 32-byte seed.
        const seed: [32]u8 = bytes[16..PRIVATE_DER_LENGTH].*;
        const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);

        const expiry = try std.fmt.allocPrint(self.allocator, "{d}", .{std.time.timestamp() + expires});
        defer self.allocator.free(expiry);

        // Signature is over the DECIMAL expiry string (TS parity), not the
        // whole token. Deterministic (no noise) — same as the TS reference.
        const signature = try Ed25519.KeyPair.sign(key_pair, expiry, null);
        const sig_b64 = try encodeBase64(self.allocator, &signature.toBytes());
        defer self.allocator.free(sig_b64);

        const pub_b64 = try self.publicKey();
        defer self.allocator.free(pub_b64);

        return std.fmt.allocPrint(self.allocator, "key.{s}.{s}.{s}", .{ pub_b64, sig_b64, expiry });
    }

    /// Loads the key file (cached), generating and writing it if missing.
    /// Returns the decoded 92 key-file bytes.
    fn loadBytes(self: *Keychain) ![]u8 {
        if (self.key_bytes) |bytes| return bytes;

        const file_contents = std.fs.cwd().readFileAlloc(self.allocator, self.path, 1 << 16) catch |err| switch (err) {
            error.FileNotFound => {
                const generated = try self.generate();
                self.key_bytes = generated;
                return generated;
            },
            else => return err,
        };
        defer self.allocator.free(file_contents);

        const trimmed = std.mem.trim(u8, file_contents, " \r\n\t");
        const decoder = std.base64.standard.Decoder;
        const decoded_size = try decoder.calcSizeForSlice(trimmed);
        if (decoded_size != KEY_FILE_LENGTH) return error.BadAuthFile;
        const decoded = try self.allocator.alloc(u8, decoded_size);
        errdefer self.allocator.free(decoded);
        try decoder.decode(decoded, trimmed);

        self.key_bytes = decoded;
        return decoded;
    }

    /// Generates a fresh keypair, writes the TS-layout auth file, and returns
    /// the decoded 92 key-file bytes.
    fn generate(self: *Keychain) ![]u8 {
        const key_pair = Ed25519.KeyPair.generate();

        var file_bytes: [KEY_FILE_LENGTH]u8 = undefined;
        @memcpy(file_bytes[0..16], PKCS8_PREFIX);
        @memcpy(file_bytes[16..PRIVATE_DER_LENGTH], &key_pair.secret_key.seed());
        @memcpy(file_bytes[PRIVATE_DER_LENGTH..60], SPKI_PREFIX);
        @memcpy(file_bytes[60..KEY_FILE_LENGTH], &key_pair.public_key.toBytes());

        const encoded = try encodeBase64(self.allocator, &file_bytes);
        defer self.allocator.free(encoded);
        try std.fs.cwd().writeFile(.{ .sub_path = self.path, .data = encoded });

        return self.allocator.dupe(u8, &file_bytes);
    }
};

fn encodeBase64(allocator: Allocator, data: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const size = encoder.calcSize(data.len);
    const out = try allocator.alloc(u8, size);
    errdefer allocator.free(out);
    _ = encoder.encode(out, data);
    return out;
}
