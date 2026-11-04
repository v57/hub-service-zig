//! What the tests' fake hubs need to answer hub/info: the vectors' keys
//! (Docs/Devices/vectors.json) and their proofs.

const std = @import("std");
const hub_service = @import("hub_service");

pub const HUB_KEY = "MCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";
pub const HUB_KEY_FILE = "MC4CAQAwBQYDK2VwBCIEIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBMCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";
pub const OTHER_KEY = "MCowBQYDK2VwAyEAgTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=";
pub const OTHER_KEY_FILE = "MC4CAQAwBQYDK2VwBCIEIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICMCowBQYDK2VwAyEAgTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=";

/// The answer on the wire. A missing field goes out as null.
pub const Info = struct {
    key: []const u8,
    protocol: i64 = 2,
    pro: bool = true,
    proof: ?[]const u8 = null,
    challenge: ?[]const u8 = null,
};

/// `signer_file` signs the proof for `claimed_key`. The handler returns it after
/// this frees, so the proof goes in a buffer of the caller's that outlives it.
pub fn proof(allocator: std.mem.Allocator, signer_file: []const u8, claimed_key: []const u8, nonce: []const u8, out: []u8) ![]const u8 {
    const data = try hub_service.hubInfoSignedData(allocator, claimed_key, nonce);
    defer allocator.free(data);
    const signature = try hub_service.signBase64(allocator, try hub_service.parseKeyFile(signer_file), data);
    defer allocator.free(signature);
    @memcpy(out[0..signature.len], signature);
    return out[0..signature.len];
}
