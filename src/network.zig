//! Hub Network share publishing (TS hub-service/network.ts parity): make a
//! local TCP/UDP port reachable through Hub Network.
//!
//! For each share the service asks the local hub-net agent (HTTP over its
//! Unix socket) for a challenge, signs the nonce with the service key, gets an
//! attestation of the local target, and sends the whole declared set to the
//! hub with `network/shares/replace`. Attestations are forwarded verbatim; the
//! hub answers with one publication per share, in request order. Declared
//! shares are published again on every (re)connect.

const std = @import("std");
const builtin = @import("builtin");
const keychain = @import("keychain.zig");

const Allocator = std.mem.Allocator;
const Value = std.json.Value;

const WIRE_VERSION = 1;
const MAX_SHARE_NAME_LENGTH = 255;

/// A share: a stable name for a local TCP/UDP port.
pub const NetworkShare = struct {
    name: []const u8,
    /// "tcp" or "udp".
    protocol: []const u8,
    host: []const u8,
    port: u16,
    /// {"mode":"hub"|"private"|"disabled"}, {"mode":"group","group":...} or
    /// {"mode":"keys","keys":[...]}; null -> {"mode":"private"}.
    policy_json: ?[]const u8 = null,
};

/// The default hub-net agent socket.
pub fn defaultAgentSocket() []const u8 {
    return if (builtin.os.tag == .macos) "/var/run/hub-net/agent.sock" else "/run/hub-net/agent.sock";
}

/// Error details of the last failed share operation.
pub const Failure = struct {
    buffer: [512]u8 = undefined,
    len: usize = 0,

    pub fn message(self: *const Failure) []const u8 {
        return self.buffer[0..self.len];
    }

    pub fn set(self: *Failure, comptime format: []const u8, args: anytype) error{ShareFailed} {
        const text = std.fmt.bufPrint(&self.buffer, format, args) catch self.buffer[0..];
        self.len = text.len;
        return error.ShareFailed;
    }
};

/// Non-empty after trimming, no control characters.
fn validText(text: []const u8) bool {
    for (text) |c| if (c < 0x20 or c == 0x7f) return false;
    return std.mem.trim(u8, text, " \t").len > 0;
}

fn validPolicy(policy: Value) bool {
    if (policy != .object) return false;
    const mode = policy.object.get("mode") orelse return false;
    if (mode != .string) return false;
    const m = mode.string;
    if (std.mem.eql(u8, m, "hub") or std.mem.eql(u8, m, "private") or std.mem.eql(u8, m, "disabled")) return true;
    if (std.mem.eql(u8, m, "group")) {
        const group = policy.object.get("group") orelse return false;
        return group == .string and validText(group.string);
    }
    if (std.mem.eql(u8, m, "keys")) {
        const keys = policy.object.get("keys") orelse return false;
        if (keys != .array or keys.array.items.len == 0) return false;
        for (keys.array.items) |key| if (key != .string or !validText(key.string)) return false;
        return true;
    }
    return false;
}

fn validateShare(allocator: Allocator, share: NetworkShare, failure: *Failure) !void {
    if (!validText(share.name) or (std.unicode.utf8CountCodepoints(share.name) catch share.name.len) > MAX_SHARE_NAME_LENGTH) {
        return failure.set("Invalid Hub Network share name", .{});
    }
    if (!std.mem.eql(u8, share.protocol, "tcp") and !std.mem.eql(u8, share.protocol, "udp")) {
        return failure.set("Invalid Hub Network protocol", .{});
    }
    if (!validText(share.host)) return failure.set("Invalid Hub Network target host", .{});
    if (share.port == 0) return failure.set("Invalid Hub Network target port", .{});
    if (share.policy_json) |text| {
        var policy = std.json.parseFromSlice(Value, allocator, text, .{}) catch return failure.set("Invalid Hub Network policy", .{});
        defer policy.deinit();
        if (!validPolicy(policy.value)) return failure.set("Invalid Hub Network policy", .{});
    }
}

fn daysFromCivil(year_in: i64, month: i64, day: i64) i64 {
    const year = if (month <= 2) year_in - 1 else year_in;
    const era = @divFloor(year, 400);
    const yoe = year - era * 400;
    const doy = @divFloor(153 * (month + @as(i64, if (month > 2) -3 else 9)) + 2, 5) + day - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146_097 + doe - 719_468;
}

/// RFC 3339 time ("2026-10-20T20:12:00.5Z", "...+03:00") to Unix milliseconds.
pub fn parseIsoMs(text: []const u8) ?i64 {
    if (text.len < 20 or text[4] != '-' or text[7] != '-' or text[10] != 'T' or text[13] != ':' or text[16] != ':') return null;
    const number = struct {
        fn at(slice: []const u8) ?i64 {
            return std.fmt.parseInt(i64, slice, 10) catch null;
        }
    }.at;
    const year = number(text[0..4]) orelse return null;
    const month = number(text[5..7]) orelse return null;
    const day = number(text[8..10]) orelse return null;
    const hour = number(text[11..13]) orelse return null;
    const minute = number(text[14..16]) orelse return null;
    const second = number(text[17..19]) orelse return null;
    if (month < 1 or month > 12 or day < 1 or day > 31 or hour > 23 or minute > 59 or second > 60) return null;
    var rest = text[19..];
    var ms: i64 = 0;
    if (rest.len > 0 and rest[0] == '.') {
        var digits: usize = 1;
        while (digits < rest.len and std.ascii.isDigit(rest[digits])) digits += 1;
        if (digits == 1) return null;
        var scale: i64 = 100;
        for (rest[1..digits]) |c| {
            ms += (c - '0') * scale;
            scale = @divTrunc(scale, 10);
        }
        rest = rest[digits..];
    }
    var offset: i64 = 0;
    if (rest.len == 1 and (rest[0] == 'Z' or rest[0] == 'z')) {
        offset = 0;
    } else if (rest.len == 6 and rest[3] == ':' and (rest[0] == '+' or rest[0] == '-')) {
        const oh = number(rest[1..3]) orelse return null;
        const om = number(rest[4..6]) orelse return null;
        offset = (if (rest[0] == '+') @as(i64, 1) else -1) * (oh * 3600 + om * 60);
    } else return null;
    return (daysFromCivil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset) * 1000 + ms;
}

const OwnedShare = struct {
    name: []u8,
    protocol: []u8,
    host: []u8,
    port: u16,
    /// Compact policy JSON.
    policy_json: []u8,

    fn deinit(self: OwnedShare, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.protocol);
        allocator.free(self.host);
        allocator.free(self.policy_json);
    }
};

/// Sends a `network/shares/replace` body and returns the reply (owned by
/// `allocator`, freed by the publisher). A hub error is reported by setting
/// the publisher's failure and returning error.ShareFailed.
pub const ReplaceFn = *const fn (context: *anyopaque, allocator: Allocator, body: Value) anyerror!Value;

/// The declared shares and their publications.
pub const Publisher = struct {
    allocator: Allocator,
    shares: std.ArrayListUnmanaged(OwnedShare) = .{},
    /// JSON array of publications in share-name order.
    publications: []u8,
    socket_path: []u8,
    timeout_ms: u32 = 5000,
    failure: Failure = .{},

    pub fn init(allocator: Allocator, socket_path: ?[]const u8) !Publisher {
        const publications = try allocator.dupe(u8, "[]");
        errdefer allocator.free(publications);
        return .{
            .allocator = allocator,
            .publications = publications,
            .socket_path = try allocator.dupe(u8, socket_path orelse defaultAgentSocket()),
        };
    }

    pub fn deinit(self: *Publisher) void {
        for (self.shares.items) |share| share.deinit(self.allocator);
        self.shares.deinit(self.allocator);
        self.allocator.free(self.publications);
        self.allocator.free(self.socket_path);
    }

    pub fn hasShares(self: *const Publisher) bool {
        return self.shares.items.len > 0;
    }

    fn find(self: *const Publisher, name: []const u8) ?usize {
        for (self.shares.items, 0..) |share, index| {
            if (std.mem.eql(u8, share.name, name)) return index;
        }
        return null;
    }

    fn lessThan(_: void, a: OwnedShare, b: OwnedShare) bool {
        return std.mem.order(u8, a.name, b.name) == .lt;
    }

    fn copy(self: *Publisher, share: NetworkShare) !OwnedShare {
        const allocator = self.allocator;
        const policy_json = if (share.policy_json) |text| blk: {
            var policy = try std.json.parseFromSlice(Value, allocator, text, .{});
            defer policy.deinit();
            break :blk try std.json.Stringify.valueAlloc(allocator, policy.value, .{});
        } else try allocator.dupe(u8, "{\"mode\":\"private\"}");
        errdefer allocator.free(policy_json);
        const name = try allocator.dupe(u8, share.name);
        errdefer allocator.free(name);
        const protocol = try allocator.dupe(u8, share.protocol);
        errdefer allocator.free(protocol);
        return .{ .name = name, .protocol = protocol, .host = try allocator.dupe(u8, share.host), .port = share.port, .policy_json = policy_json };
    }

    /// Inserts or replaces a share; returns the replaced one.
    fn put(self: *Publisher, share: NetworkShare) !?OwnedShare {
        const owned = try self.copy(share);
        if (self.find(share.name)) |index| {
            const previous = self.shares.items[index];
            self.shares.items[index] = owned;
            return previous;
        }
        self.shares.append(self.allocator, owned) catch |err| {
            owned.deinit(self.allocator);
            return err;
        };
        std.mem.sort(OwnedShare, self.shares.items, {}, lessThan);
        return null;
    }

    /// Declares a share (published on the next connect).
    pub fn declare(self: *Publisher, share: NetworkShare) !void {
        try validateShare(self.allocator, share, &self.failure);
        if (try self.put(share)) |previous| previous.deinit(self.allocator);
    }

    /// Publishes `share` with the rest of the set; on failure the set is left
    /// as it was.
    pub fn publish(self: *Publisher, share: NetworkShare, kc: *keychain.Keychain, context: *anyopaque, replace: ReplaceFn) !void {
        try validateShare(self.allocator, share, &self.failure);
        const previous = try self.put(share);
        self.synchronize(kc, context, replace) catch |err| {
            const index = self.find(share.name).?;
            self.shares.items[index].deinit(self.allocator);
            if (previous) |old| {
                self.shares.items[index] = old;
            } else {
                _ = self.shares.orderedRemove(index);
            }
            return err;
        };
        if (previous) |old| old.deinit(self.allocator);
    }

    /// Removes a share and publishes the remaining set.
    pub fn remove(self: *Publisher, name: []const u8, kc: *keychain.Keychain, context: *anyopaque, replace: ReplaceFn) !void {
        const index = self.find(name) orelse return self.failure.set("Share '{s}' not found", .{name});
        const removed = self.shares.orderedRemove(index);
        self.synchronize(kc, context, replace) catch |err| {
            self.shares.insert(self.allocator, index, removed) catch removed.deinit(self.allocator);
            return err;
        };
        removed.deinit(self.allocator);
    }

    /// Attests every declared share and sends the set with
    /// network/shares/replace.
    pub fn synchronize(self: *Publisher, kc: *keychain.Keychain, context: *anyopaque, replace: ReplaceFn) !void {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const service_key = try kc.publicKey();
        defer self.allocator.free(service_key);

        var wire = std.json.Array.init(arena);
        for (self.shares.items) |share| {
            const attestation = try self.attest(arena, share, service_key, kc);
            var entry = std.json.ObjectMap.init(arena);
            try entry.put("name", .{ .string = share.name });
            try entry.put("protocol", .{ .string = share.protocol });
            var target = std.json.ObjectMap.init(arena);
            try target.put("host", .{ .string = share.host });
            try target.put("port", .{ .integer = share.port });
            try entry.put("target", .{ .object = target });
            try entry.put("policy", try std.json.parseFromSliceLeaky(Value, arena, share.policy_json, .{}));
            try entry.put("version", .{ .integer = WIRE_VERSION });
            // Forwarded verbatim: the agent signed it.
            try entry.put("attestation", attestation);
            try wire.append(.{ .object = entry });
        }
        var body = std.json.ObjectMap.init(arena);
        try body.put("shares", .{ .array = wire });

        var reply = replace(context, self.allocator, .{ .object = body }) catch |err| {
            // ShareFailed: the replace function already set the hub's error.
            if (err == error.ShareFailed) return err;
            return self.failure.set("network/shares/replace failed ({s})", .{@errorName(err)});
        };
        defer freeReply(self.allocator, &reply);
        const publications = if (reply == .object) reply.object.get("shares") else null;
        if (publications == null or publications.? != .array) {
            return self.failure.set("Hub returned an invalid shares/replace response", .{});
        }
        const items = publications.?.array.items;
        if (items.len != self.shares.items.len) {
            return self.failure.set("Hub returned {d} publications for {d} shares", .{ items.len, self.shares.items.len });
        }
        // v1 publications carry no share name: the hub keeps request order.
        for (items, self.shares.items, 0..) |publication, share, index| {
            try self.checkPublication(publication, share, index);
            for (items[0..index]) |other| {
                if (std.mem.eql(u8, other.object.get("resourceId").?.string, publication.object.get("resourceId").?.string)) {
                    return self.failure.set("Hub returned duplicate resourceId at share index {d}", .{index});
                }
            }
        }
        const text = try std.json.Stringify.valueAlloc(self.allocator, publications.?, .{});
        self.allocator.free(self.publications);
        self.publications = text;
    }

    fn freeReply(allocator: Allocator, reply: *Value) void {
        const channel_codec = struct {
            fn free(a: Allocator, value: Value) void {
                switch (value) {
                    .string => |s| a.free(s),
                    .number_string => |s| a.free(s),
                    .array => |array| {
                        for (array.items) |item| free(a, item);
                        array.deinit();
                    },
                    .object => |object| {
                        var map = object;
                        var it = map.iterator();
                        while (it.next()) |entry| {
                            a.free(entry.key_ptr.*);
                            free(a, entry.value_ptr.*);
                        }
                        map.deinit();
                    },
                    else => {},
                }
            }
        };
        channel_codec.free(allocator, reply.*);
    }

    fn checkPublication(self: *Publisher, publication: Value, share: OwnedShare, index: usize) !void {
        if (publication != .object) return self.failure.set("Invalid Hub publication at share index {d}", .{index});
        const fields = publication.object;
        const version = fields.get("version");
        if (version == null or version.? != .integer or version.?.integer != WIRE_VERSION) {
            return self.failure.set("Invalid Hub publication version at share index {d}", .{index});
        }
        const resource = fields.get("resourceId");
        if (resource == null or resource.? != .string or !std.mem.startsWith(u8, resource.?.string, "hnr1_") or resource.?.string.len == 5) {
            return self.failure.set("Invalid Hub publication resourceId at share index {d}", .{index});
        }
        for ([_][]const u8{ "authority", "providerId", "overlayAddress" }) |field| {
            const value = fields.get(field);
            if (value == null or value.? != .string or !validText(value.?.string)) {
                return self.failure.set("Invalid Hub publication {s} at share index {d}", .{ field, index });
            }
        }
        const protocol = fields.get("protocol");
        if (protocol == null or protocol.? != .string or !std.mem.eql(u8, protocol.?.string, share.protocol)) {
            return self.failure.set("Hub publication protocol mismatch at share index {d}", .{index});
        }
        const port = fields.get("port");
        if (port == null or port.? != .integer or port.?.integer < 1 or port.?.integer > 65_535) {
            return self.failure.set("Invalid Hub publication port at share index {d}", .{index});
        }
    }

    /// Challenge, sign, attest. The attestation lives in `arena`.
    fn attest(self: *Publisher, arena: Allocator, share: OwnedShare, service_key: []const u8, kc: *keychain.Keychain) !Value {
        var request = std.json.ObjectMap.init(arena);
        try request.put("serviceKey", .{ .string = service_key });
        try request.put("shareName", .{ .string = share.name });
        try request.put("protocol", .{ .string = share.protocol });
        var target = std.json.ObjectMap.init(arena);
        try target.put("host", .{ .string = share.host });
        try target.put("port", .{ .integer = share.port });
        try request.put("target", .{ .object = target });

        const challenge = try self.agentJson(arena, "/challenge", .{ .object = request }, "challenge");
        const nonce = challenge.object.get("nonce");
        if (nonce == null or nonce.? != .string or nonce.?.string.len == 0) {
            return self.failure.set("Hub Network agent returned an invalid challenge", .{});
        }
        const signature = try kc.signData(nonce.?.string);
        defer self.allocator.free(signature);
        try request.put("signature", .{ .string = try arena.dupe(u8, signature) });
        const attestation = try self.agentJson(arena, "/attest", .{ .object = request }, "attestation");
        try self.checkAttestation(attestation, share, service_key);
        return attestation;
    }

    fn checkAttestation(self: *Publisher, attestation: Value, share: OwnedShare, service_key: []const u8) !void {
        const fields = attestation.object;
        const text = struct {
            fn get(map: std.json.ObjectMap, field: []const u8) ?[]const u8 {
                const value = map.get(field) orelse return null;
                return if (value == .string) value.string else null;
            }
        }.get;
        const version = fields.get("version");
        const target = fields.get("target");
        const host = if (target != null and target.? == .object) text(target.?.object, "host") else null;
        const port = if (target != null and target.? == .object) target.?.object.get("port") else null;
        const matches = version != null and version.? == .integer and version.?.integer == WIRE_VERSION and
            std.mem.eql(u8, text(fields, "serviceKey") orelse "", service_key) and
            std.mem.eql(u8, text(fields, "shareName") orelse "", share.name) and
            std.mem.eql(u8, text(fields, "protocol") orelse "", share.protocol) and
            std.mem.eql(u8, host orelse "", share.host) and
            port != null and port.? == .integer and port.?.integer == share.port;
        if (!matches) return self.failure.set("Local-agent attestation does not match the share", .{});
        const issued = parseIsoMs(text(fields, "issuedAt") orelse "");
        const expires = parseIsoMs(text(fields, "expiresAt") orelse "");
        const now = std.time.milliTimestamp();
        if (issued == null or expires == null or expires.? <= issued.? or issued.? > now + 30_000 or expires.? <= now) {
            return self.failure.set("Local-agent attestation is expired", .{});
        }
    }

    /// POSTs JSON to the agent over its Unix socket; the reply object lives in
    /// `arena`.
    fn agentJson(self: *Publisher, arena: Allocator, path: []const u8, body: Value, operation: []const u8) !Value {
        const payload = try std.json.Stringify.valueAlloc(arena, body, .{});
        const stream = std.net.connectUnixSocket(self.socket_path) catch {
            return self.failure.set("Hub Network agent is unavailable at {s}", .{self.socket_path});
        };
        defer stream.close();
        const timeout = std.posix.timeval{
            .sec = @intCast(self.timeout_ms / 1000),
            .usec = @intCast((self.timeout_ms % 1000) * 1000),
        };
        std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};
        std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch {};

        const head = try std.fmt.allocPrint(arena, "POST {s} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ path, payload.len });
        writeAll(stream.handle, head) catch return self.failure.set("Hub Network agent is unavailable at {s}", .{self.socket_path});
        writeAll(stream.handle, payload) catch return self.failure.set("Hub Network agent is unavailable at {s}", .{self.socket_path});

        var response = std.ArrayListUnmanaged(u8){};
        var buffer: [4096]u8 = undefined;
        while (true) {
            const n = std.posix.read(stream.handle, &buffer) catch |err| switch (err) {
                error.WouldBlock => return self.failure.set("Hub Network agent timed out after {d} ms", .{self.timeout_ms}),
                else => return self.failure.set("Hub Network agent is unavailable at {s}", .{self.socket_path}),
            };
            if (n == 0) break;
            try response.appendSlice(arena, buffer[0..n]);
        }
        const split = std.mem.indexOf(u8, response.items, "\r\n\r\n") orelse return self.failure.set("Hub Network agent returned an invalid response", .{});
        const head_text = response.items[0..split];
        var reply_body = response.items[split + 4 ..];
        var status_parts = std.mem.splitScalar(u8, head_text, ' ');
        _ = status_parts.next();
        const status = std.fmt.parseInt(u16, status_parts.next() orelse "", 10) catch return self.failure.set("Hub Network agent returned an invalid response", .{});
        var lines = std.mem.splitSequence(u8, head_text, "\r\n");
        while (lines.next()) |line| {
            if (std.ascii.startsWithIgnoreCase(line, "transfer-encoding:") and std.ascii.indexOfIgnoreCase(line, "chunked") != null) {
                reply_body = try dechunk(arena, reply_body);
                break;
            }
        }
        const text = std.mem.trim(u8, reply_body, " \r\n\t");
        if (status < 200 or status > 299) {
            if (text.len == 0) return self.failure.set("Hub Network agent rejected {s} ({d})", .{ operation, status });
            return self.failure.set("Hub Network agent rejected {s} ({d}): {s}", .{ operation, status, text });
        }
        const value = std.json.parseFromSliceLeaky(Value, arena, text, .{}) catch return self.failure.set("Hub Network agent returned invalid JSON", .{});
        if (value != .object) return self.failure.set("Hub Network agent returned invalid JSON", .{});
        return value;
    }
};

fn writeAll(handle: std.posix.socket_t, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) written += try std.posix.write(handle, data[written..]);
}

fn dechunk(allocator: Allocator, body: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    var rest = body;
    while (std.mem.indexOf(u8, rest, "\r\n")) |line_end| {
        const line = rest[0..line_end];
        const size_text = std.mem.trim(u8, line[0..(std.mem.indexOfScalar(u8, line, ';') orelse line.len)], " ");
        const size = std.fmt.parseInt(usize, size_text, 16) catch break;
        if (size == 0) break;
        const start = line_end + 2;
        if (start + size > rest.len) break;
        try out.appendSlice(allocator, rest[start .. start + size]);
        rest = rest[@min(start + size + 2, rest.len)..];
    }
    return out.toOwnedSlice(allocator);
}
