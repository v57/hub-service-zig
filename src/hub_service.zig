//! hub-service-zig: a lite Zig port of hub-service (TS reference).
//!
//! Connect to a hub (hub-server), host post/stream API endpoints, register apps,
//! and call API through the hub. Before every (re)connect the service asks
//! hub/info with a fresh nonce on a short anonymous connection (see
//! hub_proof.zig): only an answer with a valid proof of the key it claims gets a
//! token (`auth` header), signed by the keychain `auth` file over that answer's
//! challenge. The first proven key is pinned in hubs.json; a hub that doesn't
//! prove its key, or proves another than the pinned one, gets nothing and holds
//! the next attempt back (Docs/Devices/protocol.md section 2).
//! Unless disabled, every connect also sends a certificate for the service
//! key signed by the device key (see device.zig), renewed when less than a
//! day is left. The wire contract matches the TS reference
//! (`hub/profile/update`, `hub/service/update`, AppInterface + element DSL).
//!
//! Depends on channel-zig (`channel` module). Use zig 0.15.x — on macOS 27
//! the only working toolchain is the homebrew keg
//! `/opt/homebrew/opt/zig@0.15/bin/zig` (PATH `zig` 0.16 breaks the
//! websocket.zig dependency and official tarballs fail to link against the
//! Xcode-beta SDK).

const std = @import("std");
pub const channel = @import("channel");
const keychain_mod = @import("keychain.zig");
pub const device = @import("device.zig");
pub const network = @import("network.zig");
const hub_proof = @import("hub_proof.zig");
pub const HubTransport = hub_proof.HubTransport;
pub const HubInfo = hub_proof.HubInfo;
pub const hubTransportOf = hub_proof.hubTransportOf;
pub const makeClientNonce = hub_proof.makeClientNonce;
pub const hubInfoSignedData = hub_proof.hubInfoSignedData;
pub const NetworkShare = network.NetworkShare;

pub const Keychain = keychain_mod.Keychain;
pub const PRIVATE_DER_LENGTH = keychain_mod.PRIVATE_DER_LENGTH;
pub const PUBLIC_DER_LENGTH = keychain_mod.PUBLIC_DER_LENGTH;
pub const AUTH_EXPIRY = keychain_mod.AUTH_EXPIRY;
pub const authToken = keychain_mod.authToken;
pub const parseKeyFile = keychain_mod.parseKeyFile;
pub const signBase64 = keychain_mod.signBase64;

pub const Allocator = std.mem.Allocator;
pub const Value = std.json.Value;

// Re-export the channel-zig request/result types so users can type handlers
// without importing channel themselves.
pub const PostRequest = channel.PostRequest;
pub const StreamRequest = channel.StreamRequest;
pub const StreamEmitter = channel.StreamEmitter;
pub const Values = channel.Values;
pub const CallResult = channel.CallResult;
pub const StreamNext = channel.StreamNext;
pub const Sender = channel.Sender;

/// A hub address normalized for hub key pins (protocol.md section 2): a bare
/// port "1997" becomes "ws://localhost:1997"; otherwise the URL as given with
/// the scheme and host lowercased and no trailing slash. Owned; free it.
pub fn normalizeHubAddress(allocator: Allocator, address: []const u8) ![]u8 {
    var digits = address.len > 0;
    for (address) |c| digits = digits and std.ascii.isDigit(c);
    if (digits) return std.fmt.allocPrint(allocator, "ws://localhost:{s}", .{address});
    const trimmed = std.mem.trimRight(u8, address, "/");
    const out = try allocator.dupe(u8, trimmed);
    if (std.mem.indexOf(u8, out, "://")) |scheme_end| {
        const rest = out[scheme_end + 3 ..];
        const authority_end = scheme_end + 3 + (std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len);
        for (out[0..authority_end]) |*c| c.* = std.ascii.toLower(c.*);
    }
    return out;
}

/// The caller's device, when its connection is device-attached.
pub const CallerDevice = struct {
    id: []const u8,
    name: []const u8 = "",
};

/// Who is calling (Docs/Devices/protocol.md section 4), from
/// `context.hub.caller`. The hub replaces any client-supplied `context.hub`,
/// so handlers can trust it. Borrowed from the request context: valid while
/// the handler runs.
///
/// Read it in a post handler declared with a `std.json.Value` context:
/// `fn (request: PostRequest(?*Service, Value, Value)) !?Value` and
/// `Caller.fromContext(request.context)`; stream handlers use `emit.caller()`.
pub const Caller = struct {
    /// Caller SPKI; null for anonymous callers.
    key: ?[]const u8 = null,
    /// Null unless the caller's connection is device-attached.
    device: ?CallerDevice = null,
    /// Groups of the key or its device (strings).
    groups: []const Value = &.{},
    /// Member of the owners group.
    owner: bool = false,
    /// Merged hub SPKI when the call came through a merged hub.
    via: ?[]const u8 = null,
    /// The merged hub's own caller (unverified).
    claimed: ?Value = null,
    /// The forwarding hub's key (`context.hub.hubKey`).
    hub_key: ?[]const u8 = null,

    /// The caller in a request context; null when it has no hub caller
    /// (a call that didn't come through a hub).
    pub fn fromContext(context: Value) ?Caller {
        const hub = objectField(context, "hub") orelse return null;
        const caller = objectField(hub, "caller") orelse return null;
        if (caller != .object) return null;
        var result = Caller{
            .key = stringField(caller, "key"),
            .owner = if (objectField(caller, "owner")) |owner| owner == .bool and owner.bool else false,
            .via = stringField(caller, "via"),
            .hub_key = stringField(hub, "hubKey"),
        };
        if (objectField(caller, "device")) |device_value| {
            if (stringField(device_value, "id")) |id| {
                result.device = .{ .id = id, .name = stringField(device_value, "name") orelse "" };
            }
        }
        if (objectField(caller, "groups")) |groups| {
            if (groups == .array) result.groups = groups.array.items;
        }
        if (objectField(caller, "claimed")) |claimed| {
            if (claimed != .null) result.claimed = claimed;
        }
        return result;
    }

    /// Whether the caller is in the group with this id.
    pub fn inGroup(self: Caller, id: []const u8) bool {
        for (self.groups) |group| {
            if (group == .string and std.mem.eql(u8, group.string, id)) return true;
        }
        return false;
    }

    fn objectField(value: Value, name: []const u8) ?Value {
        if (value != .object) return null;
        return value.object.get(name);
    }

    fn stringField(value: Value, name: []const u8) ?[]const u8 {
        const field = objectField(value, name) orelse return null;
        return if (field == .string) field.string else null;
    }
};

/// Handler state: every registered handler reaches the owning Service via
/// `request.state.*`.
pub const State = ?*Service;

/// Where to connect: a port (int) or a ws:// URL. Defaults to 1997 or $HUB.
pub const Address = union(enum) {
    port: u16,
    url: []const u8,
};

pub const ServiceOptions = struct {
    address: ?Address = null,
    name: ?[]const u8 = null,
    icon: ?Value = null,
    /// Keychain auth file path (default: $HUBKEY, else "auth" in the cwd).
    key_path: ?[]const u8 = null,
    /// Instance name in the device certificate, unique per device
    /// ("s3-local/Backup Disk"). Default: $HUB_INSTANCE, else name, else the
    /// basename of the working directory, else "service". Must outlive the
    /// Service.
    instance: ?[]const u8 = null,
    /// Suggested device name in the certificate. Default: $HUB_DEVICE_NAME,
    /// else the macOS computer name, else the host name.
    device_name: ?[]const u8 = null,
    /// Declared parent device name, for containers and VMs. Default:
    /// $HUB_DEVICE_PARENT.
    parent: ?[]const u8 = null,
    /// Device key path (default: $HUB_DEVICE_KEY, /var/lib/hub/device.key
    /// for root, else ~/.hub/device.key).
    device_key_path: ?[]const u8 = null,
    /// A caller-provided device key (key file text) used instead of the key
    /// file, for apps that keep it in their own store.
    device_key: ?[]const u8 = null,
    /// No device key and no `device` header: a plain key connection.
    /// $HUB_DEVICE=0 (or off, false, no) does the same.
    disable_device: bool = false,
    /// The hub-net agent socket for share publishing (default
    /// /var/run/hub-net/agent.sock on macOS, /run/hub-net/agent.sock elsewhere).
    agent_socket: ?[]const u8 = null,
    /// Dial plain ws:// beyond loopback, the overlay and the LAN, which would
    /// carry the key unencrypted: for private networks the SDK can't recognize,
    /// such as a container's ws://hub:1997. $HUB_ALLOW_PLAINTEXT=1 does the same.
    allow_plaintext: bool = false,
};

/// Sent to the hub as hub/profile/update on every (re)connect.
pub const Profile = struct {
    name: ?[]const u8 = null,
    icon: ?Value = null,
};

/// One entry of the hub/service/update apps array.
pub const AppHeader = struct {
    @"type": []const u8 = "app",
    name: []const u8,
    path: []const u8,
};

/// hub-server's permission fields.
pub const ServicePermissions = struct {
    group: ?[]const u8 = null,
    name: []const u8,
    allows: ?bool = null,
};

pub const ApiSettings = struct {
    permissions: ?ServicePermissions = null,
    limit: ?i64 = null,
};

/// A hub app: header plus a UI body of elements. The Service takes ownership
/// of (clones) the element/data Values passed here; they must stay alive
/// until `app()` returns.
pub const App = struct {
    header: AppHeader,
    body: []const Value = &.{},
    top: ?Value = null,
    bottom: ?Value = null,
    data: ?Value = null,
};

const AppInterface = struct {
    header: AppHeader,
    body: []const Value,
    top: ?Value,
    bottom: ?Value,
    data: ?Value,
};

pub const Service = struct {
    allocator: Allocator,
    ch: channel.Channel(?*Service),
    address: Address,
    profile: ?Profile = null,
    owned_env: ?[]u8 = null,
    owned_key_env: ?[]u8 = null,
    keychain: Keychain,
    apps: std.ArrayListUnmanaged(AppHeader) = .{},
    paths: std.StringHashMapUnmanaged(void) = .{},
    settings: std.StringHashMapUnmanaged(ApiSettings) = .{},
    app_values: std.StringHashMapUnmanaged(Value) = .{},
    client: ?channel.Client(?*Service) = null,
    started: bool = false,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    poll_thread: ?std.Thread = null,
    mutex: std.Thread.Mutex = .{},
    allow_plaintext: bool = false,
    /// Why start dialed nothing (owned), or null.
    refusal: ?[]u8 = null,
    /// The failure last reported (owned): each distinct one goes out once.
    last_failure: ?[]u8 = null,
    /// Null when device mode is off or there is no home directory.
    device_key: ?device.DeviceKey = null,
    instance_option: ?[]const u8 = null,
    device_name: ?[]const u8 = null,
    parent: ?[]const u8 = null,
    /// The current `device` header (owned) and its expiry.
    certificate: ?[]u8 = null,
    certificate_exp: i64 = 0,
    /// Declared Hub Network shares and their publications.
    shares: network.Publisher,

    /// Creates a Service. Address defaults to 1997, or $HUB when set.
    pub fn init(allocator: Allocator, options: ServiceOptions) !Service {
        var address: Address = .{ .port = 1997 };
        var owned_env: ?[]u8 = null;
        errdefer if (owned_env) |env| allocator.free(env);
        if (options.address) |a| {
            address = a;
        } else if (std.process.getEnvVarOwned(allocator, "HUB")) |env| {
            owned_env = env;
            // A bare port number in $HUB (e.g. "1998") becomes a port address;
            // anything else is treated as a ws:// or host:port URL.
            if (std.fmt.parseInt(u16, env, 10)) |port| {
                address = .{ .port = port };
            } else |_| {
                address = .{ .url = env };
            }
        } else |_| {}

        var key_path: []const u8 = "auth";
        var owned_key_env: ?[]u8 = null;
        errdefer if (owned_key_env) |env| allocator.free(env);
        if (options.key_path) |kp| {
            key_path = kp;
        } else if (std.process.getEnvVarOwned(allocator, "HUBKEY")) |env| {
            owned_key_env = env;
            key_path = env;
        } else |_| {}

        var profile: ?Profile = null;
        if (options.name != null or options.icon != null) {
            profile = .{ .name = options.name, .icon = options.icon };
        }

        var keychain = try Keychain.init(allocator, key_path);
        errdefer keychain.deinit();

        var device_key: ?device.DeviceKey = null;
        if (!options.disable_device and device.modeEnabled(allocator)) {
            if (options.device_key) |key_file| {
                device_key = try device.DeviceKey.fromKeyFile(allocator, key_file);
            } else if (options.device_key_path) |path| {
                device_key = try device.DeviceKey.init(allocator, path);
            } else if (try device.defaultPath(allocator)) |path| {
                defer allocator.free(path);
                device_key = try device.DeviceKey.init(allocator, path);
            }
        }
        errdefer if (device_key) |*key| key.deinit();

        var shares = try network.Publisher.init(allocator, options.agent_socket);
        errdefer shares.deinit();

        var allow_plaintext = options.allow_plaintext;
        if (std.process.getEnvVarOwned(allocator, "HUB_ALLOW_PLAINTEXT")) |env| {
            defer allocator.free(env);
            if (std.mem.eql(u8, env, "1")) allow_plaintext = true;
        } else |_| {}

        return .{
            .allocator = allocator,
            .ch = channel.Channel(?*Service).init(allocator),
            .address = address,
            .profile = profile,
            .owned_env = owned_env,
            .owned_key_env = owned_key_env,
            .keychain = keychain,
            .device_key = device_key,
            .shares = shares,
            .instance_option = options.instance,
            .device_name = options.device_name,
            .parent = options.parent,
            .allow_plaintext = allow_plaintext,
        };
    }

    pub fn deinit(self: *Service) void {
        self.stop_flag.store(true, .release);
        if (self.poll_thread) |thread| thread.join();
        if (self.client) |*client| client.deinit();
        if (self.refusal) |refusal| self.allocator.free(refusal);
        if (self.last_failure) |failure| self.allocator.free(failure);
        if (self.owned_env) |env| self.allocator.free(env);
        if (self.owned_key_env) |env| self.allocator.free(env);
        self.keychain.deinit();
        if (self.device_key) |*key| key.deinit();
        if (self.certificate) |certificate| self.allocator.free(certificate);
        self.shares.deinit();

        self.apps.deinit(self.allocator);

        var paths_it = self.paths.iterator();
        while (paths_it.next()) |entry| self.allocator.free(@constCast(entry.key_ptr.*));
        self.paths.deinit(self.allocator);

        var settings_it = self.settings.iterator();
        while (settings_it.next()) |entry| self.allocator.free(@constCast(entry.key_ptr.*));
        self.settings.deinit(self.allocator);

        var app_it = self.app_values.iterator();
        while (app_it.next()) |entry| {
            self.allocator.free(@constCast(entry.key_ptr.*));
            valueDeinit(self.allocator, entry.value_ptr.*);
        }
        self.app_values.deinit(self.allocator);

        self.ch.deinit();
        self.* = undefined;
    }

    /// Registers a request/response API endpoint. The handler receives the
    /// JSON-decoded body and returns a JSON-encodable response:
    /// `fn (PostRequest(*Service, std.json.Value, void)) anyerror!?std.json.Value`.
    pub fn post(self: *Service, path: []const u8, comptime handler: anytype, settings: ?ApiSettings) !*Service {
        try self.addPath(path, settings);
        _ = try self.ch.post(path, handler);
        return self;
    }

    /// Registers a streaming API endpoint. The handler receives the body and
    /// an Emit with which it emits values:
    /// `fn (body: std.json.Value, emit: hub_service.Emit) anyerror!void`.
    pub fn stream(self: *Service, path: []const u8, comptime handler: anytype, settings: ?ApiSettings) !*Service {
        try self.addPath(path, settings);
        const Wrapper = struct {
            fn invoke(request: channel.StreamRequest(?*Service, std.json.Value, std.json.Value, std.json.Value)) !void {
                const emit = Emit{ .request = &request };
                try handler(request.body, emit);
            }
        };
        _ = try self.ch.stream(std.json.Value, std.json.Value, std.json.Value, path, Wrapper.invoke);
        return self;
    }

    /// Registers an app: its header goes to the hub apps list and its path
    /// serves the AppInterface (all 5 keys: header/body/top/bottom/data) as a
    /// stream. The app path is also listed in the services array (TS parity).
    pub fn app(self: *Service, app_config: App) !*Service {
        try self.apps.append(self.allocator, app_config.header);
        try self.addPath(app_config.header.path, null);

        var interface = std.json.ObjectMap.init(self.allocator);
        try interface.put("header", try appHeaderValue(self.allocator, app_config.header));
        var body = std.json.Array.init(self.allocator);
        for (app_config.body) |element| {
            try body.append(try cloneValue(self.allocator, element));
        }
        try interface.put("body", .{ .array = body });
        try interface.put("top", if (app_config.top) |t| try cloneValue(self.allocator, t) else .null);
        try interface.put("bottom", if (app_config.bottom) |b| try cloneValue(self.allocator, b) else .null);
        try interface.put("data", if (app_config.data) |d| try cloneValue(self.allocator, d) else .{ .object = std.json.ObjectMap.init(self.allocator) });

        const key = try self.allocator.dupe(u8, app_config.header.path);
        errdefer self.allocator.free(key);
        const gop = try self.app_values.getOrPut(self.allocator, key);
        if (gop.found_existing) {
            self.allocator.free(key);
            valueDeinit(self.allocator, gop.value_ptr.*);
        }
        gop.value_ptr.* = .{ .object = interface };

        _ = try self.ch.stream(void, std.json.Value, void, app_config.header.path, appStreamHandler);
        return self;
    }

    /// Calls an API through the hub. Between connections it waits for one, also
    /// while a hub that doesn't prove its key holds the attempts back. Errors with
    /// error.ServiceNotStarted before start or once stopped, and with
    /// error.WouldCarryKeyUnencrypted for an address start refused (see
    /// plaintextRefusal).
    pub fn send(self: *Service, allocator: Allocator, path: []const u8, body: ?Value) !channel.CallResult(std.json.Value) {
        const client = try self.waitForClient();
        defer self.mutex.unlock();
        return client.send(allocator, std.json.Value, path, body orelse .null);
    }

    /// Opens a stream call through the hub. Waits and errors like send.
    /// NOTE: iterating the returned Values pumps the transport; with the poll
    /// thread running, do so from a single thread (the poll thread itself is
    /// the safe choice).
    pub fn values(self: *Service, allocator: Allocator, path: []const u8, body: ?Value) !channel.Values(std.json.Value) {
        const client = try self.waitForClient();
        defer self.mutex.unlock();
        return client.values(allocator, std.json.Value, std.json.Value, void, path, body orelse .null, {});
    }

    /// The client once there is one, with the mutex held.
    fn waitForClient(self: *Service) !*channel.Client(?*Service) {
        while (true) {
            self.mutex.lock();
            if (self.refusal != null) {
                self.mutex.unlock();
                return error.WouldCarryKeyUnencrypted;
            }
            if (self.client != null) return &self.client.?;
            const waiting = self.started and !self.stop_flag.load(.acquire);
            self.mutex.unlock();
            if (!waiting) return error.ServiceNotStarted;
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }
    }

    /// Asks the hub to prove its key and connects, then keeps the poll/reconnect
    /// loop running: a failed attempt holds the next one back, from 1 s doubling
    /// to 30 s, and each distinct failure goes to stderr once. On every
    /// isConnected false->true transition (per connection) it sends
    /// hub/profile/update (if a profile is set) then hub/service/update. An
    /// address that would carry the key unencrypted opens nothing (see
    /// allow_plaintext).
    pub fn start(self: *Service) !*Service {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.started or self.refusal != null) return self;
        if (!self.allow_plaintext and self.address == .url and hub_proof.hubTransportOf(self.address.url) == .refused) {
            self.refusal = try std.fmt.allocPrint(
                self.allocator,
                "{s} would carry this service's key unencrypted. Use wss://, or set allow_plaintext (HUB_ALLOW_PLAINTEXT=1) on a private network",
                .{self.address.url},
            );
            std.debug.print("hub-service: {s}\n", .{self.refusal.?});
            return self;
        }
        self.started = true;
        self.poll_thread = try std.Thread.spawn(.{}, Service.pollLoop, .{self});
        return self;
    }

    /// Why start dialed nothing, or null.
    pub fn plaintextRefusal(self: *const Service) ?[]const u8 {
        return self.refusal;
    }

    /// The key of this service's hub key pin (see normalizeHubAddress).
    /// Owned; free it.
    pub fn pinAddress(self: *Service, allocator: Allocator) ![]u8 {
        return switch (self.address) {
            .port => |port| std.fmt.allocPrint(allocator, "ws://localhost:{d}", .{port}),
            .url => |url| normalizeHubAddress(allocator, url),
        };
    }

    /// The instance name in the device certificate: the `instance` option,
    /// else $HUB_INSTANCE, else the profile name, else the basename of the
    /// working directory, else "service". Owned; free it.
    pub fn instance(self: *const Service, allocator: Allocator) ![]u8 {
        if (self.instance_option) |value| {
            if (value.len > 0) return allocator.dupe(u8, value);
        }
        if (std.process.getEnvVarOwned(allocator, "HUB_INSTANCE")) |value| {
            if (value.len > 0) return value;
            allocator.free(value);
        } else |_| {}
        if (self.profile) |profile| {
            if (profile.name) |name| {
                if (name.len > 0) return allocator.dupe(u8, name);
            }
        }
        if (std.process.getCwdAlloc(allocator)) |cwd| {
            defer allocator.free(cwd);
            const name = std.fs.path.basename(cwd);
            if (name.len > 0) return allocator.dupe(u8, name);
        } else |_| {}
        return allocator.dupe(u8, "service");
    }

    /// The `device` header for a connect at `now`: the current certificate,
    /// or a new one when there is none or less than CERTIFICATE_RENEW is
    /// left. Null when device mode is off. Borrowed from the Service.
    pub fn currentCertificate(self: *Service, now: i64) !?[]const u8 {
        var device_key = &(self.device_key orelse return null);
        if (self.certificate) |certificate| {
            if (self.certificate_exp - now >= device.CERTIFICATE_RENEW) return certificate;
        }
        const service_key = try self.keychain.publicKey();
        defer self.allocator.free(service_key);
        const device_spki = try device_key.publicKey();
        defer self.allocator.free(device_spki);
        const default_name = if (self.device_name == null) try device.defaultName(self.allocator) else null;
        defer if (default_name) |name| self.allocator.free(name);
        const device_name = self.device_name orelse default_name;
        const parent_env = if (self.parent == null) std.process.getEnvVarOwned(self.allocator, "HUB_DEVICE_PARENT") catch null else null;
        defer if (parent_env) |value| self.allocator.free(value);
        const parent_name = self.parent orelse parent_env;
        const parent: ?[]const u8 = if (parent_name) |parent| (if (parent.len > 0) device.truncate(parent, 64) else null) else null;
        const instance_name = try self.instance(self.allocator);
        defer self.allocator.free(instance_name);
        const header = try device_key.sign(.{
            .device = device_spki,
            .service = service_key,
            .instance = device.truncate(instance_name, 128),
            .deviceName = if (device_name) |name| device.truncate(name, 64) else null,
            .platform = device.platform(),
            .parent = parent,
            .iat = now,
            .exp = now + device.CERTIFICATE_LIFETIME,
        });
        if (self.certificate) |old| self.allocator.free(old);
        self.certificate = header;
        self.certificate_exp = now + device.CERTIFICATE_LIFETIME;
        return header;
    }

    /// Declares a Hub Network share before start(): the complete declared set
    /// is published on connect and after every reconnect. On
    /// error.ShareFailed, shareError() says why.
    pub fn share(self: *Service, share_config: NetworkShare) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.shares.declare(share_config);
    }

    /// Publishes (or updates) a share now: the local hub-net agent attests it
    /// and the hub publishes the whole declared set. On failure the set is
    /// left as it was; on error.ShareFailed, shareError() says why.
    pub fn publishShare(self: *Service, share_config: NetworkShare) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.client == null or !self.client.?.isConnected()) return error.ServiceNotStarted;
        try self.shares.publish(share_config, &self.keychain, self, replaceShares);
    }

    /// Removes a share and publishes the remaining set.
    pub fn removeShare(self: *Service, name: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.client == null or !self.client.?.isConnected()) return error.ServiceNotStarted;
        try self.shares.remove(name, &self.keychain, self, replaceShares);
    }

    /// The current publications as a JSON array of {version, resourceId,
    /// authority, providerId, protocol, overlayAddress, port} in share-name
    /// order. Owned; free it.
    pub fn sharePublications(self: *Service, allocator: Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return allocator.dupe(u8, self.shares.publications);
    }

    /// Why the last share operation failed with error.ShareFailed.
    pub fn shareError(self: *Service) []const u8 {
        return self.shares.failure.message();
    }

    /// network/shares/replace on the current client (the mutex is held).
    fn replaceShares(context: *anyopaque, allocator: Allocator, body: Value) anyerror!Value {
        const self: *Service = @ptrCast(@alignCast(context));
        const client = &(self.client orelse return error.ServiceNotStarted);
        var result = try client.send(allocator, std.json.Value, "network/shares/replace", body);
        switch (result) {
            .ok => |value| return value orelse .null,
            .remote_err => |message| {
                defer result.deinit(allocator);
                return self.shares.failure.set("{s}", .{message});
            },
        }
    }

    /// Forgets the hub key pinned for this service's address, for a hub whose key
    /// changed on purpose. The next connect pins what the hub proves.
    pub fn forgetHubKey(self: *Service) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const address = try self.pinAddress(self.allocator);
        defer self.allocator.free(address);
        try self.keychain.forgetHubKey(address);
    }

    /// Requests the poll loop to stop (used by deinit), and ends the calls waiting
    /// for a connection.
    pub fn stop(self: *Service) void {
        self.stop_flag.store(true, .release);
    }

    /// Builds the hub/service/update payload: services (one entry per
    /// registered path, sorted by path) + apps. The returned Value is fully
    /// owned; free it with valueDeinit.
    pub fn updateValue(self: *Service) !Value {
        const allocator = self.allocator;
        const paths = try self.sortedPaths(allocator);
        defer allocator.free(paths);

        var services = std.json.Array.init(allocator);
        for (paths) |path| {
            var entry = std.json.ObjectMap.init(allocator);
            try entry.put("path", .{ .string = try allocator.dupe(u8, path) });
            if (self.settings.get(path)) |st| {
                if (st.permissions) |perm| {
                    var pmap = std.json.ObjectMap.init(allocator);
                    if (perm.group) |group| {
                        if (group.len > 0) try pmap.put("group", .{ .string = try allocator.dupe(u8, group) });
                    }
                    try pmap.put("name", .{ .string = try allocator.dupe(u8, perm.name) });
                    if (perm.allows) |allows| try pmap.put("allows", .{ .bool = allows });
                    try entry.put("permissions", .{ .object = pmap });
                }
                if (st.limit) |limit| try entry.put("limit", .{ .integer = limit });
            }
            try services.append(.{ .object = entry });
        }

        var apps = std.json.Array.init(allocator);
        for (self.apps.items) |header| {
            try apps.append(try appHeaderValue(allocator, header));
        }

        var root = std.json.ObjectMap.init(allocator);
        try root.put("services", .{ .array = services });
        try root.put("apps", .{ .array = apps });
        return .{ .object = root };
    }

    /// Builds the hub/profile/update payload (name + icon, only set fields).
    /// The returned Value is fully owned; free it with valueDeinit.
    pub fn profileValue(self: *Service) !Value {
        const allocator = self.allocator;
        const profile = self.profile orelse return error.NoProfile;
        var map = std.json.ObjectMap.init(allocator);
        if (profile.name) |name| {
            try map.put("name", .{ .string = try allocator.dupe(u8, name) });
        }
        if (profile.icon) |icon_value| {
            try map.put("icon", try cloneValue(allocator, icon_value));
        }
        return .{ .object = map };
    }

    fn addPath(self: *Service, path: []const u8, settings: ?ApiSettings) !void {
        var stored_path: []const u8 = undefined;
        {
            const owned = try self.allocator.dupe(u8, path);
            errdefer self.allocator.free(owned);
            const gop = try self.paths.getOrPut(self.allocator, owned);
            if (gop.found_existing) {
                self.allocator.free(owned);
                stored_path = gop.key_ptr.*;
            } else {
                gop.key_ptr.* = owned;
                stored_path = owned;
            }
        }
        if (settings) |st| {
            var st2 = st;
            // TS parity: if permissions are set and group is missing, auto-fill
            // group with the first path segment.
            if (st2.permissions) |*perm| {
                if (perm.group == null or perm.group.?.len == 0) {
                    const idx = std.mem.indexOfScalar(u8, stored_path, '/') orelse stored_path.len;
                    perm.group = stored_path[0..idx];
                }
            }
            const settings_key = try self.allocator.dupe(u8, stored_path);
            errdefer self.allocator.free(settings_key);
            const gop2 = try self.settings.getOrPut(self.allocator, settings_key);
            if (gop2.found_existing) self.allocator.free(settings_key);
            gop2.value_ptr.* = st2;
        }
    }

    fn sortedPaths(self: *Service, allocator: Allocator) ![]const []const u8 {
        var paths_list = std.ArrayListUnmanaged([]const u8){};
        var it = self.paths.iterator();
        while (it.next()) |entry| try paths_list.append(allocator, entry.key_ptr.*);
        std.mem.sort([]const u8, paths_list.items, {}, lessThanPath);
        return paths_list.toOwnedSlice(allocator);
    }

    fn lessThanPath(_: void, a: []const u8, b: []const u8) bool {
        return std.mem.order(u8, a, b) == .lt;
    }

    fn sendUpdates(self: *Service, client: *channel.Client(?*Service)) !void {
        if (self.profile != null) {
            const profile_payload = try self.profileValue();
            defer valueDeinit(self.allocator, profile_payload);
            var profile_result = try client.send(self.allocator, std.json.Value, "hub/profile/update", profile_payload);
            defer profile_result.deinit(self.allocator);
            switch (profile_result) {
                .remote_err => |msg| std.debug.print("hub-service: profile update failed: {s}\n", .{msg}),
                else => {},
            }
        }
        const update_payload = try self.updateValue();
        defer valueDeinit(self.allocator, update_payload);
        var update_result = try client.send(self.allocator, std.json.Value, "hub/service/update", update_payload);
        defer update_result.deinit(self.allocator);
        switch (update_result) {
            .remote_err => |msg| std.debug.print("hub-service: service update failed: {s}\n", .{msg}),
            else => {},
        }
    }

    /// A fresh raw header block for a connect to the hub with key `hub_key`, over
    /// the challenge it answered: the auth token (a challenge is good for one
    /// connection, so it's built per connect), the protocol version and the
    /// device certificate. The channel client memcpys this verbatim after the
    /// standard headers. Owned; free it.
    pub fn connectHeaderBlock(self: *Service, hub_key: []const u8, challenge: []const u8) ![]u8 {
        const token = try self.keychain.signForHub(hub_key, challenge, AUTH_EXPIRY);
        defer self.allocator.free(token);
        // A device key that can't be read or created leaves a plain key
        // connection.
        const certificate = self.currentCertificate(std.time.timestamp()) catch |err| blk: {
            std.debug.print("hub-service: device certificate failed ({s})\n", .{@errorName(err)});
            break :blk null;
        };
        if (certificate) |header| {
            return std.fmt.allocPrint(self.allocator, "auth: {s}\r\nv: 1\r\ndevice: {s}\r\n", .{ token, header });
        }
        return std.fmt.allocPrint(self.allocator, "auth: {s}\r\nv: 1\r\n", .{token});
    }

    const Handshake = union(enum) {
        /// The header block for this answer alone. Owned.
        headers: []u8,
        /// Why the hub gets nothing. Owned.
        failure: []u8,
    };

    /// Runs before every connection attempt (protocol.md section 2): asks the hub
    /// for its proof, pins a first key, refuses another than the pinned one, and
    /// builds the headers for that answer alone.
    fn handshake(self: *Service) !Handshake {
        const allocator = self.allocator;
        const address = try self.pinAddress(allocator);
        defer allocator.free(address);
        const asked = switch (self.address) {
            .port => |port| hub_proof.askHub(allocator, port),
            .url => |url| hub_proof.askHub(allocator, url),
        };
        const hub = asked catch |err| {
            const reason = if (err == error.HubDidNotProveKey) "hub didn't prove its key" else @errorName(err);
            return .{ .failure = try std.fmt.allocPrint(allocator, "{s}: {s}, sending it nothing", .{ address, reason }) };
        };
        defer hub.deinit(allocator);
        if (try self.keychain.hubKey(address)) |pinned| {
            defer allocator.free(pinned);
            if (!std.mem.eql(u8, pinned, hub.key)) {
                return .{ .failure = try std.fmt.allocPrint(
                    allocator,
                    "{s} answers with key {s}, not the pinned {s}, sending it nothing. forgetHubKey if its key really changed",
                    .{ address, hub.key, pinned },
                ) };
            }
        } else {
            try self.keychain.pinHubKey(address, hub.key);
        }
        return .{ .headers = try self.connectHeaderBlock(hub.key, hub.challenge) };
    }

    /// One attempt: the proof first, then the hub. Null when it failed, reported.
    fn dial(self: *Service) ?channel.Client(?*Service) {
        const outcome = self.handshake() catch |err| {
            self.reportFailure(@errorName(err));
            return null;
        };
        switch (outcome) {
            .failure => |failure| {
                defer self.allocator.free(failure);
                self.reportFailure(failure);
                return null;
            },
            .headers => |headers| {
                defer self.allocator.free(headers);
                const connected = switch (self.address) {
                    .port => |port| self.ch.connect(self.allocator, port, .{ .state = self, .headers = headers }),
                    .url => |url| self.ch.connect(self.allocator, url, .{ .state = self, .headers = headers }),
                };
                return connected catch |err| {
                    self.reportFailure(@errorName(err));
                    return null;
                };
            },
        }
    }

    /// Reports a failure that differs from the last one.
    fn reportFailure(self: *Service, message: []const u8) void {
        if (self.last_failure) |last| {
            if (std.mem.eql(u8, last, message)) return;
            self.allocator.free(last);
            self.last_failure = null;
        }
        std.debug.print("hub-service: {s}\n", .{message});
        self.last_failure = self.allocator.dupe(u8, message) catch null;
    }

    /// Waits before the next attempt, or until stop.
    fn holdBack(self: *Service, seconds: u64) void {
        var waited: u64 = 0;
        while (waited < seconds * 100 and !self.stop_flag.load(.acquire)) : (waited += 1) {
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }
    }

    fn pollLoop(self: *Service) void {
        var was_connected = false;
        var retry_delay: u64 = 1;
        while (!self.stop_flag.load(.acquire)) {
            self.mutex.lock();
            {
                if (self.client) |*client| {
                    if (!client.isConnected()) {
                        client.deinit();
                        self.client = null;
                    }
                }
                if (self.client == null) {
                    self.client = self.dial();
                    if (self.client == null) {
                        self.mutex.unlock();
                        self.holdBack(retry_delay);
                        retry_delay = @min(retry_delay * 2, 30);
                        continue;
                    }
                    was_connected = false;
                }
                const client = &self.client.?;
                _ = client.poll() catch |err| {
                    std.debug.print("hub-service: poll error ({s}); reconnecting\n", .{@errorName(err)});
                    client.deinit();
                    self.client = null;
                    was_connected = false;
                    self.mutex.unlock();
                    std.Thread.sleep(100 * std.time.ns_per_ms);
                    continue;
                };
                const connected = client.isConnected();
                if (connected and !was_connected) {
                    retry_delay = 1;
                    if (self.last_failure) |failure| {
                        self.allocator.free(failure);
                        self.last_failure = null;
                    }
                    self.sendUpdates(client) catch |err| {
                        std.debug.print("hub-service: update send failed ({s})\n", .{@errorName(err)});
                    };
                    was_connected = true;
                    if (self.shares.hasShares()) {
                        self.shares.synchronize(&self.keychain, self, replaceShares) catch |err| {
                            std.debug.print("hub-service: failed to republish network shares ({s}: {s})\n", .{ @errorName(err), self.shares.failure.message() });
                        };
                    }
                }
                if (!connected) was_connected = false;
            }
            self.mutex.unlock();
            std.Thread.sleep(1 * std.time.ns_per_ms);
        }
    }
};

/// Emit handle passed to stream handlers; wraps the channel stream emitter.
pub const Emit = struct {
    request: *const channel.StreamRequest(?*Service, std.json.Value, std.json.Value, std.json.Value),

    /// Who is calling; null when the call carries no hub caller.
    pub fn caller(self: *const Emit) ?Caller {
        return Caller.fromContext(self.request.context);
    }

    /// The whole request context (`service`/`device` selection, `hub`).
    pub fn context(self: *const Emit) std.json.Value {
        return self.request.context;
    }

    pub fn emit(self: *const Emit, value: std.json.Value) !void {
        const svc = self.request.state.*.?;
        try self.request.emitter.emit(svc.allocator, value);
    }

    pub fn isCancelled(self: *const Emit) bool {
        return self.request.emitter.isCancelled();
    }
};

fn appStreamHandler(request: channel.StreamRequest(?*Service, void, void, std.json.Value)) !void {
    const svc = request.state.*.?;
    const value = svc.app_values.get(request.path) orelse return error.AppNotFound;
    try request.emitter.emit(svc.allocator, value);
}

fn appHeaderValue(allocator: Allocator, header: AppHeader) !Value {
    var map = std.json.ObjectMap.init(allocator);
    try map.put("type", .{ .string = try allocator.dupe(u8, header.@"type") });
    try map.put("name", .{ .string = try allocator.dupe(u8, header.name) });
    try map.put("path", .{ .string = try allocator.dupe(u8, header.path) });
    return .{ .object = map };
}

/// Deep-clones a Value: strings are duplicated, containers copied. Keys are
/// shared (borrowed), matching how ObjectMap stores them.
pub fn cloneValue(allocator: Allocator, value: Value) !Value {
    return switch (value) {
        .object => |map| blk: {
            var out = std.json.ObjectMap.init(allocator);
            var it = map.iterator();
            while (it.next()) |entry| {
                try out.put(entry.key_ptr.*, try cloneValue(allocator, entry.value_ptr.*));
            }
            break :blk .{ .object = out };
        },
        .array => |arr| blk: {
            var out = std.json.Array.init(allocator);
            for (arr.items) |item| {
                try out.append(try cloneValue(allocator, item));
            }
            break :blk .{ .array = out };
        },
        .string => |s| .{ .string = try allocator.dupe(u8, s) },
        .number_string => |s| .{ .number_string = try allocator.dupe(u8, s) },
        else => value,
    };
}

/// Frees a Value tree built by this library (updateValue/profileValue payloads,
/// app interface trees): string values and containers are freed; map keys are
/// borrowed and must not be freed.
pub fn valueDeinit(allocator: Allocator, value: Value) void {
    switch (value) {
        .object => |map| {
            var map_copy = map;
            var it = map_copy.iterator();
            while (it.next()) |entry| valueDeinit(allocator, entry.value_ptr.*);
            map_copy.deinit();
        },
        .array => |arr| {
            for (arr.items) |item| valueDeinit(allocator, item);
            arr.deinit();
        },
        .string => |s| allocator.free(s),
        .number_string => |s| allocator.free(s),
        else => {},
    }
}

// ---------------------------------------------------------------------------
// Element DSL (TS app.ts parity; see the wire contract). Every helper returns
// a fully owned Value — free with valueDeinit if you do not pass it to
// Service.app() (which clones it).

/// {"type":"text","value":...} — plain strings are also accepted as shorthand
/// text elements.
pub fn text(allocator: Allocator, value: []const u8) !Value {
    var map = std.json.ObjectMap.init(allocator);
    try map.put("type", .{ .string = try allocator.dupe(u8, "text") });
    try map.put("value", .{ .string = try allocator.dupe(u8, value) });
    return .{ .object = map };
}

pub fn progress(allocator: Allocator, value: []const u8, min: ?i64, max: ?i64) !Value {
    var map = std.json.ObjectMap.init(allocator);
    try map.put("type", .{ .string = try allocator.dupe(u8, "progress") });
    try map.put("value", .{ .string = try allocator.dupe(u8, value) });
    if (min) |m| try map.put("min", .{ .integer = m });
    if (max) |m| try map.put("max", .{ .integer = m });
    return .{ .object = map };
}

pub fn textField(allocator: Allocator, value: []const u8, placeholder: ?[]const u8, action_value: ?Value) !Value {
    var map = std.json.ObjectMap.init(allocator);
    try map.put("type", .{ .string = try allocator.dupe(u8, "textField") });
    try map.put("value", .{ .string = try allocator.dupe(u8, value) });
    if (placeholder) |p| try map.put("placeholder", .{ .string = try allocator.dupe(u8, p) });
    if (action_value) |a| try map.put("action", try cloneValue(allocator, a));
    return .{ .object = map };
}

pub fn button(allocator: Allocator, title: []const u8, action_value: Value) !Value {
    var map = std.json.ObjectMap.init(allocator);
    try map.put("type", .{ .string = try allocator.dupe(u8, "button") });
    try map.put("title", .{ .string = try allocator.dupe(u8, title) });
    try map.put("action", try cloneValue(allocator, action_value));
    return .{ .object = map };
}

pub fn slider(allocator: Allocator, value: []const u8, default_value: ?i64, min: ?i64, max: ?i64, step: ?i64, action_value: ?Value) !Value {
    var map = std.json.ObjectMap.init(allocator);
    try map.put("type", .{ .string = try allocator.dupe(u8, "slider") });
    try map.put("value", .{ .string = try allocator.dupe(u8, value) });
    if (default_value) |d| try map.put("defaultValue", .{ .integer = d });
    if (min) |m| try map.put("min", .{ .integer = m });
    if (max) |m| try map.put("max", .{ .integer = m });
    if (step) |s| try map.put("step", .{ .integer = s });
    if (action_value) |a| try map.put("action", try cloneValue(allocator, a));
    return .{ .object = map };
}

pub fn list(allocator: Allocator, data: []const u8, content: Value) !Value {
    var map = std.json.ObjectMap.init(allocator);
    try map.put("type", .{ .string = try allocator.dupe(u8, "list") });
    try map.put("data", .{ .string = try allocator.dupe(u8, data) });
    try map.put("content", try cloneValue(allocator, content));
    return .{ .object = map };
}

pub fn picker(allocator: Allocator, options: []const []const u8, selected: []const u8) !Value {
    var map = std.json.ObjectMap.init(allocator);
    try map.put("type", .{ .string = try allocator.dupe(u8, "picker") });
    var opts = std.json.Array.init(allocator);
    for (options) |opt| try opts.append(.{ .string = try allocator.dupe(u8, opt) });
    try map.put("options", .{ .array = opts });
    try map.put("selected", .{ .string = try allocator.dupe(u8, selected) });
    return .{ .object = map };
}

pub fn cell(allocator: Allocator, title: ?Value, subtitle: ?Value) !Value {
    var map = std.json.ObjectMap.init(allocator);
    try map.put("type", .{ .string = try allocator.dupe(u8, "cell") });
    if (title) |t| try map.put("title", try cloneValue(allocator, t));
    if (subtitle) |s| try map.put("subtitle", try cloneValue(allocator, s));
    return .{ .object = map };
}

pub fn files(allocator: Allocator, value: []const u8, title: ?Value, action_value: Value) !Value {
    var map = std.json.ObjectMap.init(allocator);
    try map.put("type", .{ .string = try allocator.dupe(u8, "files") });
    try map.put("value", .{ .string = try allocator.dupe(u8, value) });
    if (title) |t| try map.put("title", try cloneValue(allocator, t));
    try map.put("action", try cloneValue(allocator, action_value));
    return .{ .object = map };
}

pub fn fileOperation(allocator: Allocator, format: ?[]const u8, title: ?Value, action_value: Value) !Value {
    var map = std.json.ObjectMap.init(allocator);
    try map.put("type", .{ .string = try allocator.dupe(u8, "fileOperation") });
    if (format) |f| try map.put("format", .{ .string = try allocator.dupe(u8, f) });
    if (title) |t| try map.put("title", try cloneValue(allocator, t));
    try map.put("action", try cloneValue(allocator, action_value));
    return .{ .object = map };
}

pub fn hstack(allocator: Allocator, content: []const Value, spacing: ?i64) !Value {
    var map = std.json.ObjectMap.init(allocator);
    try map.put("type", .{ .string = try allocator.dupe(u8, "hstack") });
    try map.put("content", .{ .array = try cloneArray(allocator, content) });
    if (spacing) |s| try map.put("spacing", .{ .integer = s });
    return .{ .object = map };
}

pub fn vstack(allocator: Allocator, content: []const Value, spacing: ?i64) !Value {
    var map = std.json.ObjectMap.init(allocator);
    try map.put("type", .{ .string = try allocator.dupe(u8, "vstack") });
    try map.put("content", .{ .array = try cloneArray(allocator, content) });
    if (spacing) |s| try map.put("spacing", .{ .integer = s });
    return .{ .object = map };
}

pub fn zstack(allocator: Allocator, content: []const Value) !Value {
    var map = std.json.ObjectMap.init(allocator);
    try map.put("type", .{ .string = try allocator.dupe(u8, "zstack") });
    try map.put("content", .{ .array = try cloneArray(allocator, content) });
    return .{ .object = map };
}

pub fn spacer(allocator: Allocator) !Value {
    var map = std.json.ObjectMap.init(allocator);
    try map.put("type", .{ .string = try allocator.dupe(u8, "spacer") });
    return .{ .object = map };
}

/// Action reference: {path, body?, output?}. body/output may be strings or maps.
pub fn action(allocator: Allocator, path: []const u8, body: ?Value, output: ?Value) !Value {
    var map = std.json.ObjectMap.init(allocator);
    try map.put("path", .{ .string = try allocator.dupe(u8, path) });
    if (body) |b| try map.put("body", try cloneValue(allocator, b));
    if (output) |o| try map.put("output", try cloneValue(allocator, o));
    return .{ .object = map };
}

/// Profile icon: {symbol?, text?}.
pub fn icon(allocator: Allocator, symbol: ?[]const u8, text_value: ?[]const u8) !Value {
    var map = std.json.ObjectMap.init(allocator);
    if (symbol) |s| try map.put("symbol", .{ .string = try allocator.dupe(u8, s) });
    if (text_value) |t| try map.put("text", .{ .string = try allocator.dupe(u8, t) });
    return .{ .object = map };
}

fn cloneArray(allocator: Allocator, items: []const Value) !std.json.Array {
    var out = std.json.Array.init(allocator);
    for (items) |item| try out.append(try cloneValue(allocator, item));
    return out;
}
