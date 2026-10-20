//! hub-service-zig: a lite Zig port of hub-service (TS reference).
//!
//! Connect to a hub (hub-lite/hub-pro), host post/stream API endpoints,
//! register apps, and call API through the hub. On every (re)connect the
//! service attaches a fresh hub-pro auth token (`auth` header) signed by the
//! keychain `auth` file (TS parity with hub-service/keychain.ts) — hub-lite
//! ignores these headers. With no hub key pinned for the address it connects
//! with v0, asks hub/info for the hub key, pins it in hubs.json and
//! reconnects with a v1 token bound to that hub (Docs/Devices/protocol.md).
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

pub const Keychain = keychain_mod.Keychain;
pub const PRIVATE_DER_LENGTH = keychain_mod.PRIVATE_DER_LENGTH;
pub const PUBLIC_DER_LENGTH = keychain_mod.PUBLIC_DER_LENGTH;
pub const AUTH_EXPIRY = keychain_mod.AUTH_EXPIRY;
pub const authToken = keychain_mod.authToken;

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
    /// ("s3-local/Backup Disk"). Default: name, else the first segment of
    /// the first registered path, else "service". Must outlive the Service.
    instance: ?[]const u8 = null,
    /// Suggested device name in the certificate. Default: the host name.
    device_name: ?[]const u8 = null,
    /// Declared parent device name, for containers and VMs.
    parent: ?[]const u8 = null,
    /// Device key path (default: $HUB_DEVICE_KEY, /var/lib/hub/device.key
    /// for root, else ~/.hub/device.key).
    device_key_path: ?[]const u8 = null,
    /// No device key and no `device` header: a plain key connection.
    disable_device: bool = false,
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

/// Pro-only wire-parity fields; hub-lite ignores them.
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
    /// The current connection used a pinned hub key (v1).
    hub_key_known: bool = false,
    /// Null when device mode is off or there is no home directory.
    device_key: ?device.DeviceKey = null,
    instance_option: ?[]const u8 = null,
    device_name: ?[]const u8 = null,
    parent: ?[]const u8 = null,
    /// The first registered path (owned by `paths`).
    first_path: ?[]const u8 = null,
    /// The current `device` header (owned) and its expiry.
    certificate: ?[]u8 = null,
    certificate_exp: i64 = 0,

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
        if (!options.disable_device) {
            if (options.device_key_path) |path| {
                device_key = try device.DeviceKey.init(allocator, path);
            } else if (try device.defaultPath(allocator)) |path| {
                defer allocator.free(path);
                device_key = try device.DeviceKey.init(allocator, path);
            }
        }
        errdefer if (device_key) |*key| key.deinit();

        return .{
            .allocator = allocator,
            .ch = channel.Channel(?*Service).init(allocator),
            .address = address,
            .profile = profile,
            .owned_env = owned_env,
            .owned_key_env = owned_key_env,
            .keychain = keychain,
            .device_key = device_key,
            .instance_option = options.instance,
            .device_name = options.device_name,
            .parent = options.parent,
        };
    }

    pub fn deinit(self: *Service) void {
        self.stop_flag.store(true, .release);
        if (self.poll_thread) |thread| thread.join();
        if (self.client) |*client| client.deinit();
        if (self.owned_env) |env| self.allocator.free(env);
        if (self.owned_key_env) |env| self.allocator.free(env);
        self.keychain.deinit();
        if (self.device_key) |*key| key.deinit();
        if (self.certificate) |certificate| self.allocator.free(certificate);

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
            fn invoke(request: channel.StreamRequest(?*Service, std.json.Value, void, std.json.Value)) !void {
                const emit = Emit{ .request = &request };
                try handler(request.body, emit);
            }
        };
        _ = try self.ch.stream(std.json.Value, std.json.Value, void, path, Wrapper.invoke);
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

    /// Calls an API through the hub. Errors with error.ServiceNotStarted if
    /// the service has not been started (or is between reconnects).
    pub fn send(self: *Service, allocator: Allocator, path: []const u8, body: ?Value) !channel.CallResult(std.json.Value) {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.client == null) return error.ServiceNotStarted;
        const client = &self.client.?;
        return client.send(allocator, std.json.Value, path, body orelse .null);
    }

    /// Opens a stream call through the hub. Errors with error.ServiceNotStarted
    /// if the service has not been started (or is between reconnects).
    /// NOTE: iterating the returned Values pumps the transport; with the poll
    /// thread running, do so from a single thread (the poll thread itself is
    /// the safe choice).
    pub fn values(self: *Service, allocator: Allocator, path: []const u8, body: ?Value) !channel.Values(std.json.Value) {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.client == null) return error.ServiceNotStarted;
        const client = &self.client.?;
        return client.values(allocator, std.json.Value, std.json.Value, void, path, body orelse .null, {});
    }

    /// Connects to the hub and starts the poll/reconnect loop. On every
    /// isConnected false->true transition (per connection) it sends
    /// hub/profile/update (if a profile is set) then hub/service/update.
    pub fn start(self: *Service) !*Service {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.started) return self;
        self.started = true;
        self.poll_thread = try std.Thread.spawn(.{}, Service.pollLoop, .{self});
        return self;
    }

    /// The address as a URL: a port becomes `ws://127.0.0.1:<port>`. Hub key
    /// pins are stored under it. Owned; free it.
    pub fn addressUrl(self: *Service, allocator: Allocator) ![]u8 {
        return switch (self.address) {
            .port => |port| std.fmt.allocPrint(allocator, "ws://127.0.0.1:{d}", .{port}),
            .url => |url| allocator.dupe(u8, url),
        };
    }

    /// The instance name in the device certificate: the `instance` option,
    /// else the profile name, else the first segment of the first registered
    /// path, else "service". Borrowed from the Service.
    pub fn instance(self: *const Service) []const u8 {
        if (self.instance_option) |value| {
            if (value.len > 0) return value;
        }
        if (self.profile) |profile| {
            if (profile.name) |name| {
                if (name.len > 0) return name;
            }
        }
        if (self.first_path) |path| {
            const segment = path[0 .. std.mem.indexOfScalar(u8, path, '/') orelse path.len];
            if (segment.len > 0) return segment;
        }
        return "service";
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
        var host: [std.posix.HOST_NAME_MAX]u8 = undefined;
        const device_name = self.device_name orelse device.hostName(&host);
        const parent: ?[]const u8 = if (self.parent) |parent| (if (parent.len > 0) device.truncate(parent, 64) else null) else null;
        const header = try device_key.sign(.{
            .device = device_spki,
            .service = service_key,
            .instance = device.truncate(self.instance(), 128),
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

    /// Forgets the hub key pinned for this service's address. Use it when a
    /// v1 connect keeps failing with `invalid signature` because the hub's
    /// key changed on purpose; the next connect learns it again.
    pub fn forgetHubKey(self: *Service) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const address = try self.addressUrl(self.allocator);
        defer self.allocator.free(address);
        try self.keychain.forgetHubKey(address);
    }

    /// Requests the poll loop to stop (used by deinit).
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
                if (self.first_path == null) self.first_path = owned;
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

    /// A fresh raw header block for the HTTP upgrade request: the auth token
    /// (built per connect — the token embeds an expiry; v1 when a hub key is
    /// pinned for the address, else v0) plus the protocol version. The
    /// channel client memcpys this verbatim after the standard headers.
    /// hub-lite ignores these headers. Owned; free it.
    pub fn connectHeaderBlock(self: *Service) ![]u8 {
        const address = try self.addressUrl(self.allocator);
        defer self.allocator.free(address);
        const hub_key = try self.keychain.hubKey(address);
        defer if (hub_key) |key| self.allocator.free(key);
        self.hub_key_known = hub_key != null;
        const token = try self.keychain.signForHub(hub_key, AUTH_EXPIRY);
        defer self.allocator.free(token);
        // A device key that can't be read or created leaves a plain key
        // connection.
        const certificate = self.currentCertificate(std.time.timestamp()) catch |err| blk: {
            std.debug.print("hub-service: device certificate failed ({s})\n", .{@errorName(err)});
            break :blk null;
        };
        if (certificate) |header| {
            return std.fmt.allocPrint(self.allocator, "auth: {s}\r\nv: {s}\r\ndevice: {s}\r\n", .{ token, if (hub_key != null) "1" else "0", header });
        }
        return std.fmt.allocPrint(self.allocator, "auth: {s}\r\nv: {s}\r\n", .{ token, if (hub_key != null) "1" else "0" });
    }

    /// Asks hub/info for the hub key and pins it. True when a key was pinned
    /// (the caller reconnects with v1); hub-lite answers with an error.
    fn learnHubKey(self: *Service, client: *channel.Client(?*Service)) bool {
        var result = client.send(self.allocator, std.json.Value, "hub/info", {}) catch return false;
        defer result.deinit(self.allocator);
        const info = switch (result) {
            .ok => |value| value orelse return false,
            .remote_err => return false,
        };
        if (info != .object) return false;
        const key = info.object.get("key") orelse return false;
        if (key != .string or key.string.len == 0) return false;
        const address = self.addressUrl(self.allocator) catch return false;
        defer self.allocator.free(address);
        self.keychain.pinHubKey(address, key.string) catch return false;
        return true;
    }

    fn pollLoop(self: *Service) void {
        var was_connected = false;
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
                    const headers = self.connectHeaderBlock() catch |err| {
                        std.debug.print("hub-service: auth token failed ({s}); retrying in 1s\n", .{@errorName(err)});
                        self.mutex.unlock();
                        std.Thread.sleep(1 * std.time.ns_per_s);
                        continue;
                    };
                    defer self.allocator.free(headers);
                    const new_client = switch (self.address) {
                        .port => |port| self.ch.connect(self.allocator, port, .{ .state = self, .headers = headers }),
                        .url => |url| self.ch.connect(self.allocator, url, .{ .state = self, .headers = headers }),
                    } catch |err| {
                        std.debug.print("hub-service: connect failed ({s}); retrying in 1s\n", .{@errorName(err)});
                        self.mutex.unlock();
                        std.Thread.sleep(1 * std.time.ns_per_s);
                        continue;
                    };
                    self.client = new_client;
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
                    self.sendUpdates(client) catch |err| {
                        std.debug.print("hub-service: update send failed ({s})\n", .{@errorName(err)});
                    };
                    was_connected = true;
                    if (!self.hub_key_known and self.learnHubKey(client)) {
                        // Reconnect at once with the hub-bound v1 token.
                        client.deinit();
                        self.client = null;
                        was_connected = false;
                        self.mutex.unlock();
                        continue;
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
    request: *const channel.StreamRequest(?*Service, std.json.Value, void, std.json.Value),

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
