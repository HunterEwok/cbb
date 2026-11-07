// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// Commands (docs/protocol.md, section 15): an admin's order for one member,
/// signed like a record and never stored, as internal/group/command.go makes
/// them: one sets the receiver's sync mode, another makes the receiver, an
/// admin computer, the group's hub in place of this phone; a paste command
/// puts a text where the receiver's focus is, and paste-off turns remote
/// paste off on the receiver (design.md, "Remote paste"); an action command
/// runs one of the receiver's quick actions by its name, and actions-off
/// turns them all off there (design.md, "Quick actions"); away-off turns
/// sync away from home off on the receiver. A watch signs only those that
/// turn things off and action (watchTypes).
public enum Commands {
    /// How long after signing a command expires; the receivers take at most 30 s.
    public static let lifetimeMS: Int64 = 30_000

    /// The version of command bodies.
    public static let version = 1

    /// A command body.
    public struct Body: Codable, Equatable, Sendable {
        public var v = Commands.version
        public var type: String
        public var group: String
        public var by: String
        public var to: String
        public var id: String
        public var time_ms: Int64
        public var expires_ms: Int64
        public var mode: String?
        public var hub: HubOrder?
        public var enter: Bool?
        public var kind: String?
        public var text: String?
        public var action: String?
        /// mute: how long, up to maxMuteMS; nil or 0 for until unmute.
        public var for_ms: Int64?
    }

    /// What a hub command tells the new hub (section 11, "Moving the
    /// hub"): where its clients reach it and the old hub's clients, with the
    /// keys they have.
    public struct HubOrder: Codable, Equatable, Sendable {
        public struct Forwarder: Codable, Equatable, Sendable {
            public var endpoint: String
            public var key: String
        }

        /// An order to stop being a hub, with nothing else in it.
        public var stop: Bool?
        public var forwarder: Forwarder?
        public var endpoints: [String]?
        public var clients: [PhoneHub.Client]?

        /// Whether the order is valid, as Go's HubOrder.check: a forwarder
        /// with an address and a key, or an address at least; at most 8
        /// addresses and maxHubClients clients, each a device ID once with
        /// keys of 32 bytes; or stop and nothing else.
        var valid: Bool {
            let endpoints = endpoints ?? [], clients = clients ?? []
            if stop == true { return forwarder == nil && endpoints.isEmpty && clients.isEmpty }
            if let f = forwarder, f.endpoint.isEmpty || f.key.isEmpty { return false }
            guard forwarder != nil || !endpoints.isEmpty, endpoints.count <= 8, clients.count <= Commands.maxHubClients else { return false }
            var seen = Set<String>()
            return clients.allSatisfy { Records.isDeviceID($0.device) && seen.insert($0.device).inserted && $0.key.count == 32 && $0.psk.count == 32 }
        }
    }

    /// The most clients a hub command hands over, as many as a hub keeps.
    public static let maxHubClients = 256

    public enum Failure: Error { case unknownMode(String), badHubOrder, badPaste, badAction(String), badMute }

    /// The longest name of a quick action, and the most a hello lists.
    public static let maxActionName = 32
    public static let maxHelloActions = 64

    /// The presets every computer knows, in the order the apps show them.
    public static let presets = ["lock", "sleep", "reboot", "shutdown", "cancel-shutdown", "restart", "keyboard-layout"]

    /// Whether name is a quick action's name: 1 to 32 of a-z, 0-9 and -,
    /// starting with a letter.
    public static func validActionName(_ name: String) -> Bool {
        let u = Array(name.utf8)
        func ok(_ c: UInt8) -> Bool { (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) || c == 0x2d }
        return (1...maxActionName).contains(u.count) && u[0] >= 0x61 && u[0] <= 0x7a && u.allSatisfy(ok)
    }

    /// An action command for the device to: run its quick action name,
    /// which only the receiver defines. Signed as mode.
    public static func action(to: String, name: String, group: String, by: String, now: Date, signer: CertificateSigner,
                              adminCA: Data? = nil, seal: Data? = nil, id: String = newID()) throws -> Member.Record {
        guard validActionName(name) else { throw Failure.badAction(name) }
        let ms = Records.ms(now)
        return try sign(Body(type: "action", group: group, by: by, to: to, id: id, time_ms: ms, expires_ms: ms + lifetimeMS, action: name),
                        signer: signer, adminCA: adminCA, seal: seal)
    }

    /// The commands a watch's admin key may sign (docs/protocol.md, section
    /// 10, rule 8), as Go's WatchCommand.
    public static let watchTypes: Set<String> = ["paste-off", "actions-off", "away-off", "action"]

    /// An away-off command for the device to: it turns sync away from home
    /// off there, and its tunnel keys go. Signed as mode.
    public static func awayOff(to: String, group: String, by: String, now: Date, signer: CertificateSigner,
                               adminCA: Data? = nil, seal: Data? = nil, id: String = newID()) throws -> Member.Record {
        let ms = Records.ms(now)
        return try sign(Body(type: "away-off", group: group, by: by, to: to, id: id, time_ms: ms, expires_ms: ms + lifetimeMS),
                        signer: signer, adminCA: adminCA, seal: seal)
    }

    /// An actions-off command for the device to: it turns every quick
    /// action off there. Signed as mode.
    public static func actionsOff(to: String, group: String, by: String, now: Date, signer: CertificateSigner,
                                  adminCA: Data? = nil, seal: Data? = nil, id: String = newID()) throws -> Member.Record {
        let ms = Records.ms(now)
        return try sign(Body(type: "actions-off", group: group, by: by, to: to, id: id, time_ms: ms, expires_ms: ms + lifetimeMS),
                        signer: signer, adminCA: adminCA, seal: seal)
    }

    /// A mute command for the device to: its copies stop reaching the
    /// group for forMS milliseconds, 0 for until an unmute command
    /// (design.md, "Muting a device"). Signed as mode.
    public static func mute(to: String, forMS: Int64 = 0, group: String, by: String, now: Date, signer: CertificateSigner,
                            adminCA: Data? = nil, seal: Data? = nil, id: String = newID()) throws -> Member.Record {
        guard (0...maxMuteMS).contains(forMS) else { throw Failure.badMute }
        let ms = Records.ms(now)
        return try sign(Body(type: "mute", group: group, by: by, to: to, id: id, time_ms: ms, expires_ms: ms + lifetimeMS,
                             for_ms: forMS > 0 ? forMS : nil),
                        signer: signer, adminCA: adminCA, seal: seal)
    }

    /// An unmute command for the device to: it ends an admin's mute there.
    /// Signed as mode.
    public static func unmute(to: String, group: String, by: String, now: Date, signer: CertificateSigner,
                              adminCA: Data? = nil, seal: Data? = nil, id: String = newID()) throws -> Member.Record {
        let ms = Records.ms(now)
        return try sign(Body(type: "unmute", group: group, by: by, to: to, id: id, time_ms: ms, expires_ms: ms + lifetimeMS),
                        signer: signer, adminCA: adminCA, seal: seal)
    }

    /// The longest text of a paste command, in bytes of UTF-8, and of one
    /// typed key by key.
    public static let maxPasteText = 1 << 20
    public static let maxTypeText = 4 << 10

    /// A new command ID: 128 random bits in hex.
    public static func newID() -> String {
        var g = SystemRandomNumberGenerator()
        return (0..<16).map { _ in String(format: "%02x", UInt8.random(in: 0...255, using: &g)) }.joined()
    }

    /// A mode command for the device to, signed with the root key (adminCA
    /// nil) or with an admin CA key, adminCA being that CA's certificate.
    public static func mode(to: String, mode: String, group: String, by: String, now: Date, signer: CertificateSigner,
                            adminCA: Data? = nil, seal: Data? = nil, id: String = newID()) throws -> Member.Record {
        guard Member.modes.contains(mode) else { throw Failure.unknownMode(mode) }
        let ms = Records.ms(now)
        let body = Body(type: "mode", group: group, by: by, to: to, id: id, time_ms: ms, expires_ms: ms + lifetimeMS, mode: mode)
        return try sign(body, signer: signer, adminCA: adminCA, seal: seal)
    }

    /// A hub command for the admin computer to: it becomes the group's
    /// hub, reached through the forwarder (endpoint "ip:port" and the pin
    /// of its key) and at endpoints, and takes clients, the old hub's, with
    /// the keys they have. Signed as mode.
    public static func hub(to: String, forwarder: (endpoint: String, pin: String)?, endpoints: [String] = [], clients: [PhoneHub.Client],
                           group: String, by: String, now: Date, signer: CertificateSigner,
                           adminCA: Data? = nil, seal: Data? = nil, id: String = newID()) throws -> Member.Record {
        guard forwarder != nil || !endpoints.isEmpty, endpoints.count <= 8, clients.count <= maxHubClients else { throw Failure.badHubOrder }
        let order = HubOrder(forwarder: forwarder.map { HubOrder.Forwarder(endpoint: $0.endpoint, key: $0.pin) },
                             endpoints: endpoints.isEmpty ? nil : endpoints, clients: clients.isEmpty ? nil : clients)
        let ms = Records.ms(now)
        let body = Body(type: "hub", group: group, by: by, to: to, id: id, time_ms: ms, expires_ms: ms + lifetimeMS, hub: order)
        return try sign(body, signer: signer, adminCA: adminCA, seal: seal)
    }

    /// A paste command for the device to: put text where its focus is, by
    /// method "paste" (the clipboard and the paste keys) or "type", then
    /// press Enter when enter is set; kind is "text" or "secret". Signed as
    /// mode.
    public static func paste(to: String, text: String, method: String = "paste", enter: Bool = false, kind: String = "text",
                             group: String, by: String, now: Date, signer: CertificateSigner,
                             adminCA: Data? = nil, seal: Data? = nil, id: String = newID()) throws -> Member.Record {
        let limit = method == "paste" ? maxPasteText : method == "type" ? maxTypeText : 0
        guard limit > 0, kind == "text" || kind == "secret", !text.isEmpty, text.utf8.count <= limit else { throw Failure.badPaste }
        let ms = Records.ms(now)
        let body = Body(type: "paste", group: group, by: by, to: to, id: id, time_ms: ms, expires_ms: ms + lifetimeMS, mode: method,
                        enter: enter ? true : nil, kind: kind, text: text)
        return try sign(body, signer: signer, adminCA: adminCA, seal: seal)
    }

    /// A paste-off command for the device to: it turns remote paste off
    /// there. Signed as mode.
    public static func pasteOff(to: String, group: String, by: String, now: Date, signer: CertificateSigner,
                                adminCA: Data? = nil, seal: Data? = nil, id: String = newID()) throws -> Member.Record {
        let ms = Records.ms(now)
        return try sign(Body(type: "paste-off", group: group, by: by, to: to, id: id, time_ms: ms, expires_ms: ms + lifetimeMS),
                        signer: signer, adminCA: adminCA, seal: seal)
    }

    /// Signs body; with seal, the receiver's key for sealed messages from
    /// its device record, its orders are sealed to that key first
    /// (docs/protocol.md, section 15, "Sealed commands"), in the Rust core.
    static func sign(_ body: Body, signer: CertificateSigner, adminCA: Data?, seal: Data? = nil) throws -> Member.Record {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var data = try enc.encode(body)
        if let seal { data = try Core.sealCommand(data, key: seal) }
        return Member.Record(body: data, sig: try signer.signature(for: data), chain: adminCA.map { [$0] })
    }

    /// How far ahead of the receiver's clock a command's time may be.
    public static let aheadMS: Int64 = 60_000

    /// The most bytes of a command's body, as Go takes: a hub command
    /// carries up to 256 clients' keys.
    static let maxBody = 64 << 10
    /// A paste command's body may be larger: it carries up to 1 MiB of text.
    static let maxPasteBody = 2 << 20

    /// Why a command was refused, in words for the sender.
    public struct Refused: Error, Equatable { public var reason: String }

    /// Checks command c for the member me, as every member does, in the
    /// Rust core (RecordSet.check): an admin of the group that may sign its
    /// type signed it now, its by is the signer's device when the records
    /// show it, it is for me in this group, it has not expired and was not
    /// signed in the future, at nowMS. A sealed command opens with secret,
    /// this member's secret for sealed messages (SealKey). The caller keeps
    /// the replay cache; a mode command's mode is not checked against
    /// Member.modes here.
    public static func verify(_ c: Member.Record, records: RecordSet, me: String, nowMS: Int64, secret: Data? = nil) throws -> Body {
        var set = records
        set.nowMS = nowMS
        return try set.check(command: c, me: me, secret: secret).command
    }

    /// The members every command's body has.
    static let fields = ["v", "type", "group", "by", "to", "id", "time_ms", "expires_ms"]

    /// The longest mute a command gives: 30 days (Go's group.MaxMute).
    public static let maxMuteMS: Int64 = 30 * 24 * 3_600_000

    /// The keys of a hub order's clients as their strings, to check their form.
    private struct RawHub: Decodable {
        struct Order: Decodable {
            struct Client: Decodable { var key, psk: String? }
            var clients: [Client]?
        }

        var hub: Order?
    }

    /// Reads a command's body once the Rust core took it (parse_body), in
    /// the strict form of signed bodies, as Go's parseCommandBody.
    static func parse(_ data: Data) throws -> Body {
        func refuse(_ reason: String) -> Refused { Refused(reason: reason) }
        // The core decides whether the body is taken; the checks below only
        // read its fields.
        if let why = Core.bodyRefusal("command", data) { throw refuse("the command is not valid: \(why)") }
        guard data.count <= maxPasteBody else { throw refuse("the command is too large") }
        do {
            try Strict.check(data, required: fields)
        } catch let e as Strict.Invalid {
            throw refuse("the command is not valid: \(e.reason)")
        }
        guard let b = try? JSONDecoder().decode(Body.self, from: data), let raw = try? JSONDecoder().decode(RawHub.self, from: data),
              (raw.hub?.clients ?? []).allSatisfy({ Strict.base64($0.key ?? "") != nil && Strict.base64($0.psk ?? "") != nil }) else {
            throw refuse("the command is not valid")
        }
        guard b.type == "paste" || data.count <= maxBody else { throw refuse("the command is too large") }
        func hex32(_ s: String) -> Bool { s.utf8.count == 32 && s.allSatisfy { "0123456789abcdef".contains($0) } }
        guard b.v == Commands.version else { throw refuse("unknown command version") }
        guard hex32(b.id) else { throw refuse("the command has no valid ID") }
        // As in Go, an empty string is no paste and no action.
        guard b.type == "paste" || (b.enter != true && (b.kind ?? "").isEmpty && (b.text ?? "").isEmpty) else { throw refuse("a \(b.type) command carries a paste") }
        guard b.type == "action" || (b.action ?? "").isEmpty else { throw refuse("a \(b.type) command names an action") }
        guard b.type == "mute" || (b.for_ms ?? 0) == 0 else { throw refuse("a \(b.type) command gives a time") }
        switch b.type {
        case "mode": guard let m = b.mode, !m.isEmpty, b.hub == nil else { throw refuse("a mode command names no mode") }
        case "hub":
            guard let h = b.hub, (b.mode ?? "").isEmpty else { throw refuse("a hub command has no order") }
            guard h.valid else { throw refuse("a hub command's order is not valid") }
        case "mute":
            guard b.hub == nil, (b.mode ?? "").isEmpty else { throw refuse("a mute command carries an order") }
            guard (0...maxMuteMS).contains(b.for_ms ?? 0) else { throw refuse("a mute command's time is not from 0 to \(maxMuteMS) ms") }
        case "paste-off", "actions-off", "away-off", "unmute": guard b.hub == nil, (b.mode ?? "").isEmpty else { throw refuse("a \(b.type) command carries an order") }
        case "action":
            guard b.hub == nil, (b.mode ?? "").isEmpty else { throw refuse("an action command carries an order") }
            guard validActionName(b.action ?? "") else { throw refuse("an action command names no valid action") }
        case "paste":
            let limit = b.mode == "paste" ? maxPasteText : b.mode == "type" ? maxTypeText : 0
            guard limit > 0 else { throw refuse("a paste command's way is not paste or type") }
            guard b.hub == nil else { throw refuse("a paste command carries a hub order") }
            guard b.kind == "text" || b.kind == "secret" else { throw refuse("a paste command's kind is not text or secret") }
            let n = b.text?.utf8.count ?? 0
            guard n > 0 else { throw refuse("a paste command has no text") }
            guard n <= limit else { throw refuse("a paste command's text is longer than \(limit) bytes") }
        default: throw refuse("unknown command type \(b.type)")
        }
        guard hex32(b.to) else { throw refuse("the command names no valid device") }
        guard hex32(b.by) else { throw refuse("a command's by is not a device ID") }
        // A time before 1970 is no signing time; from it the difference cannot overflow.
        guard b.time_ms >= 0, b.expires_ms > b.time_ms, b.expires_ms - b.time_ms <= lifetimeMS else { throw refuse("the command's lifetime is not valid") }
        return b
    }

    /// The ID in a command's body, or nil when it has none.
    public static func id(of c: Member.Record) -> String? { head(of: c)?.id }

    /// The receiver a command's body names, or nil when it names none.
    static func to(of c: Member.Record) -> String? { head(of: c)?.to }

    /// When a command expires, or nil when its body says not.
    static func expires(of c: Member.Record) -> Int64? { head(of: c)?.expires_ms }

    private struct Head: Decodable { var id: String?, to: String?, expires_ms: Int64? }
    private static func head(of c: Member.Record) -> Head? { try? JSONDecoder().decode(Head.self, from: c.body) }
}
