// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// What the phone tells its watch, through WatchConnectivity: the watch has
/// no network of its own for an ordinary app, so it shows the group as the
/// phone sees it (docs/apps.md, Apple Watch). Never the clipboard.
struct WatchState: Codable, Equatable {
    struct Device: Codable, Equatable, Identifiable {
        var id: String
        var name: String
        /// An SF Symbol for its kind.
        var symbol: String
        var online: Bool
        /// What this watch may do to it, as PhoneGroup.WatchAction's raw
        /// values; nil from a phone before 0.6.
        var can: [String]?
        /// The quick actions it has on, while it is connected.
        var actions: [String]?
        /// The name of the phone's collection it is in; nil in none, and
        /// from a phone before 0.6.
        var collection: String?
        /// The watch's own phone, which the phone lists first as every app
        /// lists the device it runs on; nil for the others.
        var phone: Bool?
    }

    /// The devices as the watch lists them: those in no collection, then
    /// each of the phone's collections in its order (docs/apps.md,
    /// "Collections and the order of the tiles"). The phone sends a
    /// collection's devices one after another.
    var sections: [(name: String?, devices: [Device])] {
        var out: [(name: String?, devices: [Device])] = [(nil, devices.filter { $0.collection == nil })]
        for d in devices {
            guard let c = d.collection else { continue }
            if out.count > 1, out[out.count - 1].name == c {
                out[out.count - 1].devices.append(d)
            } else {
                out.append((c, [d]))
            }
        }
        return out
    }

    /// Where sync away from home stands, as the phone's Settings say it.
    enum Away: String, Codable {
        case off, atHome, connecting, connected, waiting
    }

    var hasGroup = false
    var devices: [Device] = []
    /// nil without a group.
    var away: Away?
    /// The latest events, newest first.
    var events: [String] = []
    /// The phone's colour, by its name in Tokens.colors.
    var color = "terminal"

    static let key = "state"
    /// The message that turns the phone's sync away from home on or off.
    static let awayKey = "away"

    /// The root phone's ask that the watch make its admin key (docs/protocol.md,
    /// section 10, "Watches"); the watch answers with requestKey, a KeyRequest,
    /// or refusedKey, why it made none.
    static let certifyKey = "certify", requestKey = "request", refusedKey = "refused"
    /// The root's answer once it certified the key: an Admission.
    static let admittedKey = "admitted"
    /// Why a watch makes no key: no passcode or no wrist detection, or no
    /// Secure Enclave.
    static let notProtected = "not-protected", noSecureEnclave = "no-secure-enclave"

    /// The key a watch made for the root to certify.
    struct KeyRequest: Codable, Equatable {
        /// The device ID the watch picked for itself.
        var device: String
        var name: String
        /// Its SubjectPublicKeyInfo, DER.
        var key: Data
    }

    /// The watch's ask that the phone build the body of an emergency action
    /// (docs/protocol.md, section 10, "Watches"); the phone answers with bodyKey
    /// or refusedKey.
    static let askKey = "ask", bodyKey = "body"
    /// What the watch signed, which the phone brings into the group; it
    /// answers with doneKey, true, or refusedKey.
    static let signedKey = "signed", doneKey = "done"

    struct Ask: Codable, Equatable {
        /// A PhoneGroup.WatchAction's raw value.
        var action: String
        var device: String
        /// The quick action's name, for action.
        var name: String?
        /// The watch's own device ID.
        var watch: String
    }

    struct Signed: Codable, Equatable {
        var body: Data
        /// ECDSA with SHA-256 over body, DER.
        var signature: Data
        var adminCA: Data
    }

    /// What the root gave the watch: its admin CA, in the group with that tag.
    struct Admission: Codable, Equatable {
        var device: String
        var adminCA: Data
        var group: String
    }

    var data: [String: Any] {
        (try? JSONEncoder().encode(self)).map { [Self.key: $0] } ?? [:]
    }

    init() {}

    init?(_ data: [String: Any]) {
        guard let d = data[Self.key] as? Data, let s = try? JSONDecoder().decode(Self.self, from: d) else { return nil }
        self = s
    }
}
