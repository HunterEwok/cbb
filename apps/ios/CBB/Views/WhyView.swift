// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#if canImport(CBBKit)
import CBBKit
#endif
import SwiftUI

/// The screen "Why it does not sync" in the advanced settings (docs/apps.md,
/// "Why it does not sync"): the reason that stops the most, large, with what
/// to do, then the others. The core decides the reasons; the app only says
/// each code in its words. The iPhone app and the Mac app share this file.
struct WhyList: View {
    /// The reasons; nil while they are not known yet.
    let reasons: [WhyReason]?
    /// Whether the error details are on: then each reason shows its code and
    /// the member's own words.
    let details: Bool
    /// Names the networks this computer is on now as home, as cbb network
    /// does (the Mac); nil where no reason asks for it (the phone).
    var homeNetwork: (() -> Void)? = nil
    @Environment(\.palette) private var palette

    var body: some View {
        if let reasons {
            if let first = reasons.first {
                Section {
                    row(first, main: true)
                }
                if reasons.count > 1 {
                    Section {
                        ForEach(reasons.dropFirst(), id: \.self) { row($0, main: false) }
                    } header: { Text("Also") }
                }
            } else {
                Section {
                    Label { Text("Everything syncs.") } icon: { Image(systemName: "checkmark.circle") }
                }
            }
        } else {
            Section { ProgressView() }
        }
    }

    private func row(_ r: WhyReason, main: Bool) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            reason(r, main: main)
            if r.code == "new_network", let homeNetwork {
                Button(action: homeNetwork) { Text("This is my home network") }
                    .accessibilityIdentifier("why-home-network")
            }
        }
    }

    private func reason(_ r: WhyReason, main: Bool) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Label {
                Self.title(r).font(main ? .headline : .body)
            } icon: {
                Image(systemName: Self.symbol(r)).foregroundStyle(r.level == "stop" ? palette.danger : palette.textDim)
            }
            if let a = Self.action(r) {
                a.font(.subheadline).foregroundStyle(palette.textDim)
            }
            if details {
                Text(verbatim: [r.code, r.detail].compactMap { $0 }.joined(separator: ": "))
                    .font(.caption.monospaced()).foregroundStyle(palette.textDim).textSelection(.enabled)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("why-" + r.code)
    }

    static func symbol(_ r: WhyReason) -> String {
        switch r.level {
        case "stop": "xmark.octagon"
        case "warn": "exclamationmark.triangle"
        default: "info.circle"
        }
    }

    /// What is wrong, in the app's words.
    static func title(_ r: WhyReason) -> Text {
        let device = r.device ?? "", value = r.value ?? ""
        let names = ListFormatter.localizedString(byJoining: r.devices ?? [])
        let date = r.until?.formatted(date: .abbreviated, time: .shortened) ?? ""
        _ = (device, value, names, date)
        return switch r.code {
        case "not_in_group": Text("This device is in no group.")
        case "removed": Text("This device was removed from the group.")
        case "taken_over": Text("\(device) took the group over from this device.")
        case "frozen": Text("This device's rights as a trusted device are paused.")
        case "cert_expired": Text("This device's certificate ended on \(date).")
        case "cert_ending": Text("This device's certificate ends on \(date).")
        case "stopped": Text("The group's records stop the exchange.")
        case "secrets_stopped": Text("The group sends no secrets until its owner decides.")
        case "sync_off": r.until == nil ? Text("Sync is off on this device.") : Text("Sync is off on this device until \(date).")
        case "only_device": Text("This is the group's only device.")
        case "away_off": Text("No device of the group is on this network.")
        case "new_network": Text("This computer has not met its group on this network.")
        case "no_hub": Text("Everywhere is on, but the group has no base.")
        case "tunnel_blocked": Text("The tunnel to the base \(device) does not get through.")
        case "hub_unreachable": Text("The base \(device) does not answer.")
        case "alone": Text("Connected, but no other device of the group is online.")
        case "relay_down": Text("The backup server does not answer.")
        case "hub_waiting": Text("This device is the base, and no device has connected yet.")
        case "muted": r.until == nil ? Text("This device is muted: its copies do not reach the group.") : Text("This device is muted until \(date): its copies do not reach the group.")
        case "forwarder_down": Text("The connection server does not take this base.")
        case "entries_stale": Text("The list of the connection servers' entry points is out of date.")
        case "newer": Text("The group has records of a newer version.")
        case "unreached": Text("Devices at home cannot connect to this one: \(names).")
        case "devices_offline": Text("Offline: \(names).")
        case "devices_sync_off": Text("Sync is off on: \(names).")
        case "devices_muted": Text("Muted: \(names).")
        case "update": Text("CBB \(value) is available.")
        default: Text(verbatim: r.code)
        }
    }

    /// What to do, nil when there is nothing to do.
    static func action(_ r: WhyReason) -> Text? {
        let device = r.device ?? ""
        _ = device
        return switch r.code {
        case "not_in_group": Text("Start a group or join one.")
        case "removed": Text("Leave the group on this device, then join again.")
        case "taken_over": Text("If this device was not lost, remove \(device) from the group.")
        case "frozen": Text("Ask the group's owner to restore its rights.")
        case "cert_expired": Text("Bring it home to a trusted device of the group, which renews the certificate.")
        case "cert_ending": Text("Connect it at home to a trusted device of the group before then.")
        case "stopped": Text("The group's owner decides on its alerts.")
        case "sync_off": Text("Turn sync on.")
        case "only_device": Text("Add a phone or a computer.")
        case "away_off": Text("Turn on Everywhere to sync away from home.")
        case "new_network": Text("If this is your home network, mark it as home.")
        case "no_hub": Text("Make a computer at home the base, in its advanced settings.")
        case "tunnel_blocked": Text("This network may block tunnels: turn on Strict networks on the base.")
        case "hub_unreachable": Text("Check that the base is on and online.")
        case "alone": Text("Turn on another device of the group.")
        case "relay_down": Text("Check the internet connection; CBB tries again by itself.")
        case "hub_waiting": Text("Check that the other devices have Everywhere on.")
        case "muted": Text("Unmute it from a trusted device of the group.")
        case "forwarder_down": Text("Devices away from home may not reach it; CBB tries again by itself.")
        case "entries_stale": Text("Update CBB on a computer of the group.")
        case "newer": Text("Update CBB on this device.")
        case "unreached": Text("Let CBB through this computer's firewall.")
        default: nil
        }
    }
}
