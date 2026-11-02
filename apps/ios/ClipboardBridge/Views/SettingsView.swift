// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI
import UIKit

/// Colour and appearance, language, sync away from home, notifications,
/// about.
struct SettingsView: View {
    @AppStorage(AccentChoice.key) private var color = Tokens.colors[0].name
    @AppStorage(Appearance.key) private var appearance = Appearance.system
    @AppStorage(LanguageChoice.key) private var language = LanguageChoice.system
    @Environment(\.palette) private var palette
    @EnvironmentObject private var model: AppModel
    @State private var switching = false
    @State private var moving: AppModel.Hub.Target?
    @State private var forwarderAddress = ""
    @State private var forwarderKey = ""
    @State private var relayAddress = ""
    @State private var relayKey = ""
    /// Whether the question about what a relay learns is showing.
    @State private var askingRelay = false
    /// Taps on the version; seven show the error details switch, as
    /// Android's build number shows its developer options.
    @State private var versionTaps = 0
    @AppStorage("ShowErrorDetails") private var errorDetails = AppModel.showsErrorDetails
    @AppStorage("ShowErrorDetailsSwitch") private var detailsSwitch = UserDefaults.standard.bool(forKey: "ShowErrorDetailsSwitch")

    private var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
    }

    var body: some View {
        Form {
            Section {
                Picker(selection: $appearance) {
                    ForEach(Appearance.allCases) { Text($0.title).tag($0) }
                } label: {
                    Text("Theme")
                }
                .pickerStyle(.segmented)
                ColorSwatches(selection: $color)
            } header: {
                Text("Colour")
            }
            .listRowBackground(palette.surface)
            Picker(selection: $language) {
                ForEach(LanguageChoice.allCases) { Text(verbatim: $0.title).tag($0) }
            } label: {
                Text("Language")
            }
            .listRowBackground(palette.surface)
            if let hub = model.hub {
                hubSection(hub)
                if hub.on, hub.status == .registered {
                    inviteSection
                }
                if !hub.computers.isEmpty {
                    moveHubSection(hub)
                }
            }
            if let away = model.away, model.hub?.on != true {
                awaySection(away)
            }
            if let relay = model.blindRelay {
                relaySection(relay)
            }
            if model.devices.contains(where: { $0.isSelf && $0.isRoot }), WatchLink.shared.watchApp {
                watchSection
            }
            NotificationSettings()
            Section {
                LabeledContent {
                    Text(version).font(.system(.body, design: .monospaced))
                } label: {
                    Text("Version")
                }
                .contentShape(Rectangle())
                .onTapGesture {
                    versionTaps += 1
                    if versionTaps >= 7 { detailsSwitch = true }
                }
                if detailsSwitch {
                    Toggle(isOn: $errorDetails) {
                        Text("Show error details")
                    }
                    // The share extension reads it from the app group.
                    .onChange(of: errorDetails, initial: true) { _, on in Shared.defaults.set(on, forKey: "ShowErrorDetails") }
                }
                Link(destination: URL(string: "https://github.com/HunterEwok/clipboardbridge")!) {
                    Text("Source code and license (AGPL-3.0)")
                }
            } header: {
                Text("About")
            } footer: {
                if detailsSwitch {
                    Text("Error messages show the error underneath them, to find out what failed. Tap the version seven times to see this switch.")
                }
            }
            .listRowBackground(palette.surface)
        }
        .scrollContentBackground(.hidden)
        .background(AppBackground())
        .navigationTitle(Text("Settings"))
        .task {
            // Where sync away from home stands, as it changes.
            while !Task.isCancelled {
                await model.refresh()
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    /// Moving the hub to a computer (docs/design.md, "Moving the hub to a
    /// computer"): the suggestion of one that is always on, once, and a
    /// button for each computer the hub can move to, each asking first.
    private func moveHubSection(_ hub: AppModel.Hub) -> some View {
        Section {
            if hub.forwarder == nil {
                Text("Save a forwarder above first: away from home, the devices reach the new hub through it.")
                    .foregroundStyle(palette.textDim)
            }
            if let s = hub.suggested {
                Text("\(s.name) is always on. Make it the hub, so that sync away from home works while this app is closed?")
                Button { moving = s } label: { Text("Make it the hub") }
                    .disabled(hub.forwarder == nil)
                Button { Task { await model.keepPhoneHub() } } label: { Text("Keep this phone") }
            }
            ForEach(hub.computers.filter { $0 != hub.suggested }) { c in
                Button { moving = c } label: { Text("Make \(c.name) the hub") }
                    .disabled(hub.forwarder == nil)
            }
        } header: {
            Text("Move the hub to a computer")
        } footer: {
            Text("A computer that is always on keeps sync away from home working while this app is closed. The devices that reach this phone from afar move with it.")
        }
        .listRowBackground(palette.surface)
        .alert(Text("Make \(moving?.name ?? "") the hub?"), isPresented: Binding(
            get: { moving != nil }, set: { if !$0 { moving = nil } }
        )) {
            Button {
                if let c = moving {
                    Task { await model.moveHub(to: c.id) }
                }
                moving = nil
            } label: { Text("Move the hub") }
            Button(role: .cancel) { moving = nil } label: { Text("Cancel") }
        } message: {
            Text("The devices that reach this phone from afar move to \(moving?.name ?? ""), and this phone becomes its client. Sync away from home must be on there (cbb global on).")
        }
    }

    /// A remote invitation for a device far away (docs/protocol.md,
    /// section 12): the button that opens it, then its file to share, and
    /// the question about the device that used it, with the fingerprint to
    /// compare.
    private var inviteSection: some View {
        Section {
            if let invite = model.invite {
                Text("The invitation is open until \(invite.expires.formatted(date: .omitted, time: .shortened)). Share its file only with the person who joins: anyone who has it can ask to join.")
                    .font(.footnote)
                    .foregroundStyle(palette.textDim)
                ShareLink(item: invite.file) { Text("Share the invitation") }
                Button(role: .destructive) { model.cancelInvite() } label: { Text("Cancel the invitation") }
            } else {
                Button { Task { await model.openInvite() } } label: { Text("Make an invitation") }
            }
            if let note = model.inviteNote {
                Text(verbatim: note).font(.caption).foregroundStyle(palette.textDim)
            }
        } header: {
            Text("Invite a device from afar")
        } footer: {
            Text("For a device that is not on your network, such as a parent's computer: share the invitation file with its owner, who joins with cbb pair -invite. It works once, for an hour, while this app is open.")
        }
        .listRowBackground(palette.surface)
        .alert(Text("Admit \(model.invite?.request?.info.name ?? "")?"), isPresented: Binding(
            get: { model.invite?.request != nil }, set: { if !$0 { model.answer(false) } }
        )) {
            Button { model.answer(true) } label: { Text("Admit") }
            Button(role: .cancel) { model.answer(false) } label: { Text("Not this one") }
        } message: {
            Text("A device (\(model.invite?.request?.info.os ?? "")) used the invitation. Admit it only if the device shows the same fingerprint:\n\n\(model.invite?.request?.fingerprint ?? "")")
        }
    }

    /// The phone as the group's hub: the switch, where it stands, the
    /// forwarder and the home networks.
    private func hubSection(_ hub: AppModel.Hub) -> some View {
        Section {
            Toggle(isOn: Binding(get: { hub.on }, set: { on in
                switching = true
                Task {
                    await model.setHub(on)
                    switching = false
                }
            })) {
                Text("This phone is the group's hub")
            }
            .disabled(switching)
            hubStatus(hub)
                .foregroundStyle(hub.status == .registered ? palette.accent : palette.textDim)
            // The registration's error underneath, when details are on.
            if let error = hub.error, AppModel.showsErrorDetails {
                Text(verbatim: error).font(.caption).foregroundStyle(palette.textDim)
            }
            if hub.on {
                Text(hub.home ? "On a home network: devices here connect to this phone."
                     : "This network is not one of the hub's home networks: devices here do not see this phone.")
                    .font(.footnote)
                    .foregroundStyle(palette.textDim)
                if !hub.home {
                    Button { Task { await model.addHomeNetwork() } } label: { Text("This is my home network") }
                }
                TextField(text: $forwarderAddress) { Text("Forwarder address, such as 198.51.100.9:8764") }
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.numbersAndPunctuation)
                TextField(text: $forwarderKey) { Text("Forwarder key, 44 characters") }
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.system(.body, design: .monospaced))
                Button {
                    switching = true
                    Task {
                        await model.setForwarder(address: forwarderAddress, pin: forwarderKey)
                        switching = false
                    }
                } label: {
                    Text("Save the forwarder")
                }
                .disabled(switching || (forwarderAddress == (hub.forwarder?.endpoint ?? "") && forwarderKey == (hub.forwarder?.pin ?? "")))
            }
            if let note = model.hubNote {
                Text(verbatim: note).font(.caption).foregroundStyle(palette.danger)
            }
        } header: {
            Text("This phone as the hub")
        } footer: {
            Text("While the app is open, this phone is the hub of a group without a computer: the other phones, TVs and lite members on the home network connect to it, and with a forwarder they reach it from afar too. The forwarder only passes encrypted packets; it learns the group's tag, this phone's tunnel key and the addresses, never what is copied. A computer that is always on is the better hub; until then this phone does it.")
        }
        .listRowBackground(palette.surface)
        .onAppear {
            forwarderAddress = hub.forwarder?.endpoint ?? ""
            forwarderKey = hub.forwarder?.pin ?? ""
        }
    }

    private func hubStatus(_ hub: AppModel.Hub) -> Text {
        switch hub.status {
        case .off: return Text("Off: this phone is no hub.")
        case .paused: return Text("Waiting for the app: the hub works while the app is open.")
        case .homeOnly: return Text("The hub at home only: add a forwarder for sync away from home.")
        case .registering: return Text("Registering with the forwarder…")
        case .registered: return Text("Registered with the forwarder: devices away from home reach this phone.")
        case .failed: return Text("The forwarder does not take this phone. Check its address and key.")
        }
    }

    /// Sync away from home: the switch, where it stands, and what it does.
    private func awaySection(_ away: AppModel.Away) -> some View {
        Section {
            Toggle(isOn: Binding(get: { away.on }, set: { on in
                switching = true
                Task {
                    await model.setAway(on)
                    switching = false
                }
            })) {
                Text("Sync away from home")
            }
            .disabled(switching)
            awayStatus(away)
                .foregroundStyle(away.on && away.status == .connected ? palette.accent : palette.textDim)
            if let error = away.error {
                Text(verbatim: error).font(.caption).foregroundStyle(palette.danger)
            }
            if let note = model.awayNote {
                Text(verbatim: note).font(.caption).foregroundStyle(palette.danger)
            }
        } header: {
            Text("Away from home")
        } footer: {
            Text("When the phone is not on the home network, it syncs through the WireGuard tunnel of your own hub, a computer of the group set up with cbb global hub; its port is reachable from the internet, but only through WireGuard with the group's keys. The hub answers this phone the next time it connects at home. Nothing goes anywhere else, and without the tunnel there is no connection. Turning it off forgets this phone's tunnel key.")
        }
        .listRowBackground(palette.surface)
    }

    private func awayStatus(_ away: AppModel.Away) -> Text {
        guard away.on else { return Text("Off") }
        switch away.status {
        case .atHome: return Text("At home: syncing directly.")
        case .connecting: return Text("Connecting to the hub through the tunnel…")
        case .connected: return Text("Connected to the hub through the tunnel.")
        case .off, .waitingForHub: return Text("Waiting for the hub: open the app at home once, near a computer of the group.")
        }
    }
}

extension SettingsView {
    /// The blind relay (docs/design.md, "Blind relay"): where the phone
    /// stands there, its address and key, and what it learns, which the
    /// user reads and accepts before the phone meets the group there.
    func relaySection(_ relay: AppModel.BlindRelay) -> some View {
        Section {
            relayStatus(relay)
                .foregroundStyle(relay.status == .connected ? palette.accent : palette.textDim)
            // The relay's error underneath, when details are on.
            if let error = relay.error, AppModel.showsErrorDetails {
                Text(verbatim: error).font(.caption).foregroundStyle(palette.textDim)
            }
            TextField(text: $relayAddress) { Text("Relay address, such as 198.51.100.9:8764") }
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.numbersAndPunctuation)
            TextField(text: $relayKey) { Text("Relay key, 44 characters") }
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .font(.system(.body, design: .monospaced))
            let empty = relayAddress.trimmingCharacters(in: .whitespaces).isEmpty && relayKey.trimmingCharacters(in: .whitespaces).isEmpty
            Button {
                if empty {
                    saveRelay()
                } else {
                    askingRelay = true
                }
            } label: {
                Text(empty ? "Leave the relay" : "Meet at this relay")
            }
            .disabled(switching || (relayAddress == (relay.relay?.endpoint ?? "") && relayKey == (relay.relay?.pin ?? "")))
            if let note = model.relayNote {
                Text(verbatim: note).font(.caption).foregroundStyle(palette.danger)
            }
        } header: {
            Text("Blind relay")
        } footer: {
            Text("For a group without a hub of its own: the devices meet at a relay, such as one set up with cbb relay, while this app is open. The clipboard stays encrypted between the devices, but the relay learns which of them are online and their addresses, and which talk to each other, when and how much. Leave both fields empty to stop.")
        }
        .listRowBackground(palette.surface)
        .onAppear {
            relayAddress = relay.relay?.endpoint ?? ""
            relayKey = relay.relay?.pin ?? ""
        }
        .alert(Text("Meet at this relay?"), isPresented: $askingRelay) {
            Button { saveRelay() } label: { Text("Meet at this relay") }
            Button(role: .cancel) {} label: { Text("Cancel") }
        } message: {
            Text("The clipboard stays encrypted end to end between the devices: the relay cannot read it or pose as a device. It does learn, while the devices use it, which devices of the group are online and their internet addresses, and which of them talk to each other, when and how much they send. A hub of the group's own lets none of this out. Use a relay you run yourself, or one whose operator you trust with this.")
        }
    }

    private func saveRelay() {
        switching = true
        Task {
            await model.setRelay(address: relayAddress, pin: relayKey)
            switching = false
        }
    }

    private func relayStatus(_ relay: AppModel.BlindRelay) -> Text {
        switch relay.status {
        case .off: return Text("Off: this phone meets nobody at a relay.")
        case .paused: return Text("Waiting for the app: the relay works while the app is open.")
        case .connecting: return Text("Connecting to the relay…")
        case .connected:
            return relay.online == 0 ? Text("At the relay: no other device of the group is there now.")
                : Text("At the relay with \(relay.online) devices of the group.")
        case .failed: return Text("The relay does not take this phone. Check its address and key.")
        }
    }
}

/// The ten colours as round swatches, the chosen one ringed and ticked.
struct ColorSwatches: View {
    @Binding var selection: String
    @Environment(\.palette) private var palette

    var body: some View {
        LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: Tokens.spacingSmall), count: 5), spacing: Tokens.spacingMedium) {
            ForEach(Tokens.colors, id: \.name) { pair in
                let swatch = palette.dark ? pair.dark : pair.light
                let chosen = pair.name == selection
                Button { selection = pair.name } label: {
                    VStack(spacing: 6) {
                        Circle()
                            .fill(swatch.accent)
                            .frame(width: 36, height: 36)
                            .overlay {
                                if chosen {
                                    Image(systemName: "checkmark").font(.footnote.weight(.bold)).foregroundStyle(swatch.onAccent)
                                }
                            }
                            .padding(3)
                            .overlay(Circle().stroke(chosen ? swatch.accent : .clear, lineWidth: 2))
                        Text(AccentChoice.title(pair.name)).font(.caption2).lineLimit(1).minimumScaleFactor(0.8)
                            .foregroundStyle(chosen ? palette.text : palette.textDim)
                    }
                    .frame(maxWidth: .infinity, minHeight: 44)
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(chosen ? .isSelected : [])
            }
        }
        .padding(.vertical, Tokens.spacingSmall)
    }
}

extension SettingsView {
    /// The root phone makes its paired watch an admin, for the emergency
    /// actions (docs/protocol.md, section 10, "Watches").
    @ViewBuilder var watchSection: some View {
        let watches = model.devices.filter { $0.role == "watch" }
        Section {
            ForEach(watches) { w in
                Text(verbatim: w.name)
            }
            if watches.isEmpty {
                Button {
                    Task {
                        switching = true
                        await model.addWatch()
                        switching = false
                    }
                } label: {
                    Text("Make the watch an admin")
                }
                .disabled(switching)
            }
        } header: {
            Text("Apple Watch")
        } footer: {
            if watches.isEmpty {
                Text("With a key of its own, the watch can freeze an admin computer, remove a device that is no admin, and turn remote paste, quick actions and sync away from home off. It needs a passcode and wrist detection. Open Clipboard Bridge on the watch first.")
            } else {
                Text("To give a new watch the key, remove this one from the devices first.")
            }
        }
        .listRowBackground(palette.surface)
    }
}

/// A switch for each kind of the group's events (GroupEvent.Kind).
struct NotificationSettings: View {
    @Environment(\.palette) private var palette

    var body: some View {
        Section {
            ForEach(GroupEvent.Kind.allCases) { NotifyToggle(kind: $0) }
        } header: {
            Text("Notifications")
        } footer: {
            // An iPad pairs with no watch.
            if UIDevice.current.userInterfaceIdiom == .pad {
                Text("The app notifies of these while it runs. It hears of an event when it next syncs with the group.")
            } else {
                Text("The app notifies of these while it runs, and a paired Apple Watch shows them too. It hears of an event when it next syncs with the group.")
            }
        }
        .listRowBackground(palette.surface)
    }
}

private struct NotifyToggle: View {
    let kind: GroupEvent.Kind
    @AppStorage private var on: Bool

    init(kind: GroupEvent.Kind) {
        self.kind = kind
        _on = AppStorage(wrappedValue: true, kind.key)
    }

    var body: some View {
        Toggle(isOn: $on) { title }
    }

    private var title: Text {
        switch kind {
        case .devices: Text("A device joined or was removed")
        case .admins: Text("A device became an admin")
        case .frozen: Text("A device was frozen or unfrozen")
        case .takeover: Text("The group was taken over")
        case .hub: Text("The hub does not answer away from home")
        }
    }
}
