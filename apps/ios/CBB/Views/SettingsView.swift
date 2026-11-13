// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import SwiftUI
import TipKit
import UIKit

/// The basic settings first: the look (theme, colour, language) as icons
/// without a heading, notifications, the watch, the recovery key on the
/// root, the switch for the advanced ones, leaving the group, about. The
/// advanced ones: away from home (the hub, moving it to a computer, the
/// relay) and, for admins, the group (copy lifetime, security level). No
/// long texts under the items: a hard one has a tip, shown until closed.
struct SettingsView: View {
    @AppStorage(ThemeChoice.key) private var theme = Tokens.themes[0].name
    @AppStorage(Appearance.key) private var appearance = Appearance.system
    @AppStorage(LanguageChoice.key) private var language = LanguageChoice.system
    @Environment(\.palette) private var palette
    @EnvironmentObject private var model: AppModel
    @State private var switching = false
    @State private var moving: AppModel.Hub.Target?
    @State private var disguiseTo: HubOnPhone.Disguise?
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
    @AppStorage("AdvancedSettings") private var advanced = false

    private var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
    }

    var body: some View {
        Form {
            Section {
                HStack(spacing: Tokens.spacingMedium) {
                    Picker(selection: $appearance) {
                        ForEach(Appearance.allCases) { a in
                            Image(systemName: a.symbol).accessibilityLabel(Text(a.title)).tag(a)
                        }
                    } label: {
                        Text("Theme")
                    }
                    .pickerStyle(.segmented)
                    Menu {
                        Picker(selection: $language) {
                            ForEach(LanguageChoice.allCases) { Text(verbatim: $0.title).tag($0) }
                        } label: { Text("Language") }
                    } label: {
                        Image(systemName: "globe").font(.title3)
                    }
                    .accessibilityLabel(Text("Language"))
                    .accessibilityValue(Text(verbatim: language.title))
                }
                if Measure.on("FixedText") {
                    // The positive control: a text that does not follow the
                    // text size, which every check of it must report.
                    Text(verbatim: "Fixed size text").font(.system(size: 17))
                }
                if Measure.on("NoSwatches") {
                } else if Measure.on("PlainGrid") {
                    PlainThemeSwatches(selection: $theme)
                } else {
                    ThemeSwatches(selection: $theme)
                }
            }
            .listRowBackground(palette.surface)
            if !Measure.on("NoNotifications") { NotificationSettings() }
            if model.devices.contains(where: { $0.isSelf && $0.isRoot }), WatchLink.shared.watchApp {
                watchSection
            }
            if model.isRoot {
                RecoverySection()
            }
            Section {
                Toggle(isOn: $advanced) { Text("Advanced settings") }
            }
            .listRowBackground(palette.surface)
            if advanced {
                Section {
                    NavigationLink { WhyScreen() } label: { Text("Why it does not sync") }
                        .accessibilityIdentifier("why")
                }
                .listRowBackground(palette.surface)
                if let hub = model.hub {
                    hubSection(hub)
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
                if model.isAdmin, model.phase == .home {
                    incomingSection
                }
                if let level = model.keyLevel {
                    keyLevelSection(level)
                }
            }
            if model.phase == .home {
                Section {
                    LeaveButton()
                }
                .listRowBackground(palette.surface)
            }
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
                Link(destination: URL(string: "https://github.com/HunterEwok/cbb")!) {
                    Text("Source code and license (AGPL-3.0)")
                }
            } header: {
                Text("About")
            }
            .listRowBackground(palette.surface)
        }
        .measurePlainList()
        .measureBackground()
        .navigationTitle(Text("Settings"))
        .task {
            if Measure.on("NoRefresh") { return }
            // Where sync away from home stands, as it changes.
            while !Task.isCancelled {
                await model.refresh()
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    /// Which keys may be the group's admins and hubs, on the root phone
    /// (docs/guide/keys.md, "The three levels").
    private func keyLevelSection(_ level: String) -> some View {
        Section {
            Picker(selection: Binding(get: { level }, set: { new in Task { await model.setKeyLevel(new) } })) {
                Text("Proven hardware only").tag(Records.proven)
                Text("Keys in hardware").tag(Records.hardware)
                Text("Keys in files too").tag(Records.levelFiles)
            } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Security level")
                    Text("Root, admins, hubs").font(.caption).foregroundStyle(palette.textDim)
                }
            }
            TipView(SettingTip.securityLevel)
        } header: {
            Text("Group")
        }
        .listRowBackground(palette.surface)
    }

    /// How long a copy from another device stays live after it arrives, on
    /// the root and the admin phones (docs/design.md, "The one button").
    private var incomingSection: some View {
        Section {
            Picker(selection: Binding(get: { model.incomingMS }, set: { new in Task { await model.setIncoming(ms: new) } })) {
                ForEach(Self.incomingChoices(model.incomingMS), id: \.self) { ms in
                    Text(Duration.milliseconds(ms).formatted(.units(allowed: [.hours, .minutes, .seconds], width: .wide))).tag(ms)
                }
            } label: {
                Text("Copy lifetime")
            }
            TipView(SettingTip.copyLifetime)
        } header: {
            Text("Group")
        }
        .listRowBackground(palette.surface)
    }

    /// The choices of the picker, with the group's own when it is none of them.
    static func incomingChoices(_ current: Int64) -> [Int64] {
        let choices: [Int64] = [15_000, 30_000, 60_000, 120_000, 300_000, 600_000]
        return choices.contains(current) ? choices : (choices + [current]).sorted()
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
            TipView(SettingTip.hub)
            hubStatus(hub)
                .foregroundStyle(hub.status == .registered ? palette.accent : palette.textDim)
            // The registration's error underneath, when details are on.
            if let error = hub.error, AppModel.showsErrorDetails {
                Text(verbatim: error).font(.caption).foregroundStyle(palette.textDim)
            }
            if hub.entriesStale {
                Label {
                    Text("The list of the project's entry points is out of date, and the forwarder does not answer on the ways this phone knows. Update CBB on a computer of the group, or import a new list there with cbb global entries import; the group passes it on when this phone meets it.")
                } icon: { Image(systemName: "exclamationmark.triangle") }
                    .font(.footnote)
                    .foregroundStyle(palette.textDim)
            }
            if hub.on {
                Text(hub.home ? "On a home network: devices here connect to this phone."
                     : "This network is not one of the hub's home networks: devices here do not see this phone.")
                    .font(.footnote)
                    .foregroundStyle(palette.textDim)
                if !hub.home {
                    Button { Task { await model.addHomeNetwork() } } label: { Text("This is my home network") }
                }
                Text(hub.forwarder?.isProject == true
                     ? "Reached from afar through the project's forwarder at cbb.tools. To use your own, enter its address and key."
                     : "To go back to the project's forwarder, empty both fields and save.")
                    .font(.footnote)
                    .foregroundStyle(palette.textDim)
                if hub.forwarder?.isProject == true {
                    Link(destination: URL(string: "https://cbb.tools/?p=terms.html")!) { Text("Terms of the project's servers") }
                        .font(.footnote)
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
                .disabled(switching || (forwarderAddress == ownForwarder(hub)?.endpoint ?? "" && forwarderKey == ownForwarder(hub)?.pin ?? ""))
                // Strict networks: AmneziaWG for networks that block VPNs,
                // and VLESS over it for those that let only the web through.
                Toggle(isOn: Binding(get: { hub.disguise != .plain }, set: { disguiseTo = $0 ? .obfuscate : .plain })) {
                    Text("Networks that block VPNs (AmneziaWG)")
                }
                .disabled(switching)
                Toggle(isOn: Binding(get: { hub.disguise == .vless }, set: { disguiseTo = $0 ? .vless : .obfuscate })) {
                    Text("Networks that let only the web through (VLESS)")
                }
                .disabled(switching || hub.disguise == .plain)
                TipView(SettingTip.disguise)
            }
            if let note = model.hubNote {
                Text(verbatim: note).font(.caption).foregroundStyle(palette.danger)
            }
        } header: {
            Text("Away from home: hub")
        }
        .listRowBackground(palette.surface)
        .onAppear {
            forwarderAddress = ownForwarder(hub)?.endpoint ?? ""
            forwarderKey = ownForwarder(hub)?.pin ?? ""
        }
        .alert(Text("Change how the hub's tunnel hides?"), isPresented: Binding(get: { disguiseTo != nil }, set: { if !$0 { disguiseTo = nil } })) {
            Button {
                if let d = disguiseTo {
                    switching = true
                    Task {
                        await model.setHubDisguise(d)
                        switching = false
                    }
                }
            } label: { Text("Change") }
            Button(role: .cancel) {} label: { Text("Cancel") }
        } message: {
            Text("Your devices get the new settings the next time they meet this hub at home; until then they do not reach it away from home.")
        }
    }

    /// The user's own forwarder, which the fields show; the project's
    /// leaves them empty.
    private func ownForwarder(_ hub: AppModel.Hub) -> HubState.Forwarder? {
        hub.forwarder?.isProject == true ? nil : hub.forwarder
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
        }
        .listRowBackground(palette.surface)
    }

    private func awayStatus(_ away: AppModel.Away) -> Text {
        guard away.on else { return Text("Off: the globe on Home turns it on.") }
        switch away.status {
        case .atHome: return Text("At home: syncing directly.")
        case .connecting: return Text("Connecting to the hub through the tunnel…")
        case .connected:
            if let name = away.hub.flatMap({ id in model.devices.first { $0.id == id }?.name }) {
                return Text("Connected to the hub \(name) through the tunnel.")
            }
            return Text("Connected to the hub through the tunnel.")
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
            TipView(SettingTip.relay)
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

/// The ten themes as round swatches, each its background and its accent,
/// the chosen one ringed and ticked.
struct ThemeSwatches: View {
    @Binding var selection: String
    @Environment(\.palette) private var palette
    /// A swatch's least width, growing with the text size so that a
    /// theme's name ("Liquid Glass" and its longer translations) breaks between words,
    /// never inside one.
    @ScaledMetric(relativeTo: .caption2) private var width: CGFloat = 76
    /// The swatch grows with the text, as its name and checkmark do: at the
    /// largest sizes a fixed swatch left the checkmark wider than it.
    @ScaledMetric(relativeTo: .caption2) private var swatchSize: CGFloat = 36

    var body: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: width), spacing: Tokens.spacingSmall)], spacing: Tokens.spacingMedium) {
            ForEach(Tokens.themes, id: \.name) { theme in
                let swatch = palette.dark ? theme.dark : theme.light
                let chosen = theme.name == selection
                Button { selection = theme.name } label: {
                    VStack(spacing: 6) {
                        ThemeSwatch(palette: swatch)
                            .frame(width: swatchSize, height: swatchSize)
                            .overlay {
                                if chosen {
                                    Image(systemName: "checkmark").font(.footnote.weight(.bold)).foregroundStyle(swatch.text)
                                }
                            }
                            .padding(3)
                            .overlay(Circle().stroke(chosen ? palette.accent : palette.line, lineWidth: 2))
                        // A hair space on each side: some names' last letter draws a
                        // little past the text's own width (the Hindi names of Swiss and
                        // Hardware), which the accessibility audit reports as clipped text.
                        (Measure.on("NoHairSpace") ? Text(ThemeChoice.title(theme.name)) : (Text(verbatim: "\u{200A}") + Text(ThemeChoice.title(theme.name)) + Text(verbatim: "\u{200A}")))
                            .font(.caption2).multilineTextAlignment(.center)
                            .foregroundStyle(chosen ? palette.text : palette.textDim)
                    }
                    .frame(maxWidth: .infinity, minHeight: 44)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(Text(ThemeChoice.title(theme.name)))
                .accessibilityAddTraits(chosen ? .isSelected : [])
            }
        }
        .padding(.vertical, Tokens.spacingSmall)
    }
}

/// A measurement of CI's runner, not to be merged: the themes in a plain
/// stack of rows, three to a row, for the lazy grid.
struct PlainThemeSwatches: View {
    @Binding var selection: String
    @Environment(\.palette) private var palette
    /// A swatch's least width, growing with the text size so that a
    /// theme's name ("Liquid Glass" and its longer translations) breaks between words,
    /// never inside one.
    @ScaledMetric(relativeTo: .caption2) private var width: CGFloat = 76
    /// The swatch grows with the text, as its name and checkmark do: at the
    /// largest sizes a fixed swatch left the checkmark wider than it.
    @ScaledMetric(relativeTo: .caption2) private var swatchSize: CGFloat = 36

    var body: some View {
        VStack(spacing: Tokens.spacingMedium) {
            ForEach(0..<(Tokens.themes.count + 2) / 3, id: \.self) { r in
            HStack(alignment: .top, spacing: Tokens.spacingSmall) {
            ForEach(Array(Tokens.themes[(r * 3)..<min(r * 3 + 3, Tokens.themes.count)]), id: \.name) { theme in
                let swatch = palette.dark ? theme.dark : theme.light
                let chosen = theme.name == selection
                Button { selection = theme.name } label: {
                    VStack(spacing: 6) {
                        ThemeSwatch(palette: swatch)
                            .frame(width: swatchSize, height: swatchSize)
                            .overlay {
                                if chosen {
                                    Image(systemName: "checkmark").font(.footnote.weight(.bold)).foregroundStyle(swatch.text)
                                }
                            }
                            .padding(3)
                            .overlay(Circle().stroke(chosen ? palette.accent : palette.line, lineWidth: 2))
                        // A hair space on each side: some names' last letter draws a
                        // little past the text's own width (the Hindi names of Swiss and
                        // Hardware), which the accessibility audit reports as clipped text.
                        (Measure.on("NoHairSpace") ? Text(ThemeChoice.title(theme.name)) : (Text(verbatim: "\u{200A}") + Text(ThemeChoice.title(theme.name)) + Text(verbatim: "\u{200A}")))
                            .font(.caption2).multilineTextAlignment(.center)
                            .foregroundStyle(chosen ? palette.text : palette.textDim)
                    }
                    .frame(maxWidth: .infinity, minHeight: 44)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(Text(ThemeChoice.title(theme.name)))
                .accessibilityAddTraits(chosen ? .isSelected : [])
            }
            }
            }
        }
        .padding(.vertical, Tokens.spacingSmall)
    }
}

/// A measurement of CI's runner, not to be merged: launch arguments a UI
/// test passes to change one thing on the screen.
enum Measure {
    static func on(_ flag: String) -> Bool { ProcessInfo.processInfo.arguments.contains("-CBBMeasure" + flag) }
}

/// A measurement of CI's runner, not to be merged: a UIKit label that
/// follows the text size as UIKit's own do.
struct MeasureLabel: UIViewRepresentable {
    let text: String

    func makeUIView(context: Context) -> UILabel {
        let label = UILabel()
        label.font = .preferredFont(forTextStyle: .footnote)
        label.adjustsFontForContentSizeCategory = true
        label.numberOfLines = 0
        label.text = text
        return label
    }

    func updateUIView(_ label: UILabel, context: Context) { label.text = text }

    func sizeThatFits(_ proposal: ProposedViewSize, uiView: UILabel, context: Context) -> CGSize? {
        uiView.sizeThatFits(CGSize(width: proposal.width ?? .greatestFiniteMagnitude, height: .greatestFiniteMagnitude))
    }
}

extension View {
    @ViewBuilder func measurePlainList() -> some View {
        if Measure.on("PlainList") { listStyle(.plain) } else { self }
    }

    @ViewBuilder func measureBackground() -> some View {
        if Measure.on("NoBackground") { self } else { scrollContentBackground(.hidden).background(AppBackground()) }
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
            if watches.isEmpty { TipView(SettingTip.watch) }
        } header: {
            Text("Apple Watch")
        }
        .listRowBackground(palette.surface)
    }
}

/// A switch for each kind of the group's events (GroupEvent.Kind).
struct NotificationSettings: View {
    @Environment(\.palette) private var palette

    var body: some View {
        if Measure.on("HeaderAsRow") {
            Section {
                Text("Notifications").font(.headline)
                ForEach(GroupEvent.Kind.allCases) { NotifyToggle(kind: $0) }
            }
            .listRowBackground(palette.surface)
        } else {
            Section {
                ForEach(GroupEvent.Kind.allCases) { NotifyToggle(kind: $0) }
            } header: {
                if Measure.on("HeaderNoTextCase") {
                    Text("Notifications").textCase(nil)
                } else if Measure.on("HeaderFont") {
                    Text("Notifications").font(.footnote)
                } else if Measure.on("HeaderCustomFont") {
                    Text("Notifications").font(.custom("Georgia", size: 13, relativeTo: .footnote))
                } else if Measure.on("HeaderUILabel") {
                    MeasureLabel(text: String(localized: "Notifications"))
                } else {
                    Text("Notifications")
                }
            }
            .listRowBackground(palette.surface)
        }
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

extension Appearance {
    /// The theme as an icon in Settings.
    var symbol: String {
        switch self {
        case .system: "circle.lefthalf.filled"
        case .dark: "moon"
        case .light: "sun.max"
        }
    }
}

/// A tip at a hard setting, a couple of sentences, shown from the first
/// launch until the user closes it, then never again (TipKit).
struct SettingTip: Tip {
    let id: String
    let title: Text
    let message: Text?

    static let hub = SettingTip(id: "hub", title: Text("The phone as the hub"),
        message: Text("While the app is open, the other devices at home connect to this phone, and with a forwarder from afar too. The forwarder passes only encrypted packets."))
    static let disguise = SettingTip(id: "disguise", title: Text("Strict networks"),
        message: Text("For networks that block VPNs or let only the web through; the second needs a connection server that takes VLESS."))
    static let relay = SettingTip(id: "relay", title: Text("Blind relay"),
        message: Text("For a group without a hub: the devices meet at a relay. It cannot read the clipboard, but it sees which devices are online and talk to each other."))
    static let copyLifetime = SettingTip(id: "copyLifetime", title: Text("Copy lifetime"),
        message: Text("How long a copy from another device goes into the clipboard after it arrives."))
    static let securityLevel = SettingTip(id: "securityLevel", title: Text("Security level"),
        message: Text("Which devices may be admins and hubs. Keys in hardware never leave the device; a key in a file can be copied."))
    static let watch = SettingTip(id: "watch", title: Text("The watch as an admin"),
        message: Text("It can freeze an admin computer and turn remote paste and quick actions off. Open CBB on the watch first."))
}

/// "Why it does not sync" (docs/apps.md): the core's reasons for this
/// phone, asked again every two seconds while the screen is open.
struct WhyScreen: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @AppStorage("ShowErrorDetails") private var errorDetails = AppModel.showsErrorDetails
    @State private var reasons: [WhyReason]?

    var body: some View {
        Form {
            WhyList(reasons: reasons, details: errorDetails)
                .listRowBackground(palette.surface)
        }
        .scrollContentBackground(.hidden)
        .background(AppBackground())
        .navigationTitle(Text("Why it does not sync"))
        .task {
            while !Task.isCancelled {
                reasons = await model.why()
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }
}
