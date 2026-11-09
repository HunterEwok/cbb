// SPDX-License-Identifier: AGPL-3.0-only

import AppKit
import SwiftUI

/// The app's settings, as the tray app's: the look (light or dark, the
/// colour, the language) as icons in a row, opening at sign-in, the advanced
/// ones behind a switch (remote paste, the recovery key), and about, where
/// seven clicks on the version show the switch for error details. A sheet
/// on the window, as the tray app's dialog, so that they belong to the app
/// rather than float on their own; every row fits its width, a long
/// version cut in the middle.
struct SettingsView: View {
    /// The sheet's width; its rows never ask for more.
    static let width: CGFloat = 460

    @EnvironmentObject private var model: MacModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @AppStorage(AccentChoice.key) private var color = Tokens.colors[0].name
    @AppStorage(Appearance.key) private var appearance = Appearance.system.rawValue
    @AppStorage("ShowErrorDetails") private var errorDetails = MacModel.showsErrorDetails
    @AppStorage("AdvancedSettings") private var advanced = false
    @State private var atLogin = LoginItem.isOn
    @State private var loginError: String?
    @State private var language = AppLanguage.chosen
    @State private var versionClicks = 0
    @State private var recovering = false

    var body: some View {
        VStack(spacing: 0) {
            form
            HStack {
                Spacer()
                Button { dismiss() } label: { Text("Done") }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("settingsDone")
            }
            .padding([.horizontal, .bottom], Tokens.spacingLarge)
        }
        .frame(width: Self.width)
        .fixedSize(horizontal: false, vertical: true)
        .sheet(isPresented: $recovering) { RecoverySheet().environmentObject(model).modifier(Themed()) }
    }

    private var form: some View {
        Form {
            Section {
                HStack(spacing: Tokens.spacingMedium) {
                    Picker(selection: $appearance) {
                        ForEach(Appearance.allCases) { a in
                            Image(systemName: a.macSymbol).accessibilityLabel(Text(a.title)).help(Text(a.title)).tag(a.rawValue)
                        }
                    } label: { Text("Appearance") }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        .fixedSize()
                    Spacer()
                    // The globe beside the menu rather than as its label: a
                    // labelled picker sized to fit takes the form's label
                    // column too, which widened every row past the sheet.
                    Image(systemName: "globe").foregroundStyle(palette.textDim).accessibilityHidden(true)
                    Picker(selection: Binding(get: { language }, set: { language = $0; AppLanguage.choose($0) })) {
                        Text("System language").tag("")
                        ForEach(AppLanguage.available, id: \.self) { l in Text(verbatim: AppLanguage.name(l)).tag(l) }
                    } label: { Text("Language") }
                        .labelsHidden()
                        .frame(maxWidth: 200)
                        .help(Text("Language"))
                }
                HStack(spacing: Tokens.spacingSmall) {
                    ForEach(Tokens.colors, id: \.name) { pair in
                        let p = (Appearance(rawValue: appearance) ?? .system).palette(pair.name, for: palette.dark ? .dark : .light)
                        Circle().fill(p.accent).frame(width: 22, height: 22)
                            .overlay(Circle().stroke(palette.text, lineWidth: pair.name == color ? 2 : 0).padding(-3))
                            .onTapGesture { color = pair.name }
                            .help(Text(AccentChoice.title(pair.name)))
                            .accessibilityLabel(Text(AccentChoice.title(pair.name)))
                            .accessibilityAddTraits(pair.name == color ? [.isButton, .isSelected] : .isButton)
                    }
                }
                if language != AppLanguage.running {
                    LabeledContent {
                        Button { AppLanguage.reopen() } label: { Text("Reopen CBB") }
                    } label: {
                        Text("The new language shows once CBB opens again.").foregroundStyle(palette.textDim)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            Section {
                Toggle(isOn: Binding(get: { atLogin }, set: { on in
                    loginError = LoginItem.set(on)
                    atLogin = LoginItem.isOn
                })) { Text("Open at sign-in") }
                if let loginError {
                    Text(verbatim: loginError).foregroundStyle(palette.danger)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Toggle(isOn: $advanced) { Text("Advanced settings") }
            }
            if advanced {
                Section {
                    LabeledContent {
                        if model.pasteAllowed {
                            Text("Allowed")
                        } else {
                            Button { model.allowPaste() } label: { Text("Allow…") }
                        }
                    } label: {
                        Text("Paste from other devices")
                    }
                    .help(Text("An admin's paste goes where this Mac's keyboard focus is, while this app is open. Turn it on with cbb paste-receive on."))
                    if model.inGroup {
                        Button { recovering = true } label: { Text("Claim the group with its recovery key") }
                    }
                } header: { Text("Advanced") }
            }
            Section {
                // The whole row takes the clicks, so that a short version
                // is as easy to hit as a long one.
                // A build's version is long (a pseudo-version and the
                // system): one line, cut in the middle, the whole of it on
                // hover.
                LabeledContent {
                    let version = model.status?.version ?? "–"
                    Text(verbatim: version).monospaced()
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(Text(verbatim: version))
                } label: { Text("Version") }
                    .contentShape(Rectangle())
                    .onTapGesture { versionClicks += 1 }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("version")
                    .accessibilityAddTraits(.isButton)
                // Seven clicks on the version show the switch, as on the
                // phones; it stays in sight while it is on.
                if versionClicks >= 7 || errorDetails {
                    Toggle(isOn: $errorDetails) { Text("Show error details") }
                        .accessibilityIdentifier("errorDetails")
                }
                Link(destination: URL(string: "https://github.com/HunterEwok/cbb")!) {
                    Text("Source code and license (AGPL-3.0)")
                }
            } header: { Text("About") }
        }
        .formStyle(.grouped)
        .frame(width: Self.width)
    }
}

extension Appearance {
    /// The appearance as an icon in Settings.
    var macSymbol: String {
        switch self {
        case .system: "circle.lefthalf.filled"
        case .dark: "moon"
        case .light: "sun.max"
        }
    }
}

/// The app's language: the system's, or one the user picks in Settings,
/// which macOS applies the next time the app opens (AppleLanguages, as
/// System Settings' per-app language does).
enum AppLanguage {
    static let key = "AppleLanguages"

    /// The languages the app is translated into.
    static var available: [String] {
        Bundle.main.localizations.filter { $0 != "Base" }.sorted()
    }

    /// The language the user picked, "" for the system's.
    static var chosen: String {
        guard UserDefaults.standard.persistentDomain(forName: Bundle.main.bundleIdentifier ?? "")?[key] != nil else { return "" }
        return (UserDefaults.standard.array(forKey: key) as? [String])?.first ?? ""
    }

    /// The language picked when the app opened.
    static let running = chosen

    static func choose(_ language: String) {
        if language.isEmpty {
            UserDefaults.standard.removeObject(forKey: key)
        } else {
            UserDefaults.standard.set([language], forKey: key)
        }
    }

    /// A language by its own name.
    static func name(_ language: String) -> String {
        let locale = Locale(identifier: language)
        let n = locale.localizedString(forLanguageCode: language) ?? language
        return n.prefix(1).uppercased(with: locale) + n.dropFirst()
    }

    /// Opens the app again, in its new language.
    static func reopen() {
        let config = NSWorkspace.OpenConfiguration()
        config.createsNewApplicationInstance = true
        NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: config) { _, _ in
            DispatchQueue.main.async { NSApp.terminate(nil) }
        }
    }
}

/// The menu bar item, as the tray app's menu: where the group stands, the
/// two switches (sync, with a time to turn it off for, and Everywhere), the
/// window, its settings, an update, quit (docs/apps.md, The Mac app).
struct MenuContent: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if let problem = model.problem {
            Text(verbatim: problem)
        } else if model.inGroup {
            Text("\(model.devices.filter { $0.online || $0.isSelf }.count) of \(model.devices.count) online")
        } else {
            Text("This Mac is in no group yet")
        }
        if let message = model.message { Text(verbatim: message) }
        if model.inGroup {
            Divider()
            Toggle(isOn: Binding(get: { !model.syncOff }, set: { on in Task { await model.turnSync(on) } })) {
                model.syncOff ? Text(verbatim: SyncSwitches.syncOffTitle(until: model.syncOffUntil)) : Text("Sync")
            }
            .disabled(model.busy)
            if !model.syncOff {
                Menu {
                    ForEach(PauseTime.allCases) { t in
                        Button { Task { await model.turnSync(false, forMS: t.ms) } } label: { Text(t.title) }
                    }
                } label: { Text("Turn sync off") }
                    .disabled(model.busy)
            }
            Toggle(isOn: Binding(get: { model.awayOn }, set: { on in
                if on {
                    // The window asks first.
                    open()
                    model.askingAway = true
                } else {
                    Task { await model.setAway(false) }
                }
            })) { Text("Everywhere") }
                .disabled(model.busy || (model.syncOff && !model.awayOn))
        }
        Divider()
        Button { open() } label: { Text("Open CBB") }
            .keyboardShortcut("o")
        Button { open(); model.settingsShown = true } label: { Text("Settings…") }
            .keyboardShortcut(",")
        if model.problem == nil, let version = model.status?.update, !version.isEmpty {
            Button { Task { await model.update() } } label: { Text("Update to \(version)") }
                .disabled(model.busy)
        }
        Divider()
        Button { NSApp.terminate(nil) } label: { Text("Quit") }.keyboardShortcut("q")
    }

    private func open() {
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }
}
