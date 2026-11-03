// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// No group yet: what CBB does, the note that this phone is ready
/// (once), connecting a device, and joining the group of a phone that
/// already uses CBB. Colour and language are a tap away.
struct StartView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @State private var adding = false
    @State private var restoring = false
    @State private var settings = false
    @AppStorage(LanguageChoice.key) private var language = LanguageChoice.system

    var body: some View {
        VStack(spacing: Tokens.spacingLarge) {
            HStack {
                if LanguageChoice.offeredOnStart(preferred: Locale.preferredLanguages, localizations: Bundle.main.localizations) {
                    // Here the system's language has no translation and the
                    // app shows English, so English is the one chosen.
                    Picker(selection: Binding { language == .system ? .en : language } set: { language = $0 }) {
                        ForEach(LanguageChoice.translations) { Text(verbatim: $0.title).tag($0) }
                    } label: {
                        Text("Language")
                    }
                    .pickerStyle(.menu)
                    .glassCard(cornerRadius: 22)
                }
                Spacer()
                Button { settings = true } label: {
                    Image(systemName: "gearshape")
                        .font(.title3)
                        .foregroundStyle(palette.text)
                        .glassCircle()
                }
                .accessibilityLabel(Text("Settings"))
            }
            Spacer()
            Text("CBB")
                .font(.system(.largeTitle, design: .monospaced).weight(.bold))
                .foregroundStyle(palette.accent)
            Text(verbatim: "Copy Beyond Borders")
                .font(.system(.headline, design: .monospaced))
                .foregroundStyle(palette.accent)
            Text("One clipboard for this phone and your computers.")
                .multilineTextAlignment(.center)
                .foregroundStyle(palette.textDim)
            if model.welcome {
                WelcomeCard()
            }
            Spacer()
            VStack(spacing: Tokens.spacingSmall) {
                Button("Connect a new device") {
                    model.dismissWelcome()
                    adding = true
                }
                .buttonStyle(AccentButtonStyle())
                Text("On a computer, run cbb pair and scan the code it shows.")
                    .font(.footnote)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(palette.textDim)
            }
            Button("I already use CBB on another phone") { model.startJoining() }
                .buttonStyle(GlassButtonStyle())
            Button("My group was made on a computer") { model.startJoiningComputer() }
                .buttonStyle(GlassButtonStyle())
            Button("I have the group's recovery sheet") {
                model.dismissWelcome()
                restoring = true
            }
            .buttonStyle(GlassButtonStyle())
        }
        .padding(Tokens.spacingLarge)
        .task { model.prepare() }
        .sheet(isPresented: $adding) { AddDeviceView() }
        .sheet(isPresented: $restoring) { AddDeviceView(restore: true) }
        .sheet(isPresented: $settings) {
            NavigationStack {
                SettingsView()
                    .toolbar {
                        ToolbarItem(placement: .confirmationAction) { Button("Done") { settings = false } }
                    }
            }
        }
    }
}

/// Said once, at the first launch: this phone has its own key now, and the
/// next step is to connect a device.
struct WelcomeCard: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
            HStack(alignment: .firstTextBaseline) {
                Label {
                    Text("This phone is ready").font(.headline)
                } icon: {
                    Image(systemName: "checkmark.shield.fill").foregroundStyle(palette.accent)
                }
                Spacer()
                Button { model.dismissWelcome() } label: {
                    Image(systemName: "xmark").foregroundStyle(palette.textDim)
                }
                .accessibilityLabel(Text("Close"))
            }
            Text("It made its own secret key, which never leaves it and lets your devices recognise this phone. Now connect a device: tap Connect a new device and scan the QR code it shows.")
                .font(.subheadline)
                .foregroundStyle(palette.textDim)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(Tokens.spacingMedium)
        .glassCard()
    }
}
