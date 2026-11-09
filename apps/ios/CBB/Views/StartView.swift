// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// No group yet: settings and the language at the top, the name, and the
/// three ways in: Create a group (this phone becomes its root and adds a
/// device at once), Join a group (this phone shows its QR code and six
/// digits), and the recovery key, small (docs/apps.md, Start).
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
                Menu {
                    Picker(selection: $language) {
                        ForEach(LanguageChoice.allCases) { Text(verbatim: $0.title).tag($0) }
                    } label: { Text("Language") }
                } label: {
                    Image(systemName: "globe")
                        .font(.title3)
                        .foregroundStyle(palette.text)
                        .glassCircle()
                }
                .accessibilityLabel(Text("Language"))
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
            Spacer()
            Button { adding = true } label: { Text("Create a group") }
                .buttonStyle(AccentButtonStyle())
            Button { model.startJoining() } label: { Text("Join a group") }
                .buttonStyle(GlassButtonStyle())
            Button { restoring = true } label: { Text("Restore with the recovery key") }
                .font(.footnote)
                .foregroundStyle(palette.textDim)
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

