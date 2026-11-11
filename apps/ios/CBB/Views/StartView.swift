// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// No group yet: settings and the language at the top, the name, and the
/// ways in: Create a group (this phone becomes its root and adds a device
/// at once), Join a group (this phone shows its QR code and six digits),
/// Join with an invitation (from afar: its QR code, file or text, accepted
/// or declined first), and the recovery key, small (docs/apps.md, Start).
struct StartView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @State private var adding = false
    @State private var restoring = false
    @State private var invited = false
    @State private var settings = false
    @Environment(\.horizontalSizeClass) private var sizeClass
    @AppStorage(LanguageChoice.key) private var language = LanguageChoice.system

    var body: some View {
        // A scroll view as tall as the screen: at the largest text sizes and
        // in the longer languages the screen scrolls instead of squeezing
        // or cutting off its texts.
        GeometryReader { screen in
            ScrollView {
                content
                    .padding(Tokens.spacingLarge)
                    .frame(minHeight: screen.size.height)
            }
            .scrollBounceBehavior(.basedOnSize)
        }
        .task { model.prepare() }
        .sheet(isPresented: $adding) { AddDeviceView() }
        .sheet(isPresented: $restoring) { AddDeviceView(restore: true) }
        .sheet(isPresented: $invited) { InvitationView() }
        .sheet(item: $model.pendingInvite) { p in InvitationAnswerView(invite: p) }
        // Settings cover the whole screen on an iPad, as a sheet does on a
        // phone: a sheet in the middle of an iPad's screen cut its list's
        // last row at its lower edge, in view.
        .sheet(isPresented: Binding(get: { settings && sizeClass != .regular }, set: { settings = $0 })) { settingsPage }
        .fullScreenCover(isPresented: Binding(get: { settings && sizeClass == .regular }, set: { settings = $0 })) { settingsPage }
    }

    private var settingsPage: some View {
        NavigationStack {
            SettingsView()
                .toolbar {
                    ToolbarItem(placement: .confirmationAction) { Button("Done") { settings = false } }
                }
        }
    }

    private var content: some View {
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
                // WCAG's large text, for ReadersUITests' contrast (3:1).
                .accessibilityIdentifier("largeText")
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
            Button { model.startJoining(admin: true) } label: { Text("Join as an admin") }
                .buttonStyle(GlassButtonStyle())
            Button { invited = true } label: { Text("Join with an invitation") }
                .buttonStyle(GlassButtonStyle())
            // Small, yet as large to touch as any button (44 points).
            Button { restoring = true } label: {
                Text("Restore with the recovery key")
                    .multilineTextAlignment(.center)
                    .padding(.vertical, Tokens.spacingSmall)
                    .frame(maxWidth: .infinity, minHeight: 44)
                    .contentShape(Rectangle())
            }
            // Plain, as the other buttons have styles of their own, so that
            // its label is laid out as plain text in every script. Medium,
            // as the other buttons' labels: at the regular weight Xcode's
            // clipped text check flags Hindi's line in any text style, at
            // the medium weight in none.
            .buttonStyle(.plain)
            .font(.footnote.weight(.medium))
            .foregroundStyle(palette.textDim)
        }
    }
}

