// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// Said once, on the first Home: what you copy goes out as the app opens,
/// once iOS lets the app read the clipboard without asking each time.
/// "Allow" asks iOS once, so that Settings, CBB lists "Paste from Other
/// Apps", and opens Settings there; "Later" leaves the system's paste
/// button on Home (docs/apps.md, Home).
struct PasteNote: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette

    var body: some View {
        VStack(spacing: Tokens.spacingLarge) {
            Spacer()
            Image(systemName: "doc.on.clipboard")
                .font(.system(size: 56))
                .foregroundStyle(palette.accent)
                .accessibilityHidden(true)
            Text("Send what you copy by itself")
                .font(.title2.weight(.semibold))
                .multilineTextAlignment(.center)
            Text("Copy something, open CBB, and it goes to your other devices. In Settings, CBB, set Paste from Other Apps to Allow, so that iOS does not ask each time.")
                .multilineTextAlignment(.center)
                .foregroundStyle(palette.textDim)
            Spacer()
            Button { Task { await model.askForClipboard() } } label: { Text("Allow in Settings") }
                .buttonStyle(AccentButtonStyle())
            Button { model.declineClipboard() } label: { Text("Later") }
                .buttonStyle(GlassButtonStyle())
        }
        .padding(Tokens.spacingLarge)
        .background(AppBackground())
        .interactiveDismissDisabled()
    }
}

/// A remote invitation for a device far away (docs/protocol.md, section
/// 12), from Home's +: made on the group's hub. On this phone while it is
/// the hub: the button that opens it, its file to share, and the question
/// about the device that used it, with the fingerprint to compare.
/// Otherwise it says where to make one.
struct InviteSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette

    var body: some View {
        NavigationStack {
            Form {
                if let hub = model.hub, hub.on, hub.status == .registered {
                    Section {
                        if let invite = model.invite {
                            Text("The invitation is open until \(invite.expires.formatted(date: .omitted, time: .shortened)). Share its file only with the person who joins.")
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
                    } footer: {
                        Text("Its owner joins with cbb pair -invite. It works once, for an hour, while this app is open.")
                    }
                    .listRowBackground(palette.surface)
                } else {
                    Section {
                        Text("On the group's hub, run cbb invite and send the file it makes through a channel you trust. On the new device, run cbb pair -invite with that file.")
                    }
                    .listRowBackground(palette.surface)
                }
            }
            .scrollContentBackground(.hidden)
            .background(AppBackground())
            .navigationTitle(Text("Send an invitation"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button { dismiss() } label: { Text("Done") } }
            }
            .alert(Text("Admit \(model.invite?.request?.info.name ?? "")?"), isPresented: Binding(
                get: { model.invite?.request != nil }, set: { if !$0 { model.answer(false) } }
            )) {
                Button { model.answer(true) } label: { Text("Admit") }
                Button(role: .cancel) { model.answer(false) } label: { Text("Not this one") }
            } message: {
                Text("A device (\(model.invite?.request?.info.os ?? "")) used the invitation. Admit it only if the device shows the same fingerprint:\n\n\(model.invite?.request?.fingerprint ?? "")")
            }
        }
    }
}
