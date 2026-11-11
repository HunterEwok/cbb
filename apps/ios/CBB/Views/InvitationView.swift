// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import CBBKit
import SwiftUI
import UniformTypeIdentifiers

/// Join with an invitation (docs/apps.md, Start): the camera for the
/// invitation's QR code, which is the usual way; its file, or its text
/// pasted, when the QR code came another way. What it reads goes to the
/// screen that accepts or declines it.
struct InvitationView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @State private var typed = ""
    @State private var picking = false

    var body: some View {
        NavigationStack {
            VStack(spacing: Tokens.spacingLarge) {
                if QRScanner.available {
                    QRScanner { text in read(text) }
                        .clipShape(RoundedRectangle(cornerRadius: Tokens.radiusCard, style: .continuous))
                        .frame(maxHeight: 360)
                    Text("Point the camera at the invitation's QR code.")
                        .multilineTextAlignment(.center)
                }
                TextField(String(localized: "Invitation text", bundle: .app), text: $typed, axis: .vertical)
                    .font(.system(.body, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .padding(Tokens.spacingMedium)
                    .glassCard()
                HStack {
                    Button { read(typed) } label: { Text("Read") }
                        .buttonStyle(AccentButtonStyle())
                        .disabled(typed.isEmpty)
                    Button { picking = true } label: { Text("Open a file") }
                        .buttonStyle(GlassButtonStyle())
                }
                if let message = model.message {
                    Text(message).foregroundStyle(palette.danger).multilineTextAlignment(.center)
                }
                Spacer()
            }
            .padding(Tokens.spacingLarge)
            .background(AppBackground())
            .navigationTitle(Text("Join with an invitation"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
            .fileImporter(isPresented: $picking, allowedContentTypes: [.data, .plainText]) { result in
                guard case let .success(url) = result else { return }
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                // An invitation's file is one short line; a big file is none.
                guard let d = try? Data(contentsOf: url), d.count <= 4096 else {
                    model.message = String(localized: "This is not a CBB invitation.", bundle: .app)
                    return
                }
                read(String(decoding: d, as: UTF8.self))
            }
            .onAppear { model.message = nil }
        }
    }

    private func read(_ text: String) {
        if model.readInvitation(text) { dismiss() }
    }
}

/// An invitation that waits for the user: the group it joins, its hub and
/// when it expires, with Join and Decline. Declining sends nothing.
struct InvitationAnswerView: View {
    let invite: AppModel.PendingInvite
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette

    var body: some View {
        NavigationStack {
            VStack(spacing: Tokens.spacingLarge) {
                Spacer()
                Image(systemName: "envelope.open")
                    .font(.system(size: 48))
                    .foregroundStyle(palette.accent)
                Text("You are invited to a group")
                    .font(.system(.title2, design: .monospaced).weight(.bold))
                    .multilineTextAlignment(.center)
                VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
                    LabeledContent { Text(verbatim: invite.invitation.group).font(.system(.body, design: .monospaced)) } label: { Text("Group") }
                    LabeledContent { Text(verbatim: String(invite.invitation.hub.prefix(12))).font(.system(.body, design: .monospaced)) } label: { Text("Hub") }
                    LabeledContent {
                        Text(Date(timeIntervalSince1970: TimeInterval(invite.invitation.expires)), style: .relative)
                    } label: { Text("Expires in") }
                }
                .padding(Tokens.spacingMedium)
                .glassCard()
                Text("Join only if you asked for this invitation. Whoever made it admits this phone once they see the words it shows.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(palette.textDim)
                Spacer()
                Button { model.acceptInvitation() } label: { Text("Join") }
                    .buttonStyle(AccentButtonStyle())
                Button { model.declineInvitation() } label: { Text("Decline") }
                    .buttonStyle(GlassButtonStyle())
            }
            .padding(Tokens.spacingLarge)
            .background(AppBackground())
        }
        .interactiveDismissDisabled()
    }
}
