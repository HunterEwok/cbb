// SPDX-License-Identifier: AGPL-3.0-only

import AppKit
import SwiftUI

/// How a device joins: pairing runs in Terminal for now, so the sheet
/// gives the commands to copy.
struct AddDeviceSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
            Text("Add a device").font(.title2.weight(.semibold))
            step("1", Text("On the new computer, run:"), command: "cbb pair")
            step("2", Text("In a group of the phone, scan the QR code it shows with the phone app. In a group of computers, run this on this Mac or another admin and type the code it shows on the new computer:"), command: "sudo cbb pair")
            Text("A phone joins from the start screen of its app.").foregroundStyle(palette.textDim)
            HStack {
                Spacer()
                Button { dismiss() } label: { Text("Done") }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(Tokens.spacingLarge)
        .frame(width: 480)
        .background(AppBackground())
    }

    private func step(_ n: String, _ text: Text, command: String) -> some View {
        HStack(alignment: .top, spacing: Tokens.spacingMedium) {
            Text(verbatim: n).font(.headline).foregroundStyle(palette.onAccent).frame(width: 26, height: 26).background(palette.accent, in: Circle())
            VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
                text.fixedSize(horizontal: false, vertical: true)
                HStack {
                    Text(verbatim: command).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                    Spacer()
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(command, forType: .string)
                    } label: { Image(systemName: "doc.on.doc") }
                        .buttonStyle(.borderless)
                        .help(Text("Copy"))
                }
                .padding(Tokens.spacingSmall)
                .glassTile(cornerRadius: Tokens.radiusCard)
            }
        }
    }
}
