// SPDX-License-Identifier: AGPL-3.0-only

import ClipboardBridgeKit
import SwiftUI
import UIKit

/// Settings' recovery key, on the root phone (docs/protocol.md, section 10,
/// "The recovery key"): whether the group has one and since when, making a
/// new one, which shows its sheet once, and removing it.
struct RecoverySection: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    /// The sheet just made, while it shows; nothing keeps it after.
    @State private var sheet: Core.RecoverySheet?
    @State private var askingReplace = false
    @State private var askingRemove = false

    var body: some View {
        Section {
            if let made = model.recoveryMade {
                Text("Made on \(made.formatted(date: .long, time: .omitted)).")
                Button { askingReplace = true } label: { Text("Make a new recovery key") }
                Button(role: .destructive) { askingRemove = true } label: { Text("Remove the recovery key") }
            } else {
                Text("None yet.").foregroundStyle(palette.textDim)
                Button { make() } label: { Text("Make a recovery key") }
            }
        } header: {
            Text("Recovery key")
        } footer: {
            Text("A sheet to print and keep away from your phones. If every phone with this group is lost, a computer of the group or a new phone takes the group back with it, after the group's wait.")
        }
        .listRowBackground(palette.surface)
        .alert(Text("Make a new recovery key?"), isPresented: $askingReplace) {
            Button { make() } label: { Text("Make a new one") }
            Button(role: .cancel) {} label: { Text("Cancel") }
        } message: {
            Text("The sheet printed for the old key stops working.")
        }
        .alert(Text("Remove the recovery key?"), isPresented: $askingRemove) {
            Button(role: .destructive) { Task { await model.removeRecovery() } } label: { Text("Remove") }
            Button(role: .cancel) {} label: { Text("Cancel") }
        } message: {
            Text("The sheet printed for it stops working. Without a recovery key, losing every phone with this group loses the group.")
        }
        .fullScreenCover(item: Binding(get: { sheet.map(Shown.init) }, set: { if $0 == nil { sheet = nil } })) { shown in
            RecoverySheetView(sheet: shown.sheet, made: Date()) { sheet = nil }
        }
    }

    private func make() {
        Task { sheet = await model.makeRecovery() }
    }

    private struct Shown: Identifiable {
        let sheet: Core.RecoverySheet
        var id: String { sheet.qr }
    }
}

/// The recovery sheet, shown once: its QR code and text, printing it or
/// saving it as a PDF, and closing it, after which the phone has no copy.
struct RecoverySheetView: View {
    let sheet: Core.RecoverySheet
    let made: Date
    let done: () -> Void
    @Environment(\.palette) private var palette
    @State private var pdf: URL?
    @State private var askingDone = false
    @State private var failure: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: Tokens.spacingLarge) {
                    Text("Print this sheet or save it as a PDF now. It shows only this once.")
                        .multilineTextAlignment(.center)
                        .foregroundStyle(palette.textDim)
                    RecoveryPage(sheet: sheet, made: made)
                        .clipShape(RoundedRectangle(cornerRadius: Tokens.radiusCard, style: .continuous))
                        .privacySensitive()
                    Button { print() } label: { Label { Text("Print") } icon: { Image(systemName: "printer") } }
                        .buttonStyle(GlassButtonStyle())
                    if let pdf {
                        ShareLink(item: pdf) { Label { Text("Save as PDF") } icon: { Image(systemName: "square.and.arrow.down") } }
                            .buttonStyle(GlassButtonStyle())
                    }
                    if let failure {
                        Text(failure).foregroundStyle(palette.danger).multilineTextAlignment(.center)
                    }
                }
                .padding(Tokens.spacingLarge)
            }
            .background(AppBackground())
            .navigationTitle(Text("Recovery key"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button { askingDone = true } label: { Text("Done") }
                }
            }
            .alert(Text("Did you keep the sheet?"), isPresented: $askingDone) {
                Button { close() } label: { Text("I kept it") }
                Button(role: .cancel) {} label: { Text("Back") }
            } message: {
                Text("This phone forgets the key now. To get a sheet again, make a new recovery key.")
            }
        }
        .interactiveDismissDisabled()
        .task {
            do {
                pdf = try RecoveryPage.pdf(sheet: sheet, made: made)
            } catch {
                failure = AppModel.describe(error, summary: String(localized: "Could not make the PDF.", bundle: .app))
            }
        }
    }

    private func print() {
        guard let pdf else { return }
        let c = UIPrintInteractionController.shared
        let info = UIPrintInfo.printInfo()
        info.outputType = .grayscale
        info.jobName = String(localized: "Clipboard Bridge recovery key", bundle: .app)
        c.printInfo = info
        c.printingItem = pdf
        c.present(animated: true)
    }

    /// Forgets the key: the PDF goes, and the sheet with the view.
    private func close() {
        if let pdf { try? FileManager.default.removeItem(at: pdf) }
        pdf = nil
        done()
    }
}

/// The page that is printed: black on white, the QR code, the key in groups
/// of four, the date and what to do with it.
struct RecoveryPage: View {
    let sheet: Core.RecoverySheet
    let made: Date

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Clipboard Bridge recovery key").font(.title2.weight(.bold))
            Text("Made on \(made.formatted(date: .long, time: .omitted)).")
            HStack {
                Spacer()
                if let image = QRImage.make(sheet.qr) {
                    Image(uiImage: image).interpolation(.none).resizable().scaledToFit().frame(maxWidth: 260)
                        .accessibilityLabel(Text("QR code of the recovery key"))
                }
                Spacer()
            }
            Text(rows).font(.system(.body, design: .monospaced).weight(.semibold)).textSelection(.disabled)
            Text("Keep this sheet somewhere safe, away from your phones. Anyone who has it can take your group over, after the group's wait, unless the root phone cancels it.")
            Text("To take the group back: on a new phone, choose Restore with a recovery key and scan the code; or on a computer of the group, run cbb recovery and type the key.")
        }
        .foregroundStyle(.black)
        .padding(24)
        .frame(maxWidth: 520, alignment: .leading)
        .background(Color.white)
    }

    /// The key's groups four to a line.
    private var rows: String {
        let groups = sheet.text.split(separator: "-")
        return stride(from: 0, to: groups.count, by: 4).map { groups[$0..<min($0 + 4, groups.count)].joined(separator: " ") }
            .joined(separator: "\n")
    }

    /// The page as a PDF of A4 in the temporary folder, which the caller
    /// deletes when the sheet closes.
    @MainActor static func pdf(sheet: Core.RecoverySheet, made: Date) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("Clipboard Bridge recovery key.pdf")
        try? FileManager.default.removeItem(at: url)
        let renderer = ImageRenderer(content: RecoveryPage(sheet: sheet, made: made).frame(width: 520))
        var box = CGRect(x: 0, y: 0, width: 595, height: 842)
        guard let out = CGContext(url as CFURL, mediaBox: &box, nil) else { throw CocoaError(.fileWriteUnknown) }
        renderer.render { size, draw in
            out.beginPDFPage(nil)
            // Centred across, from the top.
            out.translateBy(x: (box.width - size.width) / 2, y: box.height - size.height - 36)
            draw(out)
            out.endPDFPage()
        }
        out.closePDF()
        try (url as NSURL).setResourceValue(true, forKey: .isExcludedFromBackupKey)
        return url
    }
}
