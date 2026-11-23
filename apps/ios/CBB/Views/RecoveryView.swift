// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// Settings' recovery key, on the root phone (docs/protocol.md, section 10,
/// "The recovery key"): on a group of 0.6 the key is part of the group and
/// its sheet is shown once, when the group is made, so Settings only says so.
struct RecoverySection: View {
    @Environment(\.palette) private var palette

    var body: some View {
        Section {
            Text("Made with the group, and its sheet was shown once. Without the sheet the group's main device cannot change: if the sheet is lost, make a new group.")
                .foregroundStyle(palette.textDim)
        } header: {
            Text("Recovery key")
        }
        .listRowBackground(palette.surface)
    }
}

/// The group's recovery key, shown once after the group is made (docs/apps.md,
/// "The recovery sheet (0.6)"): the person writes it on a sheet (printed or
/// saved to Files), onto a YubiKey, or both; leaving with neither asks first.
/// The phone keeps no copy once the view closes.
struct RecoverySheetView: View {
    let sheet: Core.RecoverySheet
    /// The group's tag, which names the YubiKey's slot.
    let group: String?
    let made: Date
    let done: () -> Void
    @Environment(\.palette) private var palette
    @Environment(\.scenePhase) private var phase
    @Environment(\.themeStyle) private var style
    @EnvironmentObject private var model: AppModel

    private enum Step { case choice, sheet, yubikey }
    @State private var step = Step.choice
    @State private var pdf: URL?
    @State private var failure: String?
    /// The sheet was seen; printing or saving it counts as kept.
    @State private var sheetSeen = false
    @State private var kept = false
    @State private var onCard = false
    @State private var saving = false
    @State private var askingDone = false
    @State private var askingUnsaved = false
    @State private var pin = ""
    /// A YubiKey is plugged into the USB-C port: the PIN then goes to it,
    /// and no NFC sheet is needed.
    @State private var plugged = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: Tokens.spacingLarge) {
                    switch step {
                    case .choice: choice
                    case .sheet: sheetStep
                    case .yubikey: yubikeyStep
                    }
                    if let m = model.message {
                        Text(m).multilineTextAlignment(.center).foregroundStyle(palette.textDim)
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
                if step == .choice {
                    ToolbarItem(placement: .confirmationAction) {
                        Button { leave() } label: { Text("Done") }
                    }
                } else {
                    ToolbarItem(placement: .cancellationAction) {
                        Button { back() } label: { Text("Back") }
                    }
                }
            }
            .alert(Text("Did you keep the sheet?"), isPresented: $askingDone) {
                Button { close() } label: { Text("I kept it") }
                Button(role: .cancel) {} label: { Text("Back") }
            } message: {
                Text("This phone forgets the key now. To get a sheet again, make a new recovery key.")
            }
            .alert(Text("Leave without saving the recovery key?"), isPresented: $askingUnsaved) {
                Button(role: .destructive) { close() } label: { Text("Leave without saving") }
                Button(role: .cancel) {} label: { Text("Back") }
            } message: {
                Text("Without it, losing this phone means making a new group and joining every device to it again.")
            }
            .fileExporter(isPresented: $saving, document: pdf.flatMap { try? PDFFile(url: $0) }, contentType: .pdf,
                          defaultFilename: String(localized: "CBB recovery key", bundle: .app)) { result in
                switch result {
                case .success: kept = true
                case let .failure(error):
                    failure = AppModel.describe(error, summary: String(localized: "Could not make the PDF.", bundle: .app))
                }
            }
        }
        .interactiveDismissDisabled()
        // The app switcher's snapshot shows a blank page, not the key.
        .overlay {
            if phase != .active { AppBackground().ignoresSafeArea() }
        }
        .task { makePDF() }
        // The PDF stays on disk only while the app is in front.
        .onChange(of: phase) { _, now in
            switch now {
            case .background:
                RecoveryPage.removePDF()
                pdf = nil
            case .active:
                if pdf == nil { makePDF() }
            default: break
            }
        }
    }

    /// The first step: the sheet, the YubiKey, or both.
    @ViewBuilder private var choice: some View {
        Text("Save the group's recovery key").font(.title2.weight(.bold)).multilineTextAlignment(.center)
        Text("Save it on a sheet, on a YubiKey, or both. Only with it can the group move to another main device if this phone is lost. It is shown only now.")
            .multilineTextAlignment(.center)
            .foregroundStyle(palette.textDim)
        Button { step = .sheet; sheetSeen = true } label: { Label { Text("Write on a sheet") } icon: { Image(systemName: "doc.text") } }
            .buttonStyle(GlassButtonStyle())
        Button { step = .yubikey; failure = nil; model.message = nil } label: { Label { Text("Write to YubiKey") } icon: { Image(systemName: "key") } }
            .buttonStyle(GlassButtonStyle())
            .disabled(onCard || model.busy || group == nil)
    }

    /// The sheet: printing it, or saving it as a PDF to Files.
    @ViewBuilder private var sheetStep: some View {
        Text("Print this sheet or save it as a PDF now. It shows only this once.")
            .multilineTextAlignment(.center)
            .foregroundStyle(palette.textDim)
        RecoveryPage(sheet: sheet, made: made)
            .clipShape(RoundedRectangle(cornerRadius: style.radiusCard, style: .continuous))
            .privacySensitive()
        Button { print() } label: { Label { Text("Print") } icon: { Image(systemName: "printer") } }
            .buttonStyle(GlassButtonStyle())
            .disabled(pdf == nil)
        Button { saving = true } label: { Label { Text("Save to Files") } icon: { Image(systemName: "folder") } }
            .buttonStyle(GlassButtonStyle())
            .disabled(pdf == nil)
        Text("A saved file is the group's key: copy it off the phone to paper or a drive kept safe, then delete it here.")
            .multilineTextAlignment(.center)
            .foregroundStyle(palette.textDim)
    }

    /// The YubiKey: one plugged in is found by itself and takes the PIN;
    /// otherwise the PIN comes first and Scan with NFC opens the system's
    /// NFC sheet.
    @ViewBuilder private var yubikeyStep: some View {
        Text("Insert your YubiKey or hold it to the phone.")
            .multilineTextAlignment(.center)
            .foregroundStyle(palette.textDim)
        YubiKeyPinField(pin: $pin)
            .onSubmit { seal() }
            .submitLabel(.go)
            .padding(Tokens.spacingMedium)
            .background(palette.surface, in: RoundedRectangle(cornerRadius: style.radiusCard, style: .continuous))
        if plugged {
            Text("Type the YubiKey's PIN.")
                .multilineTextAlignment(.center)
                .foregroundStyle(palette.textDim)
            Button { seal() } label: { Text("Continue") }
                .buttonStyle(GlassButtonStyle())
                .disabled(!YubiKeyPinField.fits(pin) || model.busy)
        } else if YubiKeyNfc.available {
            Button { seal() } label: { Label { Text("Scan with NFC") } icon: { Image(systemName: "wave.3.right") } }
                .buttonStyle(GlassButtonStyle())
                .disabled(!YubiKeyPinField.fits(pin) || model.busy)
        }
        // A key plugged in while this step shows is found within a second.
        Color.clear.frame(height: 0).task(id: step) {
            while !Task.isCancelled, step == .yubikey {
                plugged = await model.yubiKeyPlugged()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private func back() {
        step = .choice
        pin = ""
    }

    /// Done on the choice: a key written somewhere closes; a sheet only
    /// looked at asks whether it was kept; nothing saved asks first.
    private func leave() {
        if onCard || kept {
            close()
        } else if sheetSeen {
            askingDone = true
        } else {
            askingUnsaved = true
        }
    }

    private func makePDF() {
        do {
            pdf = try RecoveryPage.pdf(sheet: sheet, made: made)
        } catch {
            failure = AppModel.describe(error, summary: String(localized: "Could not make the PDF.", bundle: .app))
        }
    }

    private func print() {
        guard let pdf else { return }
        let c = UIPrintInteractionController.shared
        let info = UIPrintInfo.printInfo()
        info.outputType = .grayscale
        info.jobName = String(localized: "CBB recovery key", bundle: .app)
        c.printInfo = info
        c.printingItem = pdf
        c.present(animated: true) { _, completed, _ in
            if completed { kept = true }
        }
    }

    /// Seals this sheet's key onto the YubiKey, in the group's slot.
    private func seal() {
        guard YubiKeyPinField.fits(pin), let group else { return }
        let pin = pin
        self.pin = ""
        failure = nil
        Task {
            if await model.sealOnCard(sheet: sheet.qr, pin: pin, group: group) {
                onCard = true
                step = .choice
            }
        }
    }

    /// Forgets the key: the PDF goes, and the sheet with the view.
    private func close() {
        RecoveryPage.removePDF()
        pdf = nil
        done()
    }
}

/// The sheet's PDF as Files saves it.
private struct PDFFile: FileDocument {
    static var readableContentTypes: [UTType] { [.pdf] }
    let data: Data

    init(url: URL) throws { data = try Data(contentsOf: url) }

    init(configuration: ReadConfiguration) throws {
        guard let d = configuration.file.regularFileContents else { throw CocoaError(.fileReadCorruptFile) }
        data = d
    }

    func fileWrapper(configuration _: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}

/// The page that is printed: black on white, the QR code, the key in groups
/// of four, the date and what to do with it.
struct RecoveryPage: View {
    let sheet: Core.RecoverySheet
    let made: Date

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("CBB recovery key").font(.title2.weight(.bold))
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
            Text("Keep this sheet somewhere safe, away from your phones. Anyone who has it and a device of the group can move your group to that device.")
            Text("To move the group to another device of it: on a phone, choose Move the group to this phone in its settings and scan the code; on a computer, run cbb recovery and type the key.")
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

    /// Where the PDF is made: the temporary folder, one file.
    static var pdfURL: URL { FileManager.default.temporaryDirectory.appendingPathComponent("CBB recovery key.pdf") }

    /// Deletes the PDF: when the sheet closes, when the app goes to the
    /// background, and at launch, for one an ended app left.
    static func removePDF() { try? FileManager.default.removeItem(at: pdfURL) }

    /// The page as a PDF of A4 in the temporary folder, which removePDF
    /// deletes.
    @MainActor static func pdf(sheet: Core.RecoverySheet, made: Date) throws -> URL {
        let url = pdfURL
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
        // The sheet restores the group: sealed whenever the phone is
        // locked, and never in a backup.
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
        try (url as NSURL).setResourceValue(true, forKey: .isExcludedFromBackupKey)
        return url
    }
}

/// The YubiKey's PIN, typed in an alert before the phone waits for the
/// card; it stays in memory only until the card took it.
struct YubiKeyPinField: View {
    @Binding var pin: String

    /// A PIV PIN has six to eight characters, not only digits.
    static func fits(_ pin: String) -> Bool { (6...8).contains(pin.utf8.count) }

    var body: some View {
        SecureField(String(localized: "YubiKey PIN", bundle: .app), text: $pin)
            .keyboardType(.asciiCapable)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
    }
}
