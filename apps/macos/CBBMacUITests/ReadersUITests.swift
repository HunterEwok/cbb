// SPDX-License-Identifier: AGPL-3.0-only

import AppKit
import XCTest

/// The Mac app's window in each of the project's eight languages and for
/// every reader (docs/testbench-catalogue.md, A9, U14; docs/testing.md, "The
/// apps' languages, accessibility and screenshots"), with no service
/// answering (CBB_SOCKET), as MacUITests runs it: the notice translated and
/// Xcode's accessibility audit (element descriptions; macOS audits no
/// clipped text) and each text's contrast, measured on the window's picture,
/// passing in every language. Each window's picture is attached to the test's result.
final class ReadersUITests: XCTestCase {
    static let languages = ["ar", "en", "es", "he", "hi", "ru", "sw", "zh-Hans"]

    override func setUp() {
        continueAfterFailure = true
    }

    private func launch(language: String) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchEnvironment["CBB_SOCKET"] = "/tmp/cbb-ui-no-service-\(ProcessInfo.processInfo.processIdentifier).sock"
        app.launchArguments = ["-AppleLanguages", "(\(language))", "-WindowAtLaunch", "YES", "-ShowErrorDetails", "NO"]
        app.launch()
        return app
    }

    private func tr(_ english: String, _ language: String, file: StaticString = #filePath, line: UInt = #line) -> String {
        if language == "en" { return english }
        guard let path = Bundle(for: Self.self).path(forResource: language, ofType: "lproj"), let bundle = Bundle(path: path) else {
            XCTFail("the test bundle has no \(language) strings", file: file, line: line)
            return english
        }
        let text = bundle.localizedString(forKey: english, value: nil, table: "Localizable")
        if text == english { XCTFail("no \(language) for \(english)", file: file, line: line) }
        return text
    }

    /// A9, U14: the stopped service's notice in each language, and the
    /// audit passing; the pictures show Arabic and Hebrew from right to left.
    func testLanguages() {
        for language in Self.languages {
            let app = launch(language: language)
            let title = app.staticTexts[tr("The service does not answer", language)]
            XCTAssertTrue(title.waitForExistence(timeout: 30), "\(language): no translated notice in \(app.debugDescription)")
            let window = app.windows.firstMatch
            let shot = window.screenshot()
            let a = XCTAttachment(screenshot: shot)
            a.name = "window-\(language)"
            a.lifetime = .keepAlways
            add(a)
            do {
                try app.performAccessibilityAudit(for: [.sufficientElementDescription]) { issue in
                    guard let e = issue.element else { return false }
                    // The Touch Bar and the window's hosting view, a group as
                    // large as the window that AppKit puts around the app's
                    // own content, are the system's, not the app's to name.
                    if e.elementType == .touchBar || e.elementType == .group && e.frame == window.frame && e.label.isEmpty { return true }
                    XCTFail("the window in \(language): \(issue.compactDescription) on \(e.elementType.rawValue) '\(e.label)' '\(String(describing: e.value ?? ""))' at \(e.frame)")
                    return true
                }
            } catch {
                XCTFail("the window in \(language): \(error)")
            }
            // The audit's contrast check on macOS fails text that its own
            // picture shows dark on a light sheet, so the contrast is
            // measured here, on that picture: each text's darkest and
            // lightest pixels at least 4.5:1 (WCAG AA).
            for text in window.staticTexts.allElementsBoundByIndex where text.frame.width > 0 {
                guard let ratio = Self.contrast(text.frame, in: shot, window: window.frame) else {
                    XCTFail("the window in \(language): no picture of '\(text.label)'")
                    continue
                }
                XCTAssertGreaterThanOrEqual(ratio, 4.5, "the window in \(language): '\(String(describing: text.value ?? text.label))' at \(text.frame) has a contrast of \(ratio)")
            }
            app.terminate()
        }
    }

    /// The contrast between the darkest and the lightest pixel of a frame
    /// of the window's picture, as WCAG computes it from their relative
    /// luminance.
    static func contrast(_ frame: CGRect, in shot: XCUIScreenshot, window: CGRect) -> Double? {
        guard let image = shot.image.cgImage(forProposedRect: nil, context: nil, hints: nil), window.width > 0 else { return nil }
        let scale = CGFloat(image.width) / window.width
        let local = frame.offsetBy(dx: -window.minX, dy: -window.minY)
        let pixels = CGRect(x: local.minX * scale, y: local.minY * scale, width: local.width * scale, height: local.height * scale)
            .integral.intersection(CGRect(x: 0, y: 0, width: image.width, height: image.height))
        guard !pixels.isEmpty, let crop = image.cropping(to: pixels) else { return nil }
        let rep = NSBitmapImageRep(cgImage: crop)
        var darkest = 1.0, lightest = 0.0
        for y in 0..<rep.pixelsHigh {
            for x in 0..<rep.pixelsWide {
                guard let c = rep.colorAt(x: x, y: y)?.usingColorSpace(.sRGB) else { continue }
                let l = luminance(c)
                darkest = min(darkest, l)
                lightest = max(lightest, l)
            }
        }
        return (lightest + 0.05) / (darkest + 0.05)
    }

    static func luminance(_ c: NSColor) -> Double {
        func linear(_ v: CGFloat) -> Double {
            let v = Double(v)
            return v <= 0.04045 ? v / 12.92 : pow((v + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * linear(c.redComponent) + 0.7152 * linear(c.greenComponent) + 0.0722 * linear(c.blueComponent)
    }
}
