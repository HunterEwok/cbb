// SPDX-License-Identifier: AGPL-3.0-only

import XCTest

/// The Mac app's window in each of the project's eight languages and for
/// every reader (docs/testbench-catalogue.md, A9, U14; docs/testing.md, "The
/// apps' languages, accessibility and screenshots"), with no service
/// answering (CBB_SOCKET), as MacUITests runs it: the notice translated and
/// Xcode's accessibility audit (contrast, clipped text, element descriptions) passing
/// in every language. Each window's picture is attached to the test's result.
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
            let a = XCTAttachment(screenshot: window.screenshot())
            a.name = "window-\(language)"
            a.lifetime = .keepAlways
            add(a)
            do {
                try app.performAccessibilityAudit(for: [.contrast, .textClipped, .sufficientElementDescription])
            } catch {
                XCTFail("the window in \(language): \(error)")
            }
            app.terminate()
        }
    }
}
