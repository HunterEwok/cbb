// SPDX-License-Identifier: AGPL-3.0-only

import XCTest

/// Home on a big screen (docs/apps.md, "Big screens"), with the debug
/// build's made-up group (-showcase): the sidebar with its sections, a
/// tile that opens its card beside the tiles, the keyboard's arrows and
/// Escape, the settings in the sidebar, and Arabic laid out from right to
/// left. Each screen's picture is attached, for a person to look over. On
/// a phone the test has nothing to check and is skipped.
final class PadUITests: XCTestCase {
    override func setUp() {
        continueAfterFailure = true
    }

    /// The simulator keeps the orientation for the tests after these: the
    /// readers' contrast check maps frames onto a portrait screenshot.
    override func tearDown() {
        XCUIDevice.shared.orientation = .portrait
    }

    private func launch(language: String = "en", extra: [String] = []) throws -> XCUIApplication {
        try XCTSkipUnless(UIDevice.current.userInterfaceIdiom == .pad, "Home's big screen is an iPad's")
        let app = XCUIApplication()
        let locale = language == "en" ? "en_GB" : language
        app.launchArguments = ["-showcase", "-PasteChoice", "button", "-deviceLayoutWide", "tiles",
                               "-AppleLanguages", "(\(language))", "-AppleLocale", locale] + extra
        app.launch()
        XCUIDevice.shared.orientation = .landscapeLeft
        return app
    }

    private func picture(_ name: String) {
        let a = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        a.name = name
        a.lifetime = .keepAlways
        add(a)
    }

    /// The sidebar lists the devices' sections and the settings' parts; a
    /// tile opens its card beside the tiles and Escape closes it; the arrow
    /// keys choose the next device; a settings part opens beside the sidebar.
    func testSidebarAndCard() throws {
        let app = try launch()
        XCTAssertTrue(app.staticTexts["All devices"].waitForExistence(timeout: 30))
        XCTAssertTrue(app.staticTexts["Needs attention"].exists, "a frozen device needs attention")
        XCTAssertTrue(app.staticTexts["Recovery key"].exists, "the root has the recovery key")
        picture("pad-home")

        let mac = app.buttons.containing(NSPredicate(format: "label CONTAINS 'studio-mac'")).firstMatch
        XCTAssertTrue(mac.waitForExistence(timeout: 10))
        mac.tap()
        XCTAssertTrue(app.buttons["Close"].waitForExistence(timeout: 10), "the card opens beside the tiles")
        XCTAssertTrue(mac.isSelected, "the chosen tile is marked")
        picture("pad-home-card")

        app.typeKey(.rightArrow, modifierFlags: [])
        let thinkpad = app.buttons.containing(NSPredicate(format: "label CONTAINS 'thinkpad'")).firstMatch
        XCTAssertTrue(thinkpad.waitForExistence(timeout: 5))
        XCTAssertTrue(thinkpad.isSelected, "the right arrow chooses the next device")

        app.typeKey(.escape, modifierFlags: [])
        XCTAssertTrue(app.buttons["Close"].waitForNonExistence(timeout: 5), "Escape closes the card")

        // The sidebar's row; the same words also stand on a button outside it.
        app.collectionViews["Sidebar"].staticTexts["Appearance"].tap()
        XCTAssertTrue(app.buttons["Blueprint"].waitForExistence(timeout: 10), "the look opens beside the sidebar")
        picture("pad-settings")

        app.typeKey("1", modifierFlags: .command)
        XCTAssertTrue(mac.waitForExistence(timeout: 5), "Command-1 goes back to all devices")
    }

    /// In portrait the sidebar folds away and the card still opens beside
    /// the tiles.
    func testPortrait() throws {
        let app = try launch()
        XCUIDevice.shared.orientation = .portrait
        let mac = app.buttons.containing(NSPredicate(format: "label CONTAINS 'studio-mac'")).firstMatch
        XCTAssertTrue(mac.waitForExistence(timeout: 30))
        mac.tap()
        XCTAssertTrue(app.buttons["Close"].waitForExistence(timeout: 10))
        picture("pad-portrait-card")
    }

    /// In Arabic the sidebar stands at the right edge and the card at the
    /// left one.
    func testRightToLeft() throws {
        let app = try launch(language: "ar")
        let mac = app.buttons.containing(NSPredicate(format: "label CONTAINS 'studio-mac'")).firstMatch
        XCTAssertTrue(mac.waitForExistence(timeout: 30))
        mac.tap()
        let close = app.buttons.matching(identifier: "padCardClose").firstMatch
        XCTAssertTrue(close.waitForExistence(timeout: 10))
        XCTAssertLessThan(close.frame.midX, mac.frame.midX, "the card stands left of the tiles")
        picture("pad-home-card-ar")
    }

    /// At the largest text size the sidebar's rows and the tiles keep
    /// their text whole.
    func testLargestText() throws {
        let app = try launch(extra: ["-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL"])
        XCTAssertTrue(app.staticTexts["All devices"].waitForExistence(timeout: 30))
        picture("pad-home-largest-text")
        try app.performAccessibilityAudit(for: [.textClipped]) { issue in
            // The system's own bars are not the app's to fix.
            guard let e = issue.element, e.isHittable else { return true }
            if app.navigationBars.allElementsBoundByIndex.contains(where: { $0.frame.contains(e.frame) }) { return true }
            // Every other issue fails, named with its element, frame and
            // the audit's words, and with the element's picture.
            XCTFail("\(issue.compactDescription) on \(e.elementType.rawValue) '\(e.label)' at \(e.frame): \(issue.detailedDescription)")
            let a = XCTAttachment(screenshot: e.screenshot())
            a.name = "failed-pad-largest-text-\(e.label)"
            a.lifetime = .keepAlways
            self.add(a)
            return true
        }
    }

    /// DIAGNOSTIC ONLY: which part takes Escape away from the card.
    func testEscapeDiag() throws {
        for variant in ["none", "uikit", "uikit,noshortcut"] {
            let app = try launch(extra: ["-padDiag", variant])
            let mac = app.buttons.containing(NSPredicate(format: "label CONTAINS 'studio-mac'")).firstMatch
            guard mac.waitForExistence(timeout: 30) else { print("PADDIAG \(variant): no tile"); continue }
            mac.tap()
            _ = app.buttons["Close"].waitForExistence(timeout: 10)
            app.typeKey(.rightArrow, modifierFlags: [])
            let thinkpad = app.buttons.containing(NSPredicate(format: "label CONTAINS 'thinkpad'")).firstMatch
            let arrow = thinkpad.waitForExistence(timeout: 5) && thinkpad.isSelected
            app.typeKey(.escape, modifierFlags: [])
            let escape = app.buttons["Close"].waitForNonExistence(timeout: 5)
            var tapEscape = false
            if !escape {
                // Escape again after tapping the empty space beside the tiles.
                app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.95)).tap()
                app.typeKey(.escape, modifierFlags: [])
                tapEscape = app.buttons["Close"].waitForNonExistence(timeout: 5)
            }
            print("PADDIAG \(variant): arrow=\(arrow) escape=\(escape) escapeAfterTap=\(tapEscape)")
            app.terminate()
        }
    }
}
