// SPDX-License-Identifier: AGPL-3.0-only

import XCTest

/// The app's screens before a group, driven as a person would
/// (docs/testbench-catalogue.md, A9, A14, A15, U12): the Start screen and
/// its first-launch note, Settings before a group with the colours and
/// themes kept across a launch, the error details switch behind seven taps
/// on the version, and Russian. A group needs the Secure Enclave and a
/// computer, which the bench's devices give.
final class StartUITests: XCTestCase {
    /// The ten colours of apps/design/tokens.json, by their English names.
    static let colours = ["Terminal", "Midnight", "Amber", "Ocean", "Teal", "Coral", "Rose", "Lime", "Graphite", "Ruby"]

    override func setUp() {
        continueAfterFailure = false
    }

    /// The app launched fresh: its settings and the first-launch note reset
    /// through the arguments domain, in English unless asked.
    private func launch(_ extra: [String] = [], language: String = "en") -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(\(language))", "-AppleLocale", language == "ru" ? "ru_RU" : "en_GB"] + extra
        app.launch()
        return app
    }

    /// A14: the Start screen says what the app does and offers both ways in;
    /// the first-launch note goes for good once closed.
    func testStartScreen() {
        let app = launch(["-welcomed", "NO"])
        XCTAssertTrue(app.staticTexts["One clipboard for this phone and your computers."].waitForExistence(timeout: 30))
        XCTAssertTrue(app.buttons["Connect a new device"].exists)
        XCTAssertTrue(app.buttons["I already use Clipboard Bridge on another phone"].exists)
        // Without the Secure Enclave the phone's key may not be made; the
        // note then stays away, and an error says why instead.
        if app.staticTexts["This phone is ready"].waitForExistence(timeout: 5) {
            app.buttons["Close"].tap()
            XCTAssertFalse(app.staticTexts["This phone is ready"].waitForExistence(timeout: 2))
            app.terminate()
            let again = launch()
            XCTAssertTrue(again.buttons["Connect a new device"].waitForExistence(timeout: 30))
            XCTAssertFalse(again.staticTexts["This phone is ready"].exists, "the first-launch note came back")
        }
    }

    /// A14: "I already use Clipboard Bridge on another phone" shows the code
    /// the other phone scans.
    func testJoinFromStart() {
        let app = launch()
        let join = app.buttons["I already use Clipboard Bridge on another phone"]
        XCTAssertTrue(join.waitForExistence(timeout: 30))
        join.tap()
        XCTAssertTrue(app.staticTexts["Join a group"].waitForExistence(timeout: 10))
    }

    /// A15, A14: Settings before a group: each of the ten colours and the
    /// three themes can be chosen, and the choice is kept across a launch.
    func testColoursAndThemes() {
        var app = launch()
        openSettings(app)
        for theme in ["Dark", "Light", "System"] {
            let b = app.segmentedControls.buttons[theme]
            XCTAssertTrue(b.waitForExistence(timeout: 5), "no theme \(theme)")
            b.tap()
            XCTAssertTrue(selected(b), "\(theme) is not chosen after a tap")
        }
        app.segmentedControls.buttons["Dark"].tap()
        for colour in Self.colours {
            let b = app.buttons[colour]
            XCTAssertTrue(b.waitForExistence(timeout: 5), "no colour \(colour)")
            b.tap()
            XCTAssertTrue(selected(b), "\(colour) is not chosen after a tap")
            for other in Self.colours where other != colour {
                XCTAssertFalse(app.buttons[other].isSelected, "\(other) is still chosen with \(colour)")
            }
        }
        app.buttons["Ocean"].tap()
        app.terminate()

        app = launch()
        openSettings(app)
        XCTAssertTrue(app.buttons["Ocean"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["Ocean"].isSelected, "the colour was not kept")
        XCTAssertTrue(app.segmentedControls.buttons["Dark"].isSelected, "the theme was not kept")
        // Back to the defaults for the other tests.
        app.buttons["Terminal"].tap()
        app.segmentedControls.buttons["System"].tap()
    }

    /// U12: the error details switch shows after seven taps on the version,
    /// and the launch argument ShowErrorDetails sets it.
    func testErrorDetailsSwitch() {
        // No launch argument here: one in the arguments domain would hide
        // what the taps store.
        var app = launch()
        openSettings(app)
        let version = app.staticTexts["Version"]
        scrollTo(version, in: app)
        // The taps are kept, so on a simulator that ran this test before the
        // switch shows at once; a fresh one, as in CI, shows it only after.
        if !app.switches["Show error details"].exists {
            for i in 0..<7 {
                XCTAssertFalse(app.switches["Show error details"].exists, "the switch shows after \(i) taps")
                version.tap()
            }
        }
        let toggle = app.switches["Show error details"]
        XCTAssertTrue(toggle.waitForExistence(timeout: 5), "seven taps on the version show no switch")
        app.terminate()

        for (arg, want) in [("NO", "0"), ("YES", "1")] {
            app = launch(["-ShowErrorDetailsSwitch", "YES", "-ShowErrorDetails", arg])
            openSettings(app)
            let s = app.switches["Show error details"]
            scrollTo(s, in: app)
            XCTAssertEqual(s.value as? String, want, "ShowErrorDetails \(arg) gives the switch \(String(describing: s.value))")
            app.terminate()
        }
    }

    /// A9: in Russian the Start screen and Settings are Russian; in a
    /// language the app has no translation for, the Start screen offers the
    /// language menu.
    func testLanguages() {
        var app = launch(language: "ru")
        XCTAssertTrue(app.buttons[ru("Connect a new device")].waitForExistence(timeout: 30))
        XCTAssertTrue(app.staticTexts[ru("One clipboard for this phone and your computers.")].exists)
        XCTAssertTrue(app.buttons[ru("I already use Clipboard Bridge on another phone")].exists)
        app.buttons[ru("Settings")].tap()
        XCTAssertTrue(app.buttons[ru("Ocean")].waitForExistence(timeout: 10))
        XCTAssertTrue(app.segmentedControls.buttons[ru("Dark")].exists)
        XCTAssertTrue(app.buttons[ru("Done")].exists)
        app.terminate()

        app = launch(language: "de")
        XCTAssertTrue(app.buttons["Connect a new device"].waitForExistence(timeout: 30))
        XCTAssertTrue(languageMenu(app).exists, "no language menu for a language without a translation")
        app.terminate()

        app = launch(language: "en")
        XCTAssertTrue(app.buttons["Connect a new device"].waitForExistence(timeout: 30))
        XCTAssertFalse(languageMenu(app).exists, "the language menu shows in English")
    }

    /// The app's Russian text for an English one, from its string catalog,
    /// which this target compiles too; a missing translation fails.
    private func ru(_ english: String, file: StaticString = #filePath, line: UInt = #line) -> String {
        guard let path = Bundle(for: Self.self).path(forResource: "ru", ofType: "lproj"), let bundle = Bundle(path: path) else {
            XCTFail("the test bundle has no Russian strings", file: file, line: line)
            return english
        }
        let text = bundle.localizedString(forKey: english, value: nil, table: "Localizable")
        if text == english { XCTFail("no Russian for \(english)", file: file, line: line) }
        return text
    }

    /// The Start screen's language menu, whose label also names the language chosen.
    private func languageMenu(_ app: XCUIApplication) -> XCUIElement {
        app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Language")).firstMatch
    }

    private func openSettings(_ app: XCUIApplication) {
        let settings = app.buttons["Settings"]
        XCTAssertTrue(settings.waitForExistence(timeout: 30))
        settings.tap()
        XCTAssertTrue(app.navigationBars["Settings"].waitForExistence(timeout: 10))
    }

    /// Whether e shows as selected within a few seconds: a tap reaches the
    /// app's state and then the accessibility tree a moment later, more so
    /// on a loaded simulator, so reading isSelected at once can see the
    /// state before the tap.
    private func selected(_ e: XCUIElement, timeout: TimeInterval = 5) -> Bool {
        let done = XCTNSPredicateExpectation(predicate: NSPredicate(format: "isSelected == true"), object: e)
        return XCTWaiter().wait(for: [done], timeout: timeout) == .completed
    }

    private func scrollTo(_ e: XCUIElement, in app: XCUIApplication) {
        for _ in 0..<8 where !(e.exists && e.isHittable) {
            app.swipeUp()
        }
        XCTAssertTrue(e.exists, "\(e) is not on the screen")
    }
}
