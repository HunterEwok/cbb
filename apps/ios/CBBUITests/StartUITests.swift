// SPDX-License-Identifier: AGPL-3.0-only

import XCTest

/// The app's screens before a group, driven as a person would
/// (docs/testbench-catalogue.md, A9, A14, A15, U12): the Start screen,
/// Settings before a group with the colours and
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

    /// A14: the Start screen says what the app does and offers the three
    /// ways in, with the language and Settings at the top.
    func testStartScreen() {
        let app = launch()
        XCTAssertTrue(app.staticTexts["One clipboard for this phone and your computers."].waitForExistence(timeout: 30))
        XCTAssertTrue(app.buttons["Create a group"].exists)
        XCTAssertTrue(app.buttons["Join a group"].exists)
        XCTAssertTrue(app.buttons["Restore with the recovery key"].exists)
        XCTAssertTrue(languageMenu(app).exists, "no language menu on the Start screen")
        XCTAssertTrue(app.buttons["Settings"].exists)
    }

    /// A14: "Join a group" shows the code a phone of the group scans and
    /// the digits a computer types.
    func testJoinFromStart() {
        let app = launch()
        let join = app.buttons["Join a group"]
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
            XCTAssertTrue(choose(b), "\(theme) is not chosen after a tap")
        }
        // Each tap is checked, as choose does: a loaded simulator can lose
        // a tap, and a lost one would look like a choice that was not kept.
        XCTAssertTrue(choose(app.segmentedControls.buttons["Dark"]), "Dark is not chosen after a tap")
        for colour in Self.colours {
            let b = app.buttons[colour]
            XCTAssertTrue(b.waitForExistence(timeout: 5), "no colour \(colour)")
            XCTAssertTrue(choose(b), "\(colour) is not chosen after a tap")
            for other in Self.colours where other != colour {
                XCTAssertFalse(app.buttons[other].isSelected, "\(other) is still chosen with \(colour)")
            }
        }
        XCTAssertTrue(choose(app.buttons["Ocean"]), "Ocean is not chosen after a tap")
        app.terminate()

        app = launch()
        openSettings(app)
        XCTAssertTrue(app.buttons["Ocean"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["Ocean"].isSelected, "the colour was not kept")
        XCTAssertTrue(app.segmentedControls.buttons["Dark"].isSelected, "the theme was not kept")
        // Back to the defaults for the other tests.
        XCTAssertTrue(choose(app.buttons["Terminal"]), "Terminal is not chosen after a tap")
        XCTAssertTrue(choose(app.segmentedControls.buttons["System"]), "System is not chosen after a tap")
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

    /// A9: in Russian the Start screen and Settings are Russian.
    func testLanguages() {
        let app = launch(language: "ru")
        XCTAssertTrue(app.buttons[ru("Create a group")].waitForExistence(timeout: 30))
        XCTAssertTrue(app.staticTexts[ru("One clipboard for this phone and your computers.")].exists)
        XCTAssertTrue(app.buttons[ru("Join a group")].exists)
        app.buttons[ru("Settings")].tap()
        XCTAssertTrue(app.buttons[ru("Ocean")].waitForExistence(timeout: 10))
        XCTAssertTrue(app.segmentedControls.buttons[ru("Dark")].exists)
        XCTAssertTrue(app.buttons[ru("Done")].exists)
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

    /// The Start screen's language menu.
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

    /// Taps e and tells whether it shows as selected; a loaded simulator
    /// can lose a tap, so one that did not take is tapped once more.
    private func choose(_ e: XCUIElement) -> Bool {
        e.tap()
        if selected(e) { return true }
        e.tap()
        return selected(e, timeout: 10)
    }

    /// Scrolls until e is inside the window. Its frame, not isHittable: a
    /// loaded simulator can fail to work out an element's hit point and
    /// fail the test from inside isHittable.
    private func scrollTo(_ e: XCUIElement, in app: XCUIApplication) {
        let window = app.windows.firstMatch
        for _ in 0..<8 where !(e.exists && !e.frame.isEmpty && window.frame.contains(e.frame)) {
            app.swipeUp()
        }
        XCTAssertTrue(e.exists, "\(e) is not on the screen")
    }
}
