// SPDX-License-Identifier: AGPL-3.0-only

import XCTest

/// The Mac app's window driven as a person would (docs/maintainers/testbench-catalogue.md,
/// A4, A9, U12), with its control socket pointed where no service answers
/// (CBB_SOCKET): the stopped service explained in one line, the error
/// underneath only with error details on, the Settings window's switch, and
/// Russian. A running service and the admin prompts are the bench's.
final class MacUITests: XCTestCase {
    static let plain = "The CBB service is not running on this Mac. Install it, or start it with sudo launchctl kickstart system/tools.cbb."

    override func setUp() {
        continueAfterFailure = false
    }

    private func launch(_ extra: [String] = [], language: String = "en") -> XCUIApplication {
        let app = XCUIApplication()
        // A short path: the test runner's own temporary folder can be long
        // enough to pass a socket address's 104 bytes, which the app reports
        // as an unexpected answer instead of a stopped service.
        app.launchEnvironment["CBB_SOCKET"] = "/tmp/cbb-ui-no-service-\(ProcessInfo.processInfo.processIdentifier).sock"
        // The app opens no window at launch, living in the menu bar; the
        // tests ask for the window as an ordinary app's.
        app.launchArguments = ["-AppleLanguages", "(\(language))", "-WindowAtLaunch", "YES"] + extra
        app.launch()
        return app
    }

    /// A4, U12: with details off the window says only what to do; with them
    /// on, the error underneath follows after a blank line.
    func testStoppedService() {
        var app = launch(["-ShowErrorDetails", "NO"])
        XCTAssertTrue(app.staticTexts["The service does not answer"].waitForExistence(timeout: 30))
        XCTAssertTrue(text(app, equal: Self.plain).waitForExistence(timeout: 10), "with details off the notice is not the plain message in \(app.debugDescription)")
        app.terminate()

        app = launch(["-ShowErrorDetails", "YES"])
        // The notice's text is selectable, which may make it a text view
        // rather than a static text.
        let detailed = app.descendants(matching: .any).matching(NSPredicate(format: "value BEGINSWITH %@ OR label BEGINSWITH %@", Self.plain + "\n\n", Self.plain + "\n\n")).firstMatch
        XCTAssertTrue(detailed.waitForExistence(timeout: 30), "with details on the notice has no error underneath in \(app.debugDescription)")
        XCTAssertFalse(text(app, equal: Self.plain).exists, "with details on the plain message shows alone")
        app.terminate()
    }

    /// U12: the Settings window's switch shows the setting the app runs
    /// with; while it is off, seven clicks on the version show it, as on the
    /// phones.
    func testSettingsSwitch() {
        for (arg, want) in [("NO", false), ("YES", true)] {
            let app = launch(["-ShowErrorDetails", arg])
            XCTAssertTrue(app.staticTexts["The service does not answer"].waitForExistence(timeout: 30))
            app.activate()
            let item = app.menuBarItems["CBB"].menuItems["Settings…"]
            if item.waitForExistence(timeout: 5) {
                app.menuBarItems["CBB"].click()
                item.click()
            } else {
                app.typeKey(",", modifierFlags: .command)
            }
            let toggle = app.descendants(matching: .any).matching(identifier: "errorDetails").firstMatch
            if !want {
                let version = app.descendants(matching: .any).matching(identifier: "version").firstMatch
                XCTAssertTrue(version.waitForExistence(timeout: 10), "Settings has no version in \(app.debugDescription)")
                XCTAssertFalse(toggle.exists, "the error details switch shows before seven clicks")
                // A click at the row's centre: the row is no control of its own,
                // which XCUITest may call not hittable.
                for _ in 0..<7 { version.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).click() }
            }
            XCTAssertTrue(toggle.waitForExistence(timeout: 10), "Settings has no error details switch in \(app.debugDescription)")
            let on = (toggle.value as? Int ?? Int(toggle.value as? String ?? "") ?? -1) == 1
            XCTAssertEqual(on, want, "ShowErrorDetails \(arg) gives the switch \(String(describing: toggle.value))")
            app.terminate()
        }
    }

    /// A9: in Russian the notice is Russian.
    func testRussian() {
        let app = launch(language: "ru")
        XCTAssertTrue(app.staticTexts[ru("The service does not answer")].waitForExistence(timeout: 30))
        app.terminate()
    }

    /// An element, a static text or the selectable text view, whose value or
    /// label is exactly this; a query by a long string
    /// as the identifier is refused past 128 characters.
    private func text(_ app: XCUIApplication, equal: String) -> XCUIElement {
        app.descendants(matching: .any).matching(NSPredicate(format: "value == %@ OR label == %@", equal, equal)).firstMatch
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
}
