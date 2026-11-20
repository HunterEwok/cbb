// SPDX-License-Identifier: AGPL-3.0-only

import XCTest

/// The app in each of the project's eight languages and for every reader
/// (docs/maintainers/testbench-catalogue.md, A9, U14, U16; docs/testing.md, "The apps'
/// languages, accessibility and screenshots"): the Start screen and Settings
/// translated, Arabic and Hebrew laid out from right to left, and Xcode's
/// accessibility audit (clipped text, element descriptions, touch targets,
/// Dynamic Type) and each text's contrast, measured on the screen's picture,
/// passing in every language and at the largest text
/// size. Each screen's picture is attached to the test's result, so a run's
/// .xcresult shows every language for a person to look over.
final class ReadersUITests: XCTestCase {
    /// The project's languages, as the app's .lproj folders name them.
    static let languages = ["ar", "en", "es", "he", "hi", "ru", "sw", "zh-Hans"]
    static let rightToLeft: Set<String> = ["ar", "he"]
    /// The languages testLargestText checks at the largest text size:
    /// English, Swahili, among the longest, and Hindi, the tallest script.
    static let largestText = ["en", "sw", "hi"]

    override func setUp() {
        continueAfterFailure = true
    }

    private func launch(language: String, extra: [String] = []) -> XCUIApplication {
        let app = XCUIApplication()
        let locale = language == "zh-Hans" ? "zh_CN" : language == "en" ? "en_GB" : language
        app.launchArguments = ["-AppleLanguages", "(\(language))", "-AppleLocale", locale] + extra
        app.launch()
        return app
    }

    /// The app's text for an English one in a language, from its string
    /// catalog, which this target compiles too; a missing translation fails.
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

    /// Attaches a picture of the screen to the test's result.
    private func picture(_ name: String) {
        XCUIApplication().settle("the picture \(name)")
        let a = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        a.name = name
        a.lifetime = .keepAlways
        add(a)
    }

    /// Runs Xcode's accessibility audit on the screen once it has settled
    /// (`settle`), on what a person can reach. Only an
    /// element of the system's own may fail it: the status bar. Contrast is
    /// measured on the screen's picture (`contrast`).
    private func audit(_ app: XCUIApplication, _ types: XCUIAccessibilityAuditType, _ screen: String) {
        app.settle(screen)
        do {
            try app.performAccessibilityAudit(for: types) { issue in
                guard let e = issue.element else {
                    self.fail("\(screen): \(issue.compactDescription) on no element: \(issue.detailedDescription)",
                              picture: XCUIScreen.main.screenshot(), screen)
                    return true
                }
                // What a person cannot reach (the screen under a sheet, a
                // row scrolled half out of its list) is not looked at, as
                // in `contrast`; it is audited where it is in view.
                if !e.isHittable { return true }
                // The system's status bar is not the app's to fix.
                if e.elementType == .statusBar || app.statusBars.firstMatch.exists && app.statusBars.firstMatch.frame.contains(e.frame) { return true }
                self.fail("\(screen): \(issue.compactDescription) on \(e.elementType.rawValue) '\(e.label)' at \(e.frame): \(issue.detailedDescription)",
                          picture: e.screenshot(), screen)
                return true
            }
        } catch {
            XCTFail("\(screen): \(error)")
        }
        contrast(app, screen)
    }

    /// Fails with an issue, each on a line of its own, and attaches the
    /// picture CI prints into the log.
    private func fail(_ message: String, picture: XCUIScreenshot, _ screen: String) {
        XCTFail(message)
        let a = XCTAttachment(screenshot: picture)
        a.name = "failed-\(screen)"
        a.lifetime = .keepAlways
        add(a)
    }

    /// The audit's contrast check fails text that its own picture shows
    /// at 6.9:1 (the dim text on the light background), so each text and
    /// button on the screen is measured on the screen's picture instead:
    /// its darkest and lightest pixels at least 4.5:1 (WCAG AA), or 3:1 for
    /// large text, which the app marks with the identifier largeText.
    private func contrast(_ app: XCUIApplication, _ screen: String) {
        let shot = XCUIScreen.main.screenshot()
        let bounds = app.frame
        let status = app.statusBars.firstMatch.exists ? app.statusBars.firstMatch.frame : .null
        let elements = app.staticTexts.allElementsBoundByIndex + app.buttons.allElementsBoundByIndex
        // Only what the user sees: a sheet hides the screen under it from
        // touch, not from the element tree.
        for e in elements where !e.label.isEmpty && e.frame.width > 1 && e.frame.height > 1 && bounds.contains(e.frame) && !status.intersects(e.frame) && e.isHittable {
            guard let ratio = Self.contrast(e.frame, in: shot, screen: bounds) else {
                XCTFail("\(screen): no picture of '\(e.label)' at \(e.frame)")
                continue
            }
            // WCAG's large text (the app marks it so) needs 3:1.
            let least = e.identifier == "largeText" ? 3.0 : 4.5
            XCTAssertGreaterThanOrEqual(ratio, least, "\(screen): '\(e.label)' at \(e.frame) has a contrast of \(ratio)")
        }
    }

    /// The contrast between the darkest and the lightest pixel of a frame
    /// of the screen's picture, as WCAG computes it from their relative
    /// luminance.
    static func contrast(_ frame: CGRect, in shot: XCUIScreenshot, screen: CGRect) -> Double? {
        guard let image = shot.image.cgImage, screen.width > 0 else { return nil }
        let scale = CGFloat(image.width) / screen.width
        let pixels = CGRect(x: frame.minX * scale, y: frame.minY * scale, width: frame.width * scale, height: frame.height * scale)
            .integral.intersection(CGRect(x: 0, y: 0, width: image.width, height: image.height))
        guard !pixels.isEmpty, let crop = image.cropping(to: pixels), let space = CGColorSpace(name: CGColorSpace.sRGB) else { return nil }
        let w = crop.width, h = crop.height
        var data = [UInt8](repeating: 0, count: w * h * 4)
        let drawn: Bool = data.withUnsafeMutableBytes { buffer in
            guard let context = CGContext(data: buffer.baseAddress, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4,
                                          space: space, bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue) else { return false }
            context.draw(crop, in: CGRect(x: 0, y: 0, width: w, height: h))
            return true
        }
        guard drawn else { return nil }
        var darkest = 1.0, lightest = 0.0
        for i in stride(from: 0, to: data.count, by: 4) {
            let l = luminance(data[i], data[i + 1], data[i + 2])
            darkest = min(darkest, l)
            lightest = max(lightest, l)
        }
        return (lightest + 0.05) / (darkest + 0.05)
    }

    static func luminance(_ r: UInt8, _ g: UInt8, _ b: UInt8) -> Double {
        func linear(_ c: UInt8) -> Double {
            let v = Double(c) / 255
            return v <= 0.04045 ? v / 12.92 : pow((v + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)
    }

    /// The audit's checks that hold in every language and text size.
    private let checks: XCUIAccessibilityAuditType = [.textClipped, .sufficientElementDescription, .hitRegion, .elementDetection]

    /// Taps e once more after a tap on it that did not take, and writes
    /// that down: a line in the test's output, and an activity with the
    /// screen's picture and the app's element tree as they were before the
    /// second tap, which CI keeps for a failed test (ci.yml, "the failed
    /// tests' activities"). An element that is gone is not tapped.
    private func lostTap(_ app: XCUIApplication, on e: XCUIElement, _ screen: String) {
        let exists = e.exists
        let line = exists
            ? "\(screen): the tap on '\(e.label)' did not open it in 10 seconds; tapping again"
            : "\(screen): the tap did not open it in 10 seconds, and the button is gone; not tapping again"
        print("ReadersUITests: \(line)")
        XCTContext.runActivity(named: line) { activity in
            let shot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
            shot.name = "lost-tap-\(screen)"
            shot.lifetime = .keepAlways
            activity.add(shot)
            let tree = XCTAttachment(string: app.debugDescription)
            tree.name = "elements after a lost tap, \(screen)"
            tree.lifetime = .keepAlways
            activity.add(tree)
            if exists { e.tap() }
        }
    }

    /// A9, U14: in each language the Start screen and Settings are
    /// translated and pass the audit, and the Start screen's top row runs
    /// with the language's direction.
    func testLanguages() {
        var englishOrder: Bool?
        for language in Self.languages {
            let app = launch(language: language)
            let create = app.buttons[tr("Create a group", language)]
            XCTAssertTrue(create.waitForExistence(timeout: 30), "\(language): no Create a group in \(app.debugDescription)")
            XCTAssertTrue(app.staticTexts[tr("One clipboard for this phone and your computers.", language)].exists, "\(language): the tagline is not translated")
            let settings = app.buttons[tr("Settings", language)]
            let menu = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", tr("Language", language))).firstMatch
            XCTAssertTrue(settings.exists && menu.exists, "\(language): no Settings or language menu")
            // The language menu and Settings swap sides from right to left.
            let languageFirst = menu.frame.midX < settings.frame.midX
            if language == "en" {
                englishOrder = languageFirst
            } else if let en = englishOrder {
                XCTAssertEqual(languageFirst, Self.rightToLeft.contains(language) ? !en : en, "\(language): the top row does not run \(Self.rightToLeft.contains(language) ? "right to left" : "left to right")")
            }
            picture("start-\(language)")
            audit(app, checks, "the Start screen in \(language)")

            settings.tap()
            // A loaded simulator can lose a tap, as StartUITests'
            // openSettings allows for: one more tap when Settings has not
            // opened, written down in the log and the test's activities
            // with the screen as it was, so that a failure shows what the
            // tap met.
            let bar = app.navigationBars[tr("Settings", language)]
            if !bar.waitForExistence(timeout: 10) {
                lostTap(app, on: settings, "Settings in \(language)")
            }
            XCTAssertTrue(bar.waitForExistence(timeout: 10), "\(language): Settings did not open")
            XCTAssertTrue(app.buttons[tr("Blueprint", language)].exists, "\(language): the colours are not translated")
            picture("settings-\(language)")
            audit(app, checks, "Settings in \(language)")
            app.terminate()
        }
    }

    /// Every text on the screen with a label and its height, from one
    /// snapshot of the app; a text the window does not hold whole is left
    /// out.
    private func textHeights(_ app: XCUIApplication) -> [String: CGFloat] {
        var heights: [String: CGFloat] = [:]
        guard let root = try? app.snapshot() else {
            XCTFail("no snapshot of the app")
            return heights
        }
        let window = app.windows.firstMatch.frame
        var stack = [root]
        while let e = stack.popLast() {
            if e.elementType == .staticText, !e.label.isEmpty, window.contains(e.frame) {
                heights[e.label] = max(heights[e.label] ?? 0, e.frame.height)
            }
            stack.append(contentsOf: e.children)
        }
        return heights
    }

    /// The screens follow the text size: every text seen at the default
    /// size and at the largest is at least half as tall again at the
    /// largest. Xcode's own dynamic type audit is not used for this: on
    /// SwiftUI's text it judges by a UIKit property the text does not
    /// always show, and on CI's runner it reported texts that grow at every
    /// size (Settings' Notifications header, at random, and a theme's
    /// name, always, after a change that moved nothing on the screen). In
    /// the same runs every text of Settings grew 1.7 times or more, and a
    /// text of a fixed size, put there to be caught, 1.1 times.
    private func assertGrows(_ small: [String: CGFloat], _ large: [String: CGFloat], _ screen: String) {
        let both = large.keys.filter { (small[$0] ?? 0) > 0 }
        XCTAssertGreaterThanOrEqual(both.count, 2, "\(screen): too few texts seen at both sizes to tell")
        for label in both.sorted() where large[label]! < small[label]! * 1.5 {
            XCTFail("\(screen): '\(label)' is \(small[label]!) high at the default text size and only \(large[label]!) at the largest")
        }
    }

    /// U16: at the largest accessibility text size, in English, in
    /// Swahili, among the longest of the eight, and in Hindi, the tallest
    /// script, no text is clipped and the screens follow the text size
    /// (`assertGrows`).
    func testLargestText() {
        for language in Self.largestText {
            // The texts' heights at the default size first.
            var app = launch(language: language, extra: ["-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryL"])
            XCTAssertTrue(app.buttons[tr("Create a group", language)].waitForExistence(timeout: 30))
            app.settle("the Start screen in \(language) at the default text size")
            let start = textHeights(app)
            app.buttons[tr("Settings", language)].tap()
            XCTAssertTrue(app.navigationBars[tr("Settings", language)].waitForExistence(timeout: 10))
            app.settle("Settings in \(language) at the default text size")
            let settings = textHeights(app)
            app.terminate()

            app = launch(language: language, extra: ["-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL"])
            XCTAssertTrue(app.buttons[tr("Create a group", language)].waitForExistence(timeout: 30))
            picture("start-\(language)-largest-text")
            audit(app, .textClipped, "the Start screen in \(language) at the largest text")
            assertGrows(start, textHeights(app), "the Start screen in \(language)")
            app.buttons[tr("Settings", language)].tap()
            XCTAssertTrue(app.navigationBars[tr("Settings", language)].waitForExistence(timeout: 10))
            picture("settings-\(language)-largest-text")
            audit(app, .textClipped, "Settings in \(language) at the largest text")
            assertGrows(settings, textHeights(app), "Settings in \(language)")
            app.terminate()
        }
    }
}
