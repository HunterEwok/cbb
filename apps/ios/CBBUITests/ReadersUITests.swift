// SPDX-License-Identifier: AGPL-3.0-only

import XCTest

/// The app in each of the project's eight languages and for every reader
/// (docs/testbench-catalogue.md, A9, U14, U16; docs/testing.md, "The apps'
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
        let a = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        a.name = name
        a.lifetime = .keepAlways
        add(a)
    }

    /// Waits until the screen has stopped changing: its element tree, every
    /// element's frame and text, the same in three snapshots in a row a
    /// third of a second apart. A screen still laying out or animating in
    /// gives the audit a picture of nothing a person sees, so a screen that
    /// does not settle in 20 seconds fails rather than being audited.
    private func settle(_ app: XCUIApplication, _ screen: String) {
        // The tree's lines name each element by an address that can change
        // between snapshots of the same element.
        let address = try! NSRegularExpression(pattern: "0x[0-9a-fA-F]+")
        func tree() -> String {
            let d = app.debugDescription
            return address.stringByReplacingMatches(in: d, range: NSRange(d.startIndex..., in: d), withTemplate: "")
        }
        let start = Date()
        let deadline = start.addingTimeInterval(20)
        var last = tree()
        var same = 0
        while Date() < deadline {
            Thread.sleep(forTimeInterval: 0.33)
            let now = tree()
            if now == last {
                same += 1
                if same == 2 {
                    print("ReadersUITests: \(screen) settled in \(String(format: "%.1f", Date().timeIntervalSince(start))) s")
                    return
                }
            } else {
                same = 0
                last = now
            }
        }
        XCTFail("\(screen): the screen was still changing after 20 seconds")
    }

    /// Runs Xcode's accessibility audit on the screen once it has settled
    /// (`settle`), on what a person can reach. Only an
    /// element of the system's own may fail it: the status bar, and the
    /// navigation bar's buttons, whose text iOS keeps from the largest
    /// sizes. Contrast is measured on the screen's picture (`contrast`).
    private func audit(_ app: XCUIApplication, _ types: XCUIAccessibilityAuditType, _ screen: String) {
        settle(app, screen)
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
                if issue.auditType == .dynamicType && app.navigationBars.firstMatch.exists && app.navigationBars.firstMatch.frame.contains(e.frame) { return true }
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

    /// U16: at the largest accessibility text size, in English, in
    /// Swahili, among the longest of the eight, and in Hindi, the tallest
    /// script, no text is clipped and the screens follow Dynamic Type.
    func testLargestText() {
        for language in Self.largestText {
            let app = launch(language: language, extra: ["-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL"])
            XCTAssertTrue(app.buttons[tr("Create a group", language)].waitForExistence(timeout: 30))
            picture("start-\(language)-largest-text")
            audit(app, [.textClipped, .dynamicType], "the Start screen in \(language) at the largest text")
            app.buttons[tr("Settings", language)].tap()
            XCTAssertTrue(app.navigationBars[tr("Settings", language)].waitForExistence(timeout: 10))
            picture("settings-\(language)-largest-text")
            audit(app, [.textClipped, .dynamicType], "Settings in \(language) at the largest text")
            app.terminate()
        }
    }

    // MARK: A measurement of CI's runner, not to be merged

    private struct Variant {
        let name: String
        var args: [String] = []
        var language = "en"
        var size = "UICTContentSizeCategoryAccessibilityXXXL"
        var types: XCUIAccessibilityAuditType = .dynamicType
        var middle = false
        var repeats = 1
        var pause: TimeInterval = 0
        var dark = false
        var landscape = false
    }

    private var probeStats: [String: (audits: Int, notifications: Int, labels: [String: Int])] = [:]
    private var probeOrder: [String] = []

    /// The app's element tree without the addresses its lines name each
    /// element by, which can change between snapshots of the same element.
    private func plainTree(_ app: XCUIApplication) -> String {
        let address = try! NSRegularExpression(pattern: "0x[0-9a-fA-F]+")
        let d = app.debugDescription
        return address.stringByReplacingMatches(in: d, range: NSRange(d.startIndex..., in: d), withTemplate: "")
    }

    /// One audit of what is on the screen, every issue printed as a
    /// MEASURE line and counted under the variant; it fails nothing.
    private func probeAudit(_ app: XCUIApplication, _ v: Variant, _ position: String, _ notifications: String, _ round: Int, _ rep: Int) {
        let key = position == "top" ? v.name : "\(v.name), \(position)"
        if probeStats[key] == nil { probeStats[key] = (0, 0, [:]); probeOrder.append(key) }
        settle(app, "MEASURE \(key)")
        if v.pause > 0 { Thread.sleep(forTimeInterval: v.pause) }
        let before = plainTree(app)
        let began = Date()
        var labels: [String] = []
        do {
            try app.performAccessibilityAudit(for: v.types) { issue in
                let at = String(format: "%.1f", Date().timeIntervalSince(began))
                guard let e = issue.element else {
                    labels.append("<no element>")
                    print("MEASURE-ISSUE \(key) round \(round) #\(rep) +\(at)s: \(issue.compactDescription) on no element")
                    return true
                }
                // The navigation bar's own buttons, as testLargestText passes them over.
                if app.navigationBars.firstMatch.exists && app.navigationBars.firstMatch.frame.contains(e.frame) { return true }
                labels.append(e.label)
                print("MEASURE-ISSUE \(key) round \(round) #\(rep) +\(at)s: \(issue.compactDescription) on \(e.elementType.rawValue) '\(e.label)' \(e.frame) hittable \(e.isHittable)")
                return true
            }
        } catch {
            print("MEASURE-ISSUE \(key) round \(round) #\(rep): the audit threw \(error)")
            labels.append("<threw>")
        }
        let took = Date().timeIntervalSince(began)
        let changed = plainTree(app) != before
        var stat = probeStats[key]!
        stat.audits += 1
        if labels.contains(notifications) { stat.notifications += 1 }
        for l in Set(labels) { stat.labels[l, default: 0] += 1 }
        probeStats[key] = stat
        print("MEASURE-AUDIT \(key) round \(round) #\(rep): \(String(format: "%.1f", took)) s, tree \(changed ? "changed" : "unchanged"), flagged \(labels.isEmpty ? "nothing" : labels.joined(separator: " | "))")
    }

    private func probeSummary(_ title: String) {
        print("MEASURE-SUMMARY \(title)")
        for key in probeOrder {
            let s = probeStats[key]!
            let others = s.labels.filter { $0.key != "Notifications" && $0.key != "सूचनाएँ" }.sorted { $0.key < $1.key }.map { "\($0.key)×\($0.value)" }.joined(separator: ", ")
            print("MEASURE-SUMMARY \(key): Notifications \(s.notifications)/\(s.audits); others: \(others.isEmpty ? "-" : others)")
        }
    }

    /// Scrolls the screen's list until the text is near the middle of the
    /// window, with slow drags that do not fling the list.
    private func scrollToMiddle(_ app: XCUIApplication, _ label: String) {
        let text = app.staticTexts[label].firstMatch
        let list = app.collectionViews.firstMatch
        let height = app.windows.firstMatch.frame.height
        for _ in 0..<8 {
            guard text.exists, list.exists else { break }
            let shift = text.frame.midY - height / 2
            if abs(shift) < 100 { break }
            let from = list.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.6))
            let to = from.withOffset(CGVector(dx: 0, dy: -max(-400, min(400, shift))))
            from.press(forDuration: 0.1, thenDragTo: to, withVelocity: .slow, thenHoldForDuration: 0.3)
        }
    }

    /// Runs the dynamic type audit of Settings in many variants of the
    /// screen and of the run, round after round until its time is up, and
    /// prints what each audit flagged.
    func testDynamicTypeProbe() {
        let variants: [Variant] = [
            Variant(name: "baseline", middle: true),
            Variant(name: "baseline hi", language: "hi"),
            Variant(name: "with textClipped", types: [.textClipped, .dynamicType]),
            Variant(name: "refresh off", args: ["-CBBMeasureNoRefresh"]),
            Variant(name: "plain grid", args: ["-CBBMeasurePlainGrid"]),
            Variant(name: "no swatches", args: ["-CBBMeasureNoSwatches"], middle: true),
            Variant(name: "no hair spaces", args: ["-CBBMeasureNoHairSpace"]),
            Variant(name: "no Notifications section", args: ["-CBBMeasureNoNotifications"]),
            Variant(name: "header as a row", args: ["-CBBMeasureHeaderAsRow"]),
            Variant(name: "header without text case", args: ["-CBBMeasureHeaderNoTextCase"]),
            Variant(name: "header with .footnote", args: ["-CBBMeasureHeaderFont"]),
            Variant(name: "plain list style", args: ["-CBBMeasurePlainList"]),
            Variant(name: "no background", args: ["-CBBMeasureNoBackground"]),
            Variant(name: "no animations", args: ["-CBBMeasureNoAnimations"]),
            Variant(name: "no tips", args: ["-CBBMeasureNoTips"]),
            Variant(name: "everything off", args: ["-CBBMeasureNoRefresh", "-CBBMeasureNoAnimations", "-CBBMeasureNoTips", "-CBBMeasureNoSwatches", "-CBBMeasureHeaderNoTextCase"]),
            Variant(name: "size AX-XXL", size: "UICTContentSizeCategoryAccessibilityXXL"),
            Variant(name: "size AX-L", size: "UICTContentSizeCategoryAccessibilityL"),
            Variant(name: "size Large (default)", size: "UICTContentSizeCategoryL"),
            Variant(name: "dark", dark: true),
            Variant(name: "landscape", landscape: true),
            Variant(name: "5 s idle before", pause: 5),
            Variant(name: "3 audits in a row", repeats: 3),
        ]
        let start = Date()
        let budget: TimeInterval = 40 * 60
        var round = 0
        rounds: while true {
            round += 1
            for v in variants {
                if Date().timeIntervalSince(start) > budget - 90 { break rounds }
                if v.dark { XCUIDevice.shared.appearance = .dark }
                if v.landscape { XCUIDevice.shared.orientation = .landscapeLeft }
                let app = launch(language: v.language, extra: ["-UIPreferredContentSizeCategoryName", v.size] + v.args)
                let settings = app.buttons[tr("Settings", v.language)]
                if settings.waitForExistence(timeout: 30) {
                    settings.tap()
                    if app.navigationBars[tr("Settings", v.language)].waitForExistence(timeout: 10) {
                        let notifications = tr("Notifications", v.language)
                        for rep in 1...v.repeats { probeAudit(app, v, "top", notifications, round, rep) }
                        if v.middle {
                            scrollToMiddle(app, notifications)
                            probeAudit(app, v, "Notifications in the middle", notifications, round, 1)
                        }
                    } else {
                        print("MEASURE \(v.name): Settings did not open")
                    }
                } else {
                    print("MEASURE \(v.name): no Settings button")
                }
                app.terminate()
                if v.dark { XCUIDevice.shared.appearance = .light }
                if v.landscape { XCUIDevice.shared.orientation = .portrait }
                print("MEASURE-PROGRESS round \(round), \(v.name) done at \(Int(Date().timeIntervalSince(start))) s")
            }
            probeSummary("after round \(round)")
        }
        probeSummary("final, \(round) rounds begun, \(Int(Date().timeIntervalSince(start))) s")
    }
}
