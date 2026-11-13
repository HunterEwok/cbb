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

    /// Every text on the screen that has a label, with its height, from
    /// one snapshot of the app.
    private func textHeights(_ app: XCUIApplication) -> [String: CGFloat] {
        var out: [String: CGFloat] = [:]
        guard let root = try? app.snapshot() else { return out }
        var stack: [XCUIElementSnapshot] = [root]
        let window = app.windows.firstMatch.frame
        while let e = stack.popLast() {
            if e.elementType == .staticText, !e.label.isEmpty, window.contains(e.frame) {
                out[e.label] = max(out[e.label] ?? 0, e.frame.height)
            }
            stack.append(contentsOf: e.children)
        }
        return out
    }

    /// Settings' texts' heights at a text size.
    private func settingsHeights(_ language: String, _ size: String, _ args: [String] = []) -> [String: CGFloat] {
        let app = launch(language: language, extra: ["-UIPreferredContentSizeCategoryName", size] + args)
        defer { app.terminate() }
        let settings = app.buttons[tr("Settings", language)]
        guard settings.waitForExistence(timeout: 30) else { return [:] }
        settings.tap()
        guard app.navigationBars[tr("Settings", language)].waitForExistence(timeout: 10) else { return [:] }
        settle(app, "MEASURE heights \(language) \(size)")
        return textHeights(app)
    }

    /// The candidate check of our own: every text of Settings seen at the
    /// default size and at the largest is taller at the largest.
    private func growth(_ language: String, _ round: Int, control: Bool = false) -> [String: CGFloat] {
        let args = control ? ["-CBBMeasureFixedText"] : []
        let small = settingsHeights(language, "UICTContentSizeCategoryL", args)
        let large = settingsHeights(language, "UICTContentSizeCategoryAccessibilityXXXL", args)
        var ratios: [String: CGFloat] = [:]
        for (label, h) in large { if let s = small[label], s > 0 { ratios[label] = h / s } }
        let sorted = ratios.sorted { $0.value < $1.value }
        let low = sorted.filter { $0.value < 1.5 }.map { "'\($0.key)' ×\(String(format: "%.2f", $0.value))" }
        print("MEASURE-GROWTH \(language) round \(round): \(ratios.count) texts in both, least ×\(String(format: "%.2f", sorted.first?.value ?? 0)), most ×\(String(format: "%.2f", sorted.last?.value ?? 0)), under ×1.5: \(low.isEmpty ? "none" : low.joined(separator: ", "))")
        for (label, r) in sorted { print("MEASURE-GROWTH-TEXT \(language) round \(round): '\(label)' \(String(format: "%.1f", small[label] ?? 0)) -> \(String(format: "%.1f", large[label] ?? 0)) ×\(String(format: "%.2f", r))") }
        let key = "own check: every text grows ×1.5 (\(language))\(control ? ", with the fixed text" : "")"
        if probeStats[key] == nil { probeStats[key] = (0, 0, [:]); probeOrder.append(key) }
        var stat = probeStats[key]!
        stat.audits += 1
        if !low.isEmpty || ratios.isEmpty { stat.notifications += 1; for l in low { stat.labels[l, default: 0] += 1 } }
        probeStats[key] = stat
        return ratios
    }

    /// Runs the candidate ways round the audit's false reports on Settings,
    /// round after round until its time is up: the audit at smaller text
    /// sizes, textClipped alone, the audit twice with only issues in both
    /// counted, our own check of the texts' growth, the audit's issues
    /// cross-checked with that growth, and three changes to the app.
    func testDynamicTypeProbe() {
        let xxxl = "UICTContentSizeCategoryAccessibilityXXXL"
        let start = Date()
        let budget: TimeInterval = 40 * 60
        var round = 0
        func left() -> Bool { Date().timeIntervalSince(start) < budget - 120 }
        func onSettings(_ v: Variant, _ body: (XCUIApplication, String) -> Void) {
            if v.landscape { XCUIDevice.shared.orientation = .landscapeLeft }
            let app = launch(language: v.language, extra: ["-UIPreferredContentSizeCategoryName", v.size] + v.args)
            let settings = app.buttons[tr("Settings", v.language)]
            if settings.waitForExistence(timeout: 30) {
                settings.tap()
                if app.navigationBars[tr("Settings", v.language)].waitForExistence(timeout: 10) {
                    body(app, tr("Notifications", v.language))
                } else { print("MEASURE \(v.name): Settings did not open") }
            } else { print("MEASURE \(v.name): no Settings button") }
            app.terminate()
            if v.landscape { XCUIDevice.shared.orientation = .portrait }
            print("MEASURE-PROGRESS round \(round), \(v.name) done at \(Int(Date().timeIntervalSince(start))) s")
        }
        rounds: while left() {
            round += 1
            // Our own check first: the heights it finds also judge the
            // audit's issues below.
            let ratios = growth("en", round)
            _ = growth("hi", round)
            _ = growth("en", round, control: true)
            let singles: [Variant] = [
                Variant(name: "audit at the default size", size: "UICTContentSizeCategoryL"),
                Variant(name: "audit at the default size (hi)", language: "hi", size: "UICTContentSizeCategoryL"),
                Variant(name: "audit at AX-L", size: "UICTContentSizeCategoryAccessibilityL"),
                Variant(name: "textClipped alone at the largest", size: xxxl, types: .textClipped),
                Variant(name: "fix: no hair spaces", args: ["-CBBMeasureNoHairSpace"], size: xxxl),
                Variant(name: "fix: header without text case", args: ["-CBBMeasureHeaderNoTextCase"], size: xxxl),
                Variant(name: "fix: header with .footnote", args: ["-CBBMeasureHeaderFont"], size: xxxl),
                // The positive control: each of these must report the
                // fixed text, or it checks nothing.
                Variant(name: "control: audit at the default size, fixed text", args: ["-CBBMeasureFixedText"], size: "UICTContentSizeCategoryL"),
                Variant(name: "control: audit at AX-L, fixed text", args: ["-CBBMeasureFixedText"], size: "UICTContentSizeCategoryAccessibilityL"),
                Variant(name: "control: audit at the largest, fixed text", args: ["-CBBMeasureFixedText"], size: xxxl),
            ]
            // The audit as testLargestText runs it, twice in a row: an
            // issue in both is what a retry would still report, and each
            // issue is set against our own heights.
            if !left() { break rounds }
            onSettings(Variant(name: "audit at the largest", size: xxxl)) { app, notifications in
                let first = probeLabels(app, Variant(name: "audit at the largest", size: xxxl), notifications, round, 1)
                let second = probeLabels(app, Variant(name: "audit at the largest", size: xxxl), notifications, round, 2)
                let both = first.intersection(second)
                let key = "retry: only issues in two audits in a row"
                if probeStats[key] == nil { probeStats[key] = (0, 0, [:]); probeOrder.append(key) }
                var stat = probeStats[key]!
                stat.audits += 1
                if both.contains(notifications) { stat.notifications += 1 }
                for l in both { stat.labels[l, default: 0] += 1 }
                probeStats[key] = stat
                print("MEASURE-RETRY round \(round): first \(first.sorted()), second \(second.sorted()), in both \(both.sorted())")
                let cross = "cross-check: issues whose text does not grow ×1.5"
                if probeStats[cross] == nil { probeStats[cross] = (0, 0, [:]); probeOrder.append(cross) }
                var c = probeStats[cross]!
                c.audits += 1
                for l in first.union(second) {
                    let r = ratios[l]
                    print("MEASURE-CROSS round \(round): '\(l)' grows \(r.map { "×" + String(format: "%.2f", $0) } ?? "unknown (not seen at both sizes)")")
                    if r == nil || r! < 1.5 { c.labels[l, default: 0] += 1; if l == notifications { c.notifications += 1 } }
                }
                probeStats[cross] = c
            }
            for v in singles {
                if !left() { break rounds }
                onSettings(v) { app, notifications in _ = probeLabels(app, v, notifications, round, 1) }
            }
            probeSummary("after round \(round)")
        }
        probeSummary("final, \(round) rounds begun, \(Int(Date().timeIntervalSince(start))) s")
    }

    /// probeAudit, returning the labels it flagged.
    private func probeLabels(_ app: XCUIApplication, _ v: Variant, _ notifications: String, _ round: Int, _ rep: Int) -> Set<String> {
        let before = probeStats[v.name]?.labels ?? [:]
        let audits = probeStats[v.name]?.audits ?? 0
        probeAudit(app, v, "top", notifications, round, rep)
        let after = probeStats[v.name]!
        _ = audits
        return Set(after.labels.filter { $0.value > (before[$0.key] ?? 0) }.keys)
    }
}
