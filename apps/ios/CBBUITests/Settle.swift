// SPDX-License-Identifier: AGPL-3.0-only

import XCTest

extension XCUIApplication {
    /// Waits until the screen stands still: the element tree the same in
    /// three snapshots a third of a second apart. XCTest waits for the app
    /// to be idle before each action, and a tap for its element to exist,
    /// but not for an animation to end or the keyboard's focus to land; an
    /// action that aims at no element (a key, an audit, a picture) comes
    /// after this, as a person acts on what they see. `screen` names it in
    /// the log and in a failure.
    func settle(_ screen: String, file: StaticString = #filePath, line: UInt = #line) {
        // The tree's lines name each element by an address that can change
        // between snapshots of the same element.
        let address = try! NSRegularExpression(pattern: "0x[0-9a-fA-F]+")
        func tree() -> String {
            let d = debugDescription
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
                    print("settle: \(screen) settled in \(String(format: "%.1f", Date().timeIntervalSince(start))) s")
                    return
                }
            } else {
                same = 0
                last = now
            }
        }
        XCTFail("\(screen): the screen was still changing after 20 seconds", file: file, line: line)
    }
}
