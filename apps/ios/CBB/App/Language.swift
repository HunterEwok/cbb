// SPDX-License-Identifier: AGPL-3.0-only

import Foundation
import SwiftUI

/// The language the user picks on the Start screen or in Settings; System
/// follows the system's (and the per-app choice in the system's Settings).
enum LanguageChoice: String, CaseIterable, Identifiable {
    case system
    case en
    case zh = "zh-Hans"
    case es
    case ru
    case ar
    case sw
    case he
    case hi

    static let key = "language"

    var id: String { rawValue }

    /// The languages the app is translated into, without System.
    static let translations = allCases.filter { $0 != .system }

    /// The choice stored in defaults, System when there is none.
    static func current(_ defaults: UserDefaults = .standard) -> LanguageChoice {
        defaults.string(forKey: key).flatMap(LanguageChoice.init(rawValue:)) ?? .system
    }

    /// The locale the views use, nil for System.
    var locale: Locale? { self == .system ? nil : Locale(identifier: rawValue) }

    /// Right to left for Arabic and Hebrew; System keeps the system's.
    var layoutDirection: LayoutDirection {
        let code = (locale ?? .autoupdatingCurrent).language.languageCode?.identifier ?? ""
        return Locale.Language(identifier: code).characterDirection == .rightToLeft ? .rightToLeft : .leftToRight
    }

    /// Each language by its own name ("English", "Russian" in Russian), so
    /// that it can be found whichever language the app shows now.
    var title: String {
        guard let locale else { return String(localized: "System", bundle: .app) }
        let name = locale.localizedString(forLanguageCode: rawValue) ?? rawValue
        return name.prefix(1).uppercased(with: locale) + name.dropFirst()
    }

    /// The bundle that strings come from: the chosen language's, or the
    /// app's own, which follows the system.
    var bundle: Bundle {
        guard self != .system else { return .main }
        guard let path = Bundle.main.path(forResource: rawValue, ofType: "lproj"), let bundle = Bundle(path: path) else {
            // English is the source language, so the app has no en.lproj;
            // a bundle without strings returns each key, its English text.
            return Self.untranslated
        }
        return bundle
    }

    private static let untranslated = Bundle(path: NSTemporaryDirectory()) ?? .main
}

extension Bundle {
    /// The bundle for String(localized:bundle:), so that the strings the
    /// model makes follow the language chosen in the app as the views do.
    static var app: Bundle { LanguageChoice.current().bundle }
}
