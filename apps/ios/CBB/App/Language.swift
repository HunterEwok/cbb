// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// The language the user picks on the Start screen or in Settings; System
/// follows the system's (and the per-app choice in the system's Settings).
enum LanguageChoice: String, CaseIterable, Identifiable {
    case system
    case en
    case ru

    static let key = "language"

    var id: String { rawValue }

    /// The languages the app is translated into, without System.
    static let translations = allCases.filter { $0 != .system }

    /// The choice stored in defaults, System when there is none.
    static func current(_ defaults: UserDefaults = .standard) -> LanguageChoice {
        defaults.string(forKey: key).flatMap(LanguageChoice.init(rawValue:)) ?? .system
    }

    /// Whether the Start screen offers the language: only when the app has
    /// no translation for the language the system prefers (it shows English
    /// then). Settings always offers it.
    static func offeredOnStart(preferred: [String], localizations: [String]) -> Bool {
        guard let first = preferred.first else { return false }
        let supported = Set(localizations.filter { $0 != "Base" }.map(languageCode))
        return !supported.contains(languageCode(first))
    }

    /// "pt" from "pt-BR" or "pt_BR".
    private static func languageCode(_ id: String) -> String {
        Locale(identifier: id).language.languageCode?.identifier ?? id
    }

    /// The locale the views use, nil for System.
    var locale: Locale? { self == .system ? nil : Locale(identifier: rawValue) }

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
