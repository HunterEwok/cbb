// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// Picks the screen and applies the theme and the language.
struct RootView: View {
    @EnvironmentObject private var model: AppModel
    @AppStorage(ThemeChoice.key) private var theme = Tokens.themes[0].name
    @AppStorage(Appearance.key) private var appearance = Appearance.system
    @AppStorage(LanguageChoice.key) private var language = LanguageChoice.system
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        let palette = appearance.palette(theme, for: scheme)
        ZStack {
            AppBackground()
            switch model.phase {
            case .start: StartView()
            case .joining: JoinView()
            case .home: HomeView()
            }
        }
        .environment(\.palette, palette)
        .environment(\.themeStyle, ThemeChoice.theme(theme).style)
        .environment(\.locale, language.locale ?? .autoupdatingCurrent)
        .environment(\.layoutDirection, language.layoutDirection)
        .tint(palette.accent)
        .foregroundStyle(palette.text)
        .preferredColorScheme(appearance.scheme)
    }
}
