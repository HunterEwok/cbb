// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// One theme's colours (apps/design/tokens.json; Tokens.swift is generated
/// from it).
struct Palette: Equatable {
    let dark: Bool
    let background: Color
    let surface: Color
    let grid: Color
    let text: Color
    let textDim: Color
    let accent: Color
    let onAccent: Color
    let danger: Color
}

extension Color {
    /// A colour from 0xRRGGBB.
    init(rgb: UInt32) {
        self.init(red: Double(rgb >> 16 & 0xff) / 255, green: Double(rgb >> 8 & 0xff) / 255, blue: Double(rgb & 0xff) / 255)
    }
}

extension Palette {
    /// A card's or a tile's glass over the background.
    var glass: Color { dark ? surface.opacity(0.78) : Color.white.opacity(0.86) }
    /// A faint wash of the accent, behind an icon or under the glow.
    var soft: Color { accent.opacity(dark ? 0.16 : 0.10) }
    /// A hairline around glass.
    var line: Color { text.opacity(dark ? 0.12 : 0.10) }
}

/// One accent colour's palettes for the dark and the light appearance.
struct PalettePair {
    let name: String
    let dark: Palette
    let light: Palette
}

/// The colour the user picks in Settings, one of Tokens.colors by its name;
/// Terminal, the first, by default.
enum AccentChoice {
    static let key = "color"

    static func pair(_ name: String) -> PalettePair {
        Tokens.colors.first { $0.name == name } ?? Tokens.colors[0]
    }

    static func title(_ name: String) -> LocalizedStringKey {
        switch name {
        case "terminal": "Terminal"
        case "midnight": "Midnight"
        case "amber": "Amber"
        case "ocean": "Ocean"
        case "teal": "Teal"
        case "coral": "Coral"
        case "rose": "Rose"
        case "lime": "Lime"
        case "graphite": "Graphite"
        case "ruby": "Ruby"
        default: LocalizedStringKey(name)
        }
    }
}

/// Light or dark, or as the system has it.
enum Appearance: String, CaseIterable, Identifiable {
    static let key = "appearance"

    case system, dark, light

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .system: "System"
        case .dark: "Dark"
        case .light: "Light"
        }
    }

    var scheme: ColorScheme? {
        switch self {
        case .system: nil
        case .dark: .dark
        case .light: .light
        }
    }

    func palette(_ color: String, for scheme: ColorScheme) -> Palette {
        let pair = AccentChoice.pair(color)
        return (self.scheme ?? scheme) == .dark ? pair.dark : pair.light
    }
}

private struct PaletteKey: EnvironmentKey {
    static let defaultValue = Tokens.colors[0].dark
}

extension EnvironmentValues {
    var palette: Palette {
        get { self[PaletteKey.self] }
        set { self[PaletteKey.self] = newValue }
    }
}

/// The background: the deep colour with a glow of the accent from the top.
struct AppBackground: View {
    @Environment(\.palette) private var palette

    var body: some View {
        palette.background
            .overlay(alignment: .top) {
                RadialGradient(colors: [palette.soft, .clear], center: .top, startRadius: 0, endRadius: 520)
                    .frame(height: 640)
            }
            .ignoresSafeArea()
            .accessibilityHidden(true)
    }
}

/// The one big button style: rounded, generous, the accent colour; Liquid
/// Glass tinted with it from iOS 26.
struct AccentButtonStyle: ButtonStyle {
    @Environment(\.palette) private var palette
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        let shape = RoundedRectangle(cornerRadius: Tokens.radiusButton, style: .continuous)
        let label = configuration.label
            .font(.title3.weight(.semibold))
            .frame(maxWidth: .infinity, minHeight: 64)
            .foregroundStyle(palette.onAccent)
            .opacity(isEnabled ? 1 : 0.5)
        #if compiler(>=6.2)
        if #available(iOS 26, watchOS 26, macOS 26, *) {
            return AnyView(label.glassEffect(.regular.tint(palette.accent.opacity(isEnabled ? 1 : 0.4)).interactive(), in: shape))
        }
        #endif
        return AnyView(label.background(palette.accent.opacity(isEnabled ? (configuration.isPressed ? 0.8 : 1) : 0.4), in: shape))
    }
}

/// The quieter button next to the big one: clear glass from iOS 26, the
/// accent colour on a material before.
struct GlassButtonStyle: ButtonStyle {
    @Environment(\.palette) private var palette

    func makeBody(configuration: Configuration) -> some View {
        let shape = RoundedRectangle(cornerRadius: Tokens.radiusButton, style: .continuous)
        let label = configuration.label
            .font(.body.weight(.medium))
            .multilineTextAlignment(.center)
            .frame(maxWidth: .infinity, minHeight: 52)
            .padding(.horizontal, Tokens.spacingMedium)
            .foregroundStyle(palette.accent)
        #if compiler(>=6.2)
        if #available(iOS 26, watchOS 26, macOS 26, *) {
            return AnyView(label.glassEffect(.regular.interactive(), in: shape))
        }
        #endif
        return AnyView(label.background(.ultraThinMaterial.opacity(configuration.isPressed ? 0.6 : 1), in: shape))
    }
}

/// A tile, a row or a card of the device pages: Liquid Glass from iOS 26,
/// the palette's glass with a hairline before.
struct GlassTile: ViewModifier {
    @Environment(\.palette) private var palette
    var cornerRadius: CGFloat = Tokens.radiusTile

    @ViewBuilder func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        #if compiler(>=6.2)
        if #available(iOS 26, watchOS 26, macOS 26, *) {
            content.glassEffect(.regular.tint(palette.glass), in: shape)
        } else {
            content.background(palette.glass, in: shape).overlay(shape.stroke(palette.line))
        }
        #else
        content.background(palette.glass, in: shape).overlay(shape.stroke(palette.line))
        #endif
    }
}

extension View {
    func glassTile(cornerRadius: CGFloat = Tokens.radiusTile) -> some View {
        modifier(GlassTile(cornerRadius: cornerRadius))
    }

    /// A card or a field on glass: Liquid Glass from iOS 26, a material
    /// before.
    @ViewBuilder func glassCard(cornerRadius: CGFloat = Tokens.radiusCard) -> some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        #if compiler(>=6.2)
        if #available(iOS 26, watchOS 26, macOS 26, *) {
            glassEffect(.regular, in: shape)
        } else {
            background(.ultraThinMaterial, in: shape)
        }
        #else
        background(.ultraThinMaterial, in: shape)
        #endif
    }

    /// A round glass button for an icon, as the toolbars draw them from
    /// iOS 26.
    @ViewBuilder func glassCircle() -> some View {
        #if compiler(>=6.2)
        if #available(iOS 26, watchOS 26, macOS 26, *) {
            frame(width: 44, height: 44).glassEffect(.regular.interactive(), in: Circle())
        } else {
            frame(width: 44, height: 44).background(.ultraThinMaterial, in: Circle())
        }
        #else
        frame(width: 44, height: 44).background(.ultraThinMaterial, in: Circle())
        #endif
    }
}

extension Tokens {
    /// The widest a column of text and buttons stands on a big screen, as
    /// on the widest phone: the Start and Join screens.
    static let readableWidth: CGFloat = 560
}
