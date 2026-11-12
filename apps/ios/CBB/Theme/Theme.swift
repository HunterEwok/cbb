// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// One theme's colours for the dark or the light appearance
/// (apps/design/tokens.json; Tokens.swift is generated from it).
struct Palette: Equatable {
    let dark: Bool
    let background: Color
    let surface: Color
    let grid: Color
    /// The theme's lines: borders, dividers and the outline of what is off.
    let line: Color
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
}

/// What a theme's surfaces are made of.
enum ThemeMaterial: Equatable {
    case flat, glass, liquid, metal

    /// Whether the theme's tiles are glass: Liquid Glass from iOS 26.
    var isGlass: Bool { self == .glass || self == .liquid }
}

/// Which corners a shape takes from the theme.
enum Corner: Equatable {
    case button, card, tile, chip
    /// Corners of their own, as the orbit's bubbles.
    case fixed(CGFloat)
}

/// What a theme draws besides its colours: the faces, the corners, the
/// width of its lines (0: none), its material, whether large surfaces show
/// a grid, whether something off or waiting is dashed and whether small
/// labels are in capitals. The system's own controls keep the system's look.
struct ThemeStyle: Equatable {
    let display: String
    let body: String
    let mono: String
    let radiusButton: CGFloat
    let radiusCard: CGFloat
    let radiusTile: CGFloat
    let radiusChip: CGFloat
    let stroke: CGFloat
    let material: ThemeMaterial
    let grid: Bool
    let dashedOff: Bool
    let upperLabels: Bool

    func radius(_ corner: Corner) -> CGFloat {
        switch corner {
        case .button: radiusButton
        case .card: radiusCard
        case .tile: radiusTile
        case .chip: radiusChip
        case .fixed(let r): r
        }
    }
}

/// One of the themes the user picks in Settings: its style and its
/// palettes for the dark and the light appearance.
struct Theme {
    let name: String
    let style: ThemeStyle
    let dark: Palette
    let light: Palette
}

/// The theme the user picks in Settings, one of Tokens.themes by its name;
/// Chalkboard, the first, by default.
enum ThemeChoice {
    static let key = "theme"

    static func theme(_ name: String) -> Theme {
        Tokens.themes.first { $0.name == name } ?? Tokens.themes[0]
    }

    static func title(_ name: String) -> LocalizedStringKey {
        switch name {
        case "board": "Chalkboard"
        case "blueprint": "Blueprint"
        case "precise": "Precise"
        case "glass": "Glass"
        case "soft": "Soft"
        case "swiss": "Swiss"
        case "hardware": "Hardware"
        case "deco": "Art Deco"
        case "liquid": "Liquid Glass"
        case "terminal": "Terminal"
        case "retro": "Retro"
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

    func palette(_ theme: String, for scheme: ColorScheme) -> Palette {
        let t = ThemeChoice.theme(theme)
        return (self.scheme ?? scheme) == .dark ? t.dark : t.light
    }
}

private struct PaletteKey: EnvironmentKey {
    static let defaultValue = Tokens.themes[0].dark
}

private struct ThemeStyleKey: EnvironmentKey {
    static let defaultValue = Tokens.themes[0].style
}

extension EnvironmentValues {
    var palette: Palette {
        get { self[PaletteKey.self] }
        set { self[PaletteKey.self] = newValue }
    }

    /// The chosen theme's style: corners, lines, material.
    var themeStyle: ThemeStyle {
        get { self[ThemeStyleKey.self] }
        set { self[ThemeStyleKey.self] = newValue }
    }
}

/// The background: the theme's colour, with a grid as on a drawing sheet
/// where the theme has one, or a glow of the accent from the top under
/// glass.
struct AppBackground: View {
    @Environment(\.palette) private var palette
    @Environment(\.themeStyle) private var style

    var body: some View {
        palette.background
            .overlay {
                if style.grid {
                    Canvas { context, size in
                        var path = Path()
                        for x in stride(from: 0, through: size.width, by: 24) {
                            path.move(to: CGPoint(x: x, y: 0))
                            path.addLine(to: CGPoint(x: x, y: size.height))
                        }
                        for y in stride(from: 0, through: size.height, by: 24) {
                            path.move(to: CGPoint(x: 0, y: y))
                            path.addLine(to: CGPoint(x: size.width, y: y))
                        }
                        context.stroke(path, with: .color(palette.grid), lineWidth: 1)
                    }
                }
            }
            .overlay(alignment: .top) {
                if style.material.isGlass {
                    RadialGradient(colors: [palette.soft, .clear], center: .top, startRadius: 0, endRadius: 520)
                        .frame(height: 640)
                }
            }
            .ignoresSafeArea()
            .accessibilityHidden(true)
    }
}

/// The one big button style: generous, the accent colour, with the
/// theme's corners; Liquid Glass tinted with it from iOS 26 in the glass
/// themes.
struct AccentButtonStyle: ButtonStyle {
    @Environment(\.palette) private var palette
    @Environment(\.themeStyle) private var style
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        let shape = RoundedRectangle(cornerRadius: style.radiusButton, style: .continuous)
        let label = configuration.label
            .font(.title3.weight(.semibold))
            .frame(maxWidth: .infinity, minHeight: 64)
            .foregroundStyle(palette.onAccent)
            .opacity(isEnabled ? 1 : 0.5)
        #if compiler(>=6.2)
        if #available(iOS 26, watchOS 26, macOS 26, *), style.material.isGlass {
            return AnyView(label.glassEffect(.regular.tint(palette.accent.opacity(isEnabled ? 1 : 0.4)).interactive(), in: shape))
        }
        #endif
        return AnyView(label.background(palette.accent.opacity(isEnabled ? (configuration.isPressed ? 0.8 : 1) : 0.4), in: shape))
    }
}

/// The quieter button next to the big one: clear glass from iOS 26 in the
/// glass themes, a material before; the theme's surface and line in the
/// others.
struct GlassButtonStyle: ButtonStyle {
    @Environment(\.palette) private var palette
    @Environment(\.themeStyle) private var style

    func makeBody(configuration: Configuration) -> some View {
        let shape = RoundedRectangle(cornerRadius: style.radiusButton, style: .continuous)
        let label = configuration.label
            .font(.body.weight(.medium))
            .multilineTextAlignment(.center)
            .frame(maxWidth: .infinity, minHeight: 52)
            .padding(.horizontal, Tokens.spacingMedium)
            .foregroundStyle(palette.accent)
        guard style.material.isGlass else {
            return AnyView(label
                .background(palette.surface.opacity(configuration.isPressed ? 0.7 : 1), in: shape)
                .overlay(shape.stroke(palette.line, lineWidth: style.stroke)))
        }
        #if compiler(>=6.2)
        if #available(iOS 26, watchOS 26, macOS 26, *) {
            return AnyView(label.glassEffect(.regular.interactive(), in: shape))
        }
        #endif
        return AnyView(label.background(.ultraThinMaterial.opacity(configuration.isPressed ? 0.6 : 1), in: shape))
    }
}

/// A tile, a row or a card of the device pages: in the glass themes Liquid
/// Glass from iOS 26, the palette's glass with a hairline before; in the
/// others the theme's surface with its line.
struct GlassTile: ViewModifier {
    @Environment(\.palette) private var palette
    @Environment(\.themeStyle) private var style
    var corner: Corner = .tile

    @ViewBuilder func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: style.radius(corner), style: .continuous)
        if style.material.isGlass {
            #if compiler(>=6.2)
            if #available(iOS 26, watchOS 26, macOS 26, *) {
                content.glassEffect(.regular.tint(palette.glass), in: shape)
            } else {
                content.background(palette.glass, in: shape).overlay(shape.stroke(palette.line))
            }
            #else
            content.background(palette.glass, in: shape).overlay(shape.stroke(palette.line))
            #endif
        } else {
            content.background(palette.surface, in: shape).overlay(shape.stroke(palette.line, lineWidth: style.stroke))
        }
    }
}

/// A card or a field: in the glass themes Liquid Glass from iOS 26, a
/// material before; in the others the theme's surface with its line.
struct GlassCard: ViewModifier {
    @Environment(\.palette) private var palette
    @Environment(\.themeStyle) private var style

    @ViewBuilder func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: style.radiusCard, style: .continuous)
        if style.material.isGlass {
            #if compiler(>=6.2)
            if #available(iOS 26, watchOS 26, macOS 26, *) {
                content.glassEffect(.regular, in: shape)
            } else {
                content.background(.ultraThinMaterial, in: shape)
            }
            #else
            content.background(.ultraThinMaterial, in: shape)
            #endif
        } else {
            content.background(palette.surface, in: shape).overlay(shape.stroke(palette.line, lineWidth: style.stroke))
        }
    }
}

/// A round button for an icon: glass as the toolbars draw it from iOS 26,
/// whatever the theme, for the system's own controls stay the system's.
struct GlassCircle: ViewModifier {
    @ViewBuilder func body(content: Content) -> some View {
        #if compiler(>=6.2)
        if #available(iOS 26, watchOS 26, macOS 26, *) {
            content.frame(width: 44, height: 44).glassEffect(.regular.interactive(), in: Circle())
        } else {
            content.frame(width: 44, height: 44).background(.ultraThinMaterial, in: Circle())
        }
        #else
        content.frame(width: 44, height: 44).background(.ultraThinMaterial, in: Circle())
        #endif
    }
}

/// A theme as a round swatch: its background, with its accent across the
/// lower half.
struct ThemeSwatch: View {
    let palette: Palette

    var body: some View {
        Circle()
            .fill(LinearGradient(stops: [.init(color: palette.background, location: 0.5), .init(color: palette.accent, location: 0.5)],
                                 startPoint: .topLeading, endPoint: .bottomTrailing))
    }
}

extension View {
    func glassTile(_ corner: Corner = .tile) -> some View {
        modifier(GlassTile(corner: corner))
    }

    func glassCard() -> some View {
        modifier(GlassCard())
    }

    func glassCircle() -> some View {
        modifier(GlassCircle())
    }
}
