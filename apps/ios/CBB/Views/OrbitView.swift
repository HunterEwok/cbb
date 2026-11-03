// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// The devices around this phone, on one or two orbits, for the big
/// screens: an iPad and the inner screen of a foldable iPhone. This phone
/// is the centre and its button syncs; a device opens its details.
struct OrbitView: View {
    let devices: [AppModel.Computer]
    let selected: AppModel.Computer.ID?
    let busy: Bool
    let select: (AppModel.Computer.ID) -> Void
    let sync: () -> Void
    @Environment(\.palette) private var palette

    /// How many devices the inner orbit holds before the outer one starts.
    private static let inner = 6

    var body: some View {
        GeometryReader { geo in
            let side = min(geo.size.width, geo.size.height)
            let center = CGPoint(x: geo.size.width / 2, y: geo.size.height / 2)
            let others = devices.filter { !$0.isSelf }
            let radii = others.count > Self.inner ? [side * 0.28, side * 0.43] : [side * 0.36]
            let spots = Self.spots(count: others.count, radii: radii, center: center)
            ZStack {
                ForEach(radii, id: \.self) { r in
                    Circle().stroke(palette.line, lineWidth: 1).frame(width: r * 2, height: r * 2).position(center)
                }
                Path { p in
                    for (d, spot) in zip(others, spots) where d.online {
                        p.move(to: center)
                        p.addLine(to: spot)
                    }
                }
                .stroke(palette.accent.opacity(0.35), style: StrokeStyle(lineWidth: 1.5, dash: [4, 6]))
                centre.position(center)
                ForEach(Array(others.enumerated()), id: \.element.id) { i, d in
                    OrbitNode(device: d, chosen: d.id == selected) { select(d.id) }
                        .position(spots[i])
                }
            }
            .accessibilityElement(children: .contain)
        }
    }

    /// This phone: the button that sends or fetches.
    private var centre: some View {
        Button(action: sync) {
            VStack(spacing: 6) {
                Image(systemName: "arrow.up.arrow.down").font(.title.weight(.semibold))
                Text("Send or fetch").font(.footnote.weight(.semibold)).multilineTextAlignment(.center)
            }
            .foregroundStyle(palette.onAccent)
            .frame(width: 128, height: 128)
            .background(palette.accent, in: Circle())
            .overlay(Circle().stroke(palette.soft, lineWidth: 12).padding(-6))
        }
        .buttonStyle(.plain)
        .disabled(busy)
        .opacity(busy ? 0.6 : 1)
        .sensoryFeedback(.impact, trigger: busy)
    }

    /// Where count devices sit: evenly on the inner orbit from the top, the
    /// rest on the outer one, half a step turned.
    static func spots(count: Int, radii: [CGFloat], center: CGPoint) -> [CGPoint] {
        guard count > 0, let first = radii.first else { return [] }
        let rings = radii.count == 1 ? [(first, count, 0.0)] : [(first, inner, 0.0), (radii[1], count - inner, 0.5)]
        var out: [CGPoint] = []
        for (r, n, turn) in rings where n > 0 {
            for i in 0..<n {
                let a = (Double(i) + turn) / Double(n) * 2 * .pi - .pi / 2
                out.append(CGPoint(x: center.x + r * cos(a), y: center.y + r * sin(a)))
            }
        }
        return out
    }
}

/// A device on an orbit: its icon with the live dot, its name.
struct OrbitNode: View {
    let device: AppModel.Computer
    let chosen: Bool
    let open: () -> Void
    @Environment(\.palette) private var palette

    var body: some View {
        Button(action: open) {
            VStack(spacing: 6) {
                DeviceIcon(device: device, size: 52)
                    .overlay(alignment: .topTrailing) { OnlineDot(online: device.online).offset(x: 3, y: -3) }
                    .padding(6)
                    .glassTile(cornerRadius: 22)
                    .overlay(RoundedRectangle(cornerRadius: 22, style: .continuous).stroke(chosen ? palette.accent : .clear, lineWidth: 2))
                Text(device.name).font(.system(.caption, design: .monospaced).weight(.semibold)).lineLimit(1)
                DeviceSubtitle(device: device)
            }
            .frame(width: 112)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityValue(device.online ? Text("online") : Text("offline"))
        .accessibilityAddTraits(chosen ? .isSelected : [])
    }
}
