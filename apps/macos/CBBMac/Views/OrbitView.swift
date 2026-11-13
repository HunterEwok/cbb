// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// The devices around this Mac, on one or two orbits, as the iPhone app
/// draws them on big screens: this Mac is the centre; a device, this Mac
/// too, opens its details.
struct OrbitView: View {
    let devices: [Control.Device]
    let me: Control.Device?
    let selected: String?
    let select: (String) -> Void
    @Environment(\.palette) private var palette

    /// How many devices the inner orbit holds before the outer one starts.
    static let inner = 6

    var body: some View {
        GeometryReader { geo in
            let side = min(geo.size.width, geo.size.height)
            let center = CGPoint(x: geo.size.width / 2, y: geo.size.height / 2)
            let radii = devices.count > Self.inner ? [side * 0.28, side * 0.43] : [side * 0.36]
            let spots = Self.spots(count: devices.count, radii: radii, center: center)
            ZStack {
                ForEach(radii, id: \.self) { r in
                    Circle().stroke(palette.line, lineWidth: 1).frame(width: r * 2, height: r * 2).position(center)
                }
                Path { p in
                    for (d, spot) in zip(devices, spots) where d.online {
                        p.move(to: center)
                        p.addLine(to: spot)
                    }
                }
                .stroke(palette.accent.opacity(0.35), style: StrokeStyle(lineWidth: 1.5, dash: [4, 6]))
                centre.position(center)
                ForEach(Array(devices.enumerated()), id: \.element.id) { i, d in
                    OrbitNode(device: d, chosen: d.id == selected) { select(d.id) }
                        .position(spots[i])
                }
            }
            .accessibilityElement(children: .contain)
        }
    }

    /// This Mac, which opens its own details.
    @ViewBuilder private var centre: some View {
        if let me {
            Button { select(me.id) } label: {
                VStack(spacing: 6) {
                    DeviceIcon(device: me, size: 40)
                    Text("This Mac").font(.footnote.weight(.semibold))
                }
                .foregroundStyle(palette.onAccent)
                .frame(width: 112, height: 112)
                .background(palette.accent, in: Circle())
                .overlay(Circle().stroke(me.id == selected ? palette.text : palette.soft, lineWidth: me.id == selected ? 3 : 12).padding(-6))
            }
            .buttonStyle(.plain)
            .accessibilityLabel(Text(verbatim: me.name))
            .accessibilityValue(Text("This Mac"))
        }
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
    let device: Control.Device
    let chosen: Bool
    let open: () -> Void
    @Environment(\.palette) private var palette

    var body: some View {
        Button(action: open) {
            VStack(spacing: 6) {
                DeviceIcon(device: device, size: 48)
                    .overlay(alignment: .topTrailing) { OnlineDot(online: device.online).offset(x: 3, y: -3) }
                    .padding(6)
                    .glassTile(.fixed(20))
                    .overlay(RoundedRectangle(cornerRadius: 20, style: .continuous).stroke(chosen ? palette.accent : .clear, lineWidth: 2))
                Text(verbatim: device.name).font(.system(.caption, design: .monospaced).weight(.semibold)).lineLimit(1)
            }
            .frame(width: 112)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityValue(device.online ? Text("online") : Text("offline"))
    }
}
