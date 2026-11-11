// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// TEMPORARY: variants of the Start screen's restore link side by side, for
/// one run of ReadersUITests.testRestoreLinkVariants that tells which of
/// them Xcode's clipped text check flags in Hindi. Removed once it has run.
struct RestoreLinkExperiment: View {
    private let text: LocalizedStringKey = "Restore with the recovery key"

    private func framed(_ t: some View) -> some View {
        t.multilineTextAlignment(.center)
            .padding(.vertical, Tokens.spacingSmall)
            .frame(maxWidth: .infinity, minHeight: 44)
            .contentShape(Rectangle())
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 2) {
                Button {} label: { framed(Text(text)) }.buttonStyle(.plain).font(.footnote).accessibilityIdentifier("v00-current")
                Text(text).font(.footnote).accessibilityIdentifier("v01-text")
                Button {} label: { Text(text) }.buttonStyle(.plain).font(.footnote).accessibilityIdentifier("v02-button-bare")
                Button {} label: { Text(text) }.font(.footnote).accessibilityIdentifier("v03-button-default")
                Button {} label: { framed(Text(text)) }.buttonStyle(.plain).font(.body).accessibilityIdentifier("v04-body")
                Button {} label: { framed(Text(text)) }.buttonStyle(.plain).font(.callout).accessibilityIdentifier("v05-callout")
                Button {} label: { framed(Text(text)) }.buttonStyle(.plain).font(.footnote.weight(.medium)).accessibilityIdentifier("v06-footnote-medium")
                Button {} label: { framed(Text(text)) }.buttonStyle(.plain).font(.footnote.leading(.loose)).accessibilityIdentifier("v07-footnote-loose")
                Button {} label: { framed(Text(text).fixedSize(horizontal: false, vertical: true)) }.buttonStyle(.plain).font(.footnote).accessibilityIdentifier("v08-fixedsize")
                Button {} label: { Text(text).padding(.vertical, 12) }.buttonStyle(.plain).font(.footnote).accessibilityIdentifier("v09-padding-only")
                Button {} label: { framed(Text(text)) }.buttonStyle(GlassButtonStyle()).accessibilityIdentifier("v10-glass")
                Button {} label: { framed(Text(text)) }.buttonStyle(.plain).font(.subheadline).accessibilityIdentifier("v11-subheadline")
                Button {} label: { framed(Text("Create a group")) }.buttonStyle(.plain).font(.footnote).accessibilityIdentifier("v12-other-text-footnote")
                Button {} label: { framed(Text(text)) }.buttonStyle(.plain).font(.caption).accessibilityIdentifier("v13-caption")
                Button {} label: { framed(Text(text).lineLimit(2)) }.buttonStyle(.plain).font(.footnote).accessibilityIdentifier("v14-linelimit2")
                Button {} label: { framed(Text(text)) }.buttonStyle(.borderless).font(.footnote).accessibilityIdentifier("v15-borderless")
            }
            .padding(.horizontal, 24)
        }
    }
}
