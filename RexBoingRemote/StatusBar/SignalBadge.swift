import AppKit
import RexBoingKit

/// The signal mark beside every rex Remote puts in the menu bar: a dot and
/// two arcs, the app icon's own, so a Remote rex never passes for one of Rex
/// Boing's when both apps sit side by side.
///
/// It has a column of its own between the character and the readout rather
/// than a corner of the character's box: across the sixteen characters,
/// over their cycles and loads, there is no corner of that box that one of
/// them does not draw in.
@MainActor
enum SignalBadge {
    static let width: CGFloat = 6

    /// The item's layout with the badge's column after the character.
    static func layout(cells: [ReadoutCell]) -> StatusBarRenderer.Layout {
        var layout = StatusBarRenderer.layout(cells: cells, hasVisual: true)
        layout.textOrigin += width
        layout.size.width += width
        return layout
    }

    /// Draws the mark into the column `layout` leaves for it, in a context
    /// whose units are points with the origin at the bottom left. Offline,
    /// the arcs all but go, as a Wi-Fi menu does with no signal.
    static func draw(in context: CGContext, layout: StatusBarRenderer.Layout, ink: NSColor, live: Bool) {
        let rgb = ink.usingColorSpace(.deviceRGB) ?? NSColor(deviceWhite: 1, alpha: 1)
        let dot = CGPoint(x: layout.visual.maxX + 1.1, y: layout.size.height / 2 + 1.2)

        context.saveGState()
        defer { context.restoreGState() }
        context.setLineCap(.round)
        context.setLineWidth(1.1)
        context.setStrokeColor(rgb.withAlphaComponent(rgb.alphaComponent * (live ? 1 : 0.25)).cgColor)
        for radius in [CGFloat(2.6), 4.4] {
            context.addArc(center: dot, radius: radius, startAngle: .pi * 0.04, endAngle: .pi * 0.46, clockwise: false)
            context.strokePath()
        }
        context.setFillColor(rgb.cgColor)
        context.fillEllipse(in: CGRect(x: dot.x - 0.95, y: dot.y - 0.95, width: 1.9, height: 1.9))
    }

    /// Kit's readouts with the mark drawn in, as one image for the item's
    /// text layer.
    static func compose(
        readouts: CGImage?, layout: StatusBarRenderer.Layout, ink: NSColor, live: Bool, scale: CGFloat
    ) -> CGImage? {
        let pixelsWide = Int(ceil(layout.size.width * scale))
        let pixelsHigh = Int(ceil(layout.size.height * scale))
        guard let context = CGContext(
            data: nil, width: pixelsWide, height: pixelsHigh, bitsPerComponent: 8, bytesPerRow: 0,
            space: readouts?.colorSpace ?? CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return readouts }
        if let readouts {
            context.draw(readouts, in: CGRect(x: 0, y: 0, width: readouts.width, height: readouts.height))
        }
        context.scaleBy(x: scale, y: scale)
        draw(in: context, layout: layout, ink: ink, live: live)
        return context.makeImage()
    }
}
