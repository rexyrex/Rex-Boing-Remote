import AppKit
import RexBoingKit

// Renders Rex Boing Remote's app icon with Rex Boing's own drawing code: the
// rex galloping on top of a three-unit server stack, on a violet plate, with
// signal arcs for "far away". The stack is what tells it from Rex Boing's
// icon at Finder and Cmd-Tab sizes, where the rex is a few pixels and the
// arcs are gone.
//   Tools/render-icon.sh   (builds this against RexBoingKit and writes the asset catalog)
@main
enum RenderIcon {
    static func main() {
        let outDir = CommandLine.arguments[1]
        try? FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true)
        let sizes: [(String, Int)] = [
            ("icon_16x16", 16), ("icon_16x16@2x", 32), ("icon_32x32", 32), ("icon_32x32@2x", 64),
            ("icon_128x128", 128), ("icon_128x128@2x", 256), ("icon_256x256", 256),
            ("icon_256x256@2x", 512), ("icon_512x512", 512), ("icon_512x512@2x", 1024),
        ]
        for (name, px) in sizes {
            let rep = NSBitmapImageRep(
                bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                bytesPerRow: 0, bitsPerPixel: 0)!
            let context = NSGraphicsContext(bitmapImageRep: rep)!
            NSGraphicsContext.current = context
            let cg = context.cgContext
            cg.scaleBy(x: CGFloat(px) / 1024, y: CGFloat(px) / 1024)
            draw(cg)
            try! rep.representation(using: .png, properties: [:])!
                .write(to: URL(fileURLWithPath: "\(outDir)/\(name).png"))
        }
    }

    /// Shadows are in device pixels, not the context's units, so each is
    /// scaled to the size being rendered: otherwise a 16-pixel icon gets the
    /// 1024-pixel icon's blur and turns grey round the edges.
    static func shadow(_ cg: CGContext, y: CGFloat, blur: CGFloat, color: CGColor) {
        let k = cg.ctm.a
        cg.setShadow(offset: CGSize(width: 0, height: y * k), blur: blur * k, color: color)
    }

    static func draw(_ cg: CGContext) {
        let inset: CGFloat = 100
        let side = 1024 - inset * 2
        let plate = CGRect(x: inset, y: inset, width: side, height: side)
        let radius = side * 0.225
        let path = CGPath(roundedRect: plate, cornerWidth: radius, cornerHeight: radius, transform: nil)

        cg.saveGState()
        shadow(cg, y: -10, blur: 24, color: CGColor(red: 0, green: 0, blue: 0, alpha: 0.3))
        cg.addPath(path)
        cg.setFillColor(red: 0.42, green: 0.26, blue: 0.82, alpha: 1)
        cg.fillPath()
        cg.restoreGState()

        cg.saveGState()
        cg.addPath(path)
        cg.clip()
        let space = CGColorSpaceCreateDeviceRGB()
        let gradient = CGGradient(colorsSpace: space, colors: [
            CGColor(red: 0.70, green: 0.50, blue: 1.00, alpha: 1),
            CGColor(red: 0.46, green: 0.30, blue: 0.92, alpha: 1),
            CGColor(red: 0.27, green: 0.18, blue: 0.70, alpha: 1),
        ] as CFArray, locations: [0, 0.55, 1])!
        cg.drawLinearGradient(gradient, start: CGPoint(x: 512, y: plate.maxY),
                              end: CGPoint(x: 512, y: plate.minY), options: [])

        // Signal arcs, up and to the right of the rex's head.
        let center = CGPoint(x: 720, y: 720)
        cg.setLineCap(.round)
        for (index, r) in [CGFloat(47), 88, 130].enumerated() {
            cg.setStrokeColor(CGColor(red: 1, green: 1, blue: 1, alpha: 0.85 - CGFloat(index) * 0.2))
            cg.setLineWidth(23)
            cg.addArc(center: center, radius: r, startAngle: .pi * 0.05, endAngle: .pi * 0.45, clockwise: false)
            cg.strokePath()
        }
        cg.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 0.95))
        cg.fillEllipse(in: CGRect(x: center.x - 18, y: center.y - 18, width: 36, height: 36))
        cg.restoreGState()

        let stack = drawStack(cg, plate: plate)

        // The rex, drawn by the menu bar's own code at menu bar proportions:
        // the drawing works in the canvas's own units, so it is scaled into
        // place rather than handed a large rect. Its ground line runs just
        // inside the top unit, white on white, and is clipped to the stack's
        // width, so the streaming dashes neither float above the stack nor
        // hang off either side of it.
        //
        // In a transparency layer of its own because the eyes are cut out of
        // the head (the menu bar shows through them): drawn straight onto the
        // plate, they would cut through it too, and look black or blank
        // depending on what the icon sits on. The shadow is set inside the
        // layer, so each part still shades the ones behind it.
        let canvas = Visualizer.canvasSize
        let width: CGFloat = 600
        let height = width * canvas.height / canvas.width
        let ground = stack.maxY - 10
        let rect = CGRect(x: 500 - width / 2, y: ground - height * 0.11, width: width, height: height)
        cg.saveGState()
        cg.clip(to: [
            CGRect(x: 0, y: stack.maxY + 14, width: 1024, height: 1024),
            CGRect(x: stack.minX, y: stack.minY, width: stack.width, height: 1024),
        ])
        cg.beginTransparencyLayer(auxiliaryInfo: nil)
        shadow(cg, y: -10, blur: 24, color: CGColor(red: 0.12, green: 0.05, blue: 0.35, alpha: 0.5))
        cg.translateBy(x: rect.minX, y: rect.minY)
        cg.scaleBy(x: rect.width / canvas.width, y: rect.height / canvas.height)
        Visualizer.rex.draw(in: cg, rect: CGRect(origin: .zero, size: canvas),
                            time: Visualizer.restingTime, load: 0.45, color: .white)
        cg.endTransparencyLayer()
        cg.restoreGState()
    }

    /// Three rack units, each with a green status light, a dim one and drive
    /// slots. Returns the frame of the whole stack.
    static func drawStack(_ cg: CGContext, plate: CGRect) -> CGRect {
        let width: CGFloat = 470, unit: CGFloat = 104, gap: CGFloat = 22
        let minX = 512 - width / 2
        let bottom = plate.minY + 120
        for index in 0..<3 {
            let r = CGRect(x: minX, y: bottom + CGFloat(index) * (unit + gap), width: width, height: unit)
            cg.saveGState()
            shadow(cg, y: -8, blur: 18, color: CGColor(red: 0.12, green: 0.05, blue: 0.35, alpha: 0.45))
            cg.addPath(CGPath(roundedRect: r, cornerWidth: unit * 0.24, cornerHeight: unit * 0.24, transform: nil))
            cg.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 0.96))
            cg.fillPath()
            cg.restoreGState()

            let light = unit * 0.26
            cg.setFillColor(CGColor(red: 0.30, green: 0.86, blue: 0.52, alpha: 1))
            cg.fillEllipse(in: CGRect(x: r.minX + unit * 0.36, y: r.midY - light / 2, width: light, height: light))
            cg.setFillColor(CGColor(red: 0.42, green: 0.30, blue: 0.82, alpha: 0.30))
            cg.fillEllipse(in: CGRect(x: r.minX + unit * 0.80, y: r.midY - light / 2, width: light, height: light))
            cg.setStrokeColor(CGColor(red: 0.42, green: 0.30, blue: 0.82, alpha: 0.35))
            cg.setLineWidth(unit * 0.12)
            cg.setLineCap(.round)
            for slot in 0..<3 {
                let x = r.maxX - unit * 0.45 - CGFloat(slot) * unit * 0.34
                cg.move(to: CGPoint(x: x, y: r.midY - unit * 0.2))
                cg.addLine(to: CGPoint(x: x, y: r.midY + unit * 0.2))
                cg.strokePath()
            }
        }
        let height = 3 * unit + 2 * gap
        return CGRect(x: minX, y: bottom, width: width, height: height)
    }
}
