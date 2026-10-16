import AppKit
import RexBoingKit

// Renders Rex Boing Remote's app icon with Rex Boing's own drawing code: the
// jetpack rex on a violet plate, with signal arcs for "far away".
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

    static func draw(_ cg: CGContext) {
        let inset: CGFloat = 100
        let side = 1024 - inset * 2
        let plate = CGRect(x: inset, y: inset, width: side, height: side)
        let radius = side * 0.225
        let path = CGPath(roundedRect: plate, cornerWidth: radius, cornerHeight: radius, transform: nil)

        cg.saveGState()
        cg.setShadow(offset: CGSize(width: 0, height: -10), blur: 24,
                     color: CGColor(red: 0, green: 0, blue: 0, alpha: 0.3))
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

        // Signal arcs in the top right corner.
        let center = CGPoint(x: plate.maxX - 190, y: plate.maxY - 190)
        cg.setLineCap(.round)
        for (index, r) in [CGFloat(52), 98, 144].enumerated() {
            cg.setStrokeColor(CGColor(red: 1, green: 1, blue: 1, alpha: 0.85 - CGFloat(index) * 0.2))
            cg.setLineWidth(26)
            cg.addArc(center: center, radius: r, startAngle: .pi * 0.05, endAngle: .pi * 0.45, clockwise: false)
            cg.strokePath()
        }
        cg.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 0.95))
        cg.fillEllipse(in: CGRect(x: center.x - 20, y: center.y - 20, width: 40, height: 40))
        cg.restoreGState()

        // The rex, drawn by the menu bar's own code at menu bar proportions:
        // the drawing works in the canvas's own units, so it is scaled into
        // place rather than handed a large rect.
        let canvas = Visualizer.canvasSize
        let width = side * 0.98
        let height = width * canvas.height / canvas.width
        let rect = CGRect(x: plate.midX - width / 2, y: plate.midY - height / 2 - 30, width: width, height: height)
        cg.saveGState()
        cg.setShadow(offset: CGSize(width: 0, height: -10), blur: 24,
                     color: CGColor(red: 0.12, green: 0.05, blue: 0.35, alpha: 0.5))
        cg.translateBy(x: rect.minX, y: rect.minY)
        cg.scaleBy(x: rect.width / canvas.width, y: rect.height / canvas.height)
        Visualizer.rex.draw(in: cg, rect: CGRect(origin: .zero, size: canvas),
                            time: Visualizer.restingTime, load: 0.45, color: .white)
        cg.restoreGState()
    }
}
