import AppKit
import SwiftUI
import RexBoingKit

// Renders the README's pictures from the app's own views, fed by demo mode,
// so they show the real interface and nobody's real machines. Nothing is put
// on screen: the views are hosted in windows far outside every display and
// read back through their layers, and the menu bar items are drawn by the
// same renderer the status items use, without creating any.
//
//   Tools/render-figures.sh [outdir]      (default docs)
//
// Writes menubar.png, fleet.png, dashboard.png, dashboard-lower.png,
// add-server-ssh.png and add-server-code.png.
@main
enum RenderFigures {
    static let scale: CGFloat = 2
    /// Stands in for the popover's dark material, which has no meaning off screen.
    static let ground = NSColor(red: 0.118, green: 0.118, blue: 0.129, alpha: 1)
    /// What the Add Server window's background looks like in dark mode.
    static let windowGround = NSColor(red: 0.157, green: 0.157, blue: 0.165, alpha: 1)

    @MainActor static func main() {
        signal(SIGPIPE, SIG_IGN)
        let outDir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "docs"
        try? FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true)

        // Demo mode, with preferences of its own that start fresh every time,
        // played fast enough that a minute and a half of history takes seconds.
        Demo.isActive = true
        Demo.recordingsDirectory = URL(fileURLWithPath: "RexBoingRemote/Demo/Recordings")
        Demo.defaultsSuite = "com.rexyrex.RexBoingRemote.figures"
        UserDefaults.standard.removePersistentDomain(forName: Demo.defaultsSuite)
        Replay.speed = 20

        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        app.appearance = NSAppearance(named: .darkAqua)

        let settings = AppSettings.shared
        let store = ServerStore(inMemory: Demo.servers)
        let fleet = Fleet(store: store, settings: settings)
        let home = Demo.servers[0]

        print("replaying the demo recordings…")
        let ready = pump(until: 30) {
            let recordings = Demo.machines.filter { if case .recording = $0.agent { true } else { false } }
            return recordings.allSatisfy { machine in
                guard let connection = fleet.connection(machine.server.id) else { return false }
                return connection.state == .live && connection.history.cpu.count >= MetricsHistory.capacity
            }
        }
        guard ready else { print("the demo servers did not come up"); exit(1) }

        menubar(fleet: fleet, store: store, settings: settings, to: "\(outDir)/menubar.png")

        // The popover: the fleet list, then the home server's dashboard.
        let navigation = Navigation()
        let actions = PopoverActions(addServer: {}, openSettings: {}, close: {})
        let popover = host(PopoverView(
            fleet: fleet, store: store, settings: settings, navigation: navigation, actions: actions))
        pump(1)
        write(snapshot(popover.view), to: "\(outDir)/fleet.png")

        navigation.selected = home.id
        let dashboard = fleet.connection(home.id)!
        let tables = dashboard.processHistory.samples.count
        pump(until: 30) {
            dashboard.processHistory.samples.count >= tables + 4 && dashboard.history.cpu.count >= MetricsHistory.capacity
        }
        pump(1)
        popover.view.layoutSubtreeIfNeeded()
        write(snapshot(popover.view), to: "\(outDir)/dashboard.png")
        if let scroll = findScrollView(in: popover.view), let document = scroll.documentView {
            let overflow = max(0, document.frame.height - scroll.contentView.bounds.height)
            scroll.contentView.scroll(to: NSPoint(x: 0, y: document.isFlipped ? overflow : 0))
            scroll.reflectScrolledClipView(scroll.contentView)
            pump(0.5)
            write(snapshot(popover.view), to: "\(outDir)/dashboard-lower.png")
        }
        popover.window.orderOut(nil)

        // The Add Server window, once for each way of adding a server.
        let add = host(AddServerView(store: store, settings: settings, close: {}), background: windowGround)
        pump(1)
        write(snapshot(add.view, background: windowGround), to: "\(outDir)/add-server-ssh.png")
        guard let picker = find(NSSegmentedControl.self, in: add.view) else {
            print("no method picker in the Add Server window"); exit(1)
        }
        picker.selectedSegment = 1
        _ = picker.sendAction(picker.action, to: picker.target)
        pump(1)
        add.resize()
        pump(0.5)
        write(snapshot(add.view, background: windowGround), to: "\(outDir)/add-server-code.png")

        fleet.connections.values.forEach { $0.stop() }
        pump(0.5)
        UserDefaults.standard.removePersistentDomain(forName: Demo.defaultsSuite)
        print("wrote \(outDir)/menubar.png, fleet.png, dashboard.png, dashboard-lower.png, add-server-ssh.png, add-server-code.png")
        exit(0)
    }

    // MARK: - The menu bar

    /// The pinned servers' items and the fleet item, left to right as the bar
    /// shows them (the item created first sits furthest right), each drawn
    /// by the status items' own readout renderer and character.
    @MainActor static func menubar(fleet: Fleet, store: ServerStore, settings: AppSettings, to path: String) {
        var items: [(cell: ReadoutCell?, character: Visualizer, load: Double, time: Double)] = []
        for (index, server) in store.servers.filter(\.pinned).reversed().enumerated() {
            let snapshot = fleet.connection(server.id)?.snapshot
            items.append((
                StatusController.readout(for: server, snapshot: snapshot, unit: settings.temperatureUnit),
                server.character, snapshot?.cpu.total ?? 0, 0.55 + 0.4 * Double(index)))
        }
        items.append((
            StatusController.fleetReadout(
                live: fleet.liveCount, total: store.servers.count,
                load: fleet.busiestLoad, needsAttention: fleet.needsAttention),
            settings.fleetCharacter, fleet.busiestLoad, 1.3))

        let magnify: CGFloat = 4
        let gap: CGFloat = 8
        let inset: CGFloat = 10
        let layouts = items.map { StatusBarRenderer.layout(cells: $0.cell.map { [$0] } ?? [], hasVisual: true) }
        let width = layouts.reduce(inset * 2) { $0 + $1.size.width } + gap * CGFloat(items.count - 1)
        let height = layouts.map(\.size.height).max() ?? 22
        let (rep, cg) = bitmap(width: Int(ceil(width * magnify)), height: Int(ceil(height * magnify)))
        cg.setFillColor(gray: 0, alpha: 1)
        cg.fill(CGRect(x: 0, y: 0, width: rep.pixelsWide, height: rep.pixelsHigh))
        cg.scaleBy(x: magnify, y: magnify)

        NSAppearance(named: .darkAqua)!.performAsCurrentDrawingAppearance {
            var x = inset
            for (item, layout) in zip(items, layouts) {
                cg.saveGState()
                cg.translateBy(x: x, y: (height - layout.size.height) / 2)
                if let readouts = StatusBarRenderer.renderReadouts(
                    cells: item.cell.map { [$0] } ?? [], layout: layout, monochrome: false, scale: magnify) {
                    cg.draw(readouts, in: CGRect(origin: .zero, size: layout.size))
                }
                cg.translateBy(x: layout.visual.minX, y: layout.visual.minY)
                item.character.draw(
                    in: cg, rect: CGRect(origin: .zero, size: layout.visual.size), time: item.time,
                    load: item.load, color: LoadInk.color(forLoad: item.load, neutral: .white))
                cg.restoreGState()
                x += layout.size.width + gap
            }
        }
        write(rep, to: path)
    }

    // MARK: - Hosting off screen

    @MainActor final class Hosted {
        let view: NSView
        let window: NSWindow

        init(view: NSView, window: NSWindow) {
            self.view = view
            self.window = window
        }

        /// Fits the window to the view's new size, after a change of content.
        func resize() {
            let size = view.fittingSize
            window.setContentSize(size)
            view.frame = CGRect(origin: .zero, size: size)
        }
    }

    /// A window that can be key, so default buttons and focus look as they do
    /// in use, without the app ever becoming active.
    final class FigureWindow: NSWindow {
        override var canBecomeKey: Bool { true }
        override var canBecomeMain: Bool { true }
    }

    @MainActor static func host<Content: View>(_ content: Content, background: NSColor = ground) -> Hosted {
        let hosting = NSHostingView(rootView: content)
        hosting.wantsLayer = true
        let size = hosting.fittingSize
        // Far outside every screen: the window has to exist for SwiftUI to lay
        // out and keep updating, but nobody should see it.
        let window = FigureWindow(
            contentRect: NSRect(x: -20000, y: -20000, width: size.width, height: size.height),
            styleMask: .borderless, backing: .buffered, defer: false)
        window.appearance = NSAppearance(named: .darkAqua)
        window.backgroundColor = background
        window.isOpaque = true
        window.contentView = hosting
        window.orderFrontRegardless()
        window.makeKey()
        return Hosted(view: hosting, window: window)
    }

    /// Runs the main run loop rather than sleeping: the connections publish on
    /// the main queue and SwiftUI commits its updates from the run loop.
    static func pump(_ seconds: Double) {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        }
    }

    @discardableResult
    @MainActor static func pump(until seconds: Double, _ done: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if done() { return true }
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        }
        return done()
    }

    static func findScrollView(in view: NSView) -> NSScrollView? {
        if let scroll = view as? NSScrollView, scroll.documentView?.frame.height ?? 0 > scroll.frame.height {
            return scroll
        }
        for child in view.subviews {
            if let found = findScrollView(in: child) { return found }
        }
        return nil
    }

    static func find<T: NSView>(_ type: T.Type, in view: NSView) -> T? {
        if let match = view as? T { return match }
        for child in view.subviews {
            if let found = find(type, in: child) { return found }
        }
        return nil
    }

    // MARK: - Bitmaps

    /// The view's layer tree drawn into a bitmap at `scale`. Through the
    /// layers, not `cacheDisplay`, because SwiftUI's content lives in layers
    /// that are not views and `cacheDisplay` walks only views.
    @MainActor static func snapshot(_ view: NSView, background: NSColor = ground) -> NSBitmapImageRep {
        let size = view.bounds.size
        let (rep, cg) = bitmap(width: Int(size.width * scale), height: Int(size.height * scale))
        rep.size = size
        cg.setFillColor(background.cgColor)
        cg.fill(CGRect(x: 0, y: 0, width: rep.pixelsWide, height: rep.pixelsHigh))
        cg.scaleBy(x: scale, y: scale)
        // The hosting view is flipped — its layer's origin is top-left — while
        // the bitmap context is bottom-left. Mirror once, or it comes out
        // upside down.
        if view.isFlipped {
            cg.translateBy(x: 0, y: size.height)
            cg.scaleBy(x: 1, y: -1)
        }
        view.layer!.render(in: cg)
        return rep
    }

    static func bitmap(width: Int, height: Int) -> (NSBitmapImageRep, CGContext) {
        let rep = NSBitmapImageRep(
            bitmapDataPlanes: nil, pixelsWide: width, pixelsHigh: height,
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
            colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        let context = NSGraphicsContext(bitmapImageRep: rep)!
        NSGraphicsContext.current = context
        let cg = context.cgContext
        cg.setShouldAntialias(true)
        cg.interpolationQuality = .high
        return (rep, cg)
    }

    static func write(_ rep: NSBitmapImageRep, to path: String) {
        let png = rep.representation(using: .png, properties: [:])!
        try! png.write(to: URL(fileURLWithPath: path))
        print("wrote \(path): \(rep.pixelsWide)×\(rep.pixelsHigh)")
    }
}
