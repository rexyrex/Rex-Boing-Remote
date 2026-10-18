import AppKit
import QuartzCore
import RexBoingKit

/// Forwards display-link callbacks through a weak reference, so the link
/// (which retains its target) never keeps an item alive.
@MainActor
private final class DisplayLinkProxy: NSObject {
    weak var item: RexItem?

    @objc func step(_ link: CADisplayLink) {
        item?.step(link)
    }
}

/// One menu bar item: an animated rex and an optional readout, drawn with
/// Rex Boing's own renderer so the characters move exactly as they do there.
///
/// The rex's pace follows `load` (0–1). When the server it stands for is
/// offline, `isAsleep` stills it and dims it, which is the menu bar's way of
/// saying "not live" without a word of text.
@MainActor
final class RexItem: NSObject {
    let statusItem: NSStatusItem
    var onClick: ((RexItem, NSEvent?) -> Void)?

    var character: Visualizer = .rex { didSet { if oldValue != character { present() } } }
    var load: Double = 0
    var isAsleep = false { didSet { if oldValue != isAsleep { refreshReadout(); retune() } } }
    var animate = true { didSet { retune() } }
    var readout: ReadoutCell? { didSet { if oldValue != readout { refreshReadout() } } }
    /// Also what VoiceOver reads for the item, which has no text of its
    /// own: the server's name and how it is.
    var toolTip: String? {
        didSet {
            statusItem.button?.toolTip = toolTip
            statusItem.button?.setAccessibilityLabel(toolTip)
        }
    }

    private let canvas = VisualCanvas()
    private var displayLink: CADisplayLink?
    private var rootLayer: CALayer?
    private var visualLayer: CALayer?
    private var layout = StatusBarRenderer.layout(cells: [], hasVisual: true)
    private var clock: Double = 0
    private var smoothedLoad: Double = 0
    private var lastFrame: CFTimeInterval = 0
    private var scheduledRate: Double = 0
    private var inkAlpha: Float = 1
    private var neutralInk = NSColor.labelColor

    // The Smooth setting of Rex Boing: up to 30 fps, 18 frames a cycle.
    private let maximumFrameRate: Double = 30
    private let framesPerCycle: Double = 18

    init(autosaveName: String) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.autosaveName = autosaveName
        super.init()
        if let button = statusItem.button {
            button.target = self
            button.action = #selector(clicked)
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
            button.image = nil
            button.imagePosition = .noImage
        }
        refreshReadout()
        startAnimation()
    }

    /// Whether the item is somewhere it can be clicked. On a notched Mac a
    /// full menu bar puts the overflow behind the camera housing, left of the
    /// area the screen reports as free to the notch's right.
    var isOnScreen: Bool {
        guard let window = statusItem.button?.window, let screen = window.screen ?? NSScreen.main else {
            return false
        }
        let frame = window.frame
        guard screen.frame.intersects(frame) else { return false }
        if let right = screen.auxiliaryTopRightArea, screen.auxiliaryTopLeftArea != nil {
            return frame.minX >= right.minX - 1
        }
        return true
    }

    func remove() {
        displayLink?.invalidate()
        displayLink = nil
        NSStatusBar.system.removeStatusItem(statusItem)
    }

    @objc private func clicked() {
        onClick?(self, NSApp.currentEvent)
    }

    // MARK: - Drawing

    private func refreshReadout() {
        guard let button = statusItem.button else { return }
        let cells = readout.map { [$0] } ?? []
        layout = StatusBarRenderer.layout(cells: cells, hasVisual: true)
        let scale = button.window?.backingScaleFactor ?? NSScreen.main?.backingScaleFactor ?? 2

        var image: CGImage?
        button.effectiveAppearance.performAsCurrentDrawingAppearance {
            let label = NSColor.labelColor.usingColorSpace(.deviceRGB) ?? .labelColor
            neutralInk = label.withAlphaComponent(1)
            inkAlpha = Float(label.alphaComponent) * (isAsleep ? 0.45 : 1)
            image = StatusBarRenderer.renderReadouts(
                cells: cells, layout: layout, monochrome: isAsleep, scale: scale)
        }
        if statusItem.length != layout.size.width { statusItem.length = layout.size.width }

        button.wantsLayer = true
        let root = rootLayer ?? {
            let layer = CALayer()
            layer.contentsGravity = .center
            layer.autoresizingMask = [.layerWidthSizable, .layerHeightSizable]
            button.layer?.addSublayer(layer)
            rootLayer = layer
            return layer
        }()
        let visual = visualLayer ?? {
            let layer = CALayer()
            layer.delegate = canvas
            layer.autoresizingMask = [.layerMaxXMargin, .layerMinYMargin, .layerMaxYMargin]
            root.addSublayer(layer)
            visualLayer = layer
            return layer
        }()
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        root.frame = CGRect(origin: .zero, size: layout.size)
        root.contentsScale = scale
        root.contents = image
        visual.frame = layout.visual
        visual.contentsScale = scale
        visual.opacity = inkAlpha
        CATransaction.commit()
        present()
    }

    /// Re-resolves colours after the menu bar switched appearance.
    func appearanceChanged() {
        refreshReadout()
    }

    private func present() {
        guard let visualLayer else { return }
        canvas.visual = character
        canvas.time = shouldAnimate ? clock : Visualizer.restingTime
        canvas.load = smoothedLoad
        canvas.color = isAsleep ? neutralInk : LoadInk.color(
            forLoad: (smoothedLoad * 200).rounded() / 200, neutral: neutralInk)
        visualLayer.setNeedsDisplay()
    }

    // MARK: - Animation

    private var shouldAnimate: Bool {
        animate && !isAsleep && !NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
    }

    private func startAnimation() {
        guard displayLink == nil, let button = statusItem.button else { return }
        let proxy = DisplayLinkProxy()
        proxy.item = self
        let link = button.displayLink(target: proxy, selector: #selector(DisplayLinkProxy.step(_:)))
        link.add(to: .main, forMode: .common)
        displayLink = link
        retune()
    }

    private var rate: (fps: Double, pace: Double) {
        let desired = character.rate(forLoad: smoothedLoad, speedFactor: 1)
        let floor = max(6, maximumFrameRate / 3)
        let fps = min(maximumFrameRate, max(floor, desired * framesPerCycle))
        return (fps, min(desired, fps / Visualizer.minimumFramesPerCycle))
    }

    private func retune() {
        guard let link = displayLink else { return }
        guard shouldAnimate else {
            link.isPaused = true
            scheduledRate = 0
            smoothedLoad = load
            present()
            return
        }
        if link.isPaused {
            link.isPaused = false
            lastFrame = 0
        }
        let fps = rate.fps
        guard scheduledRate == 0 || abs(fps - scheduledRate) / scheduledRate > 0.2 else { return }
        scheduledRate = fps
        link.preferredFrameRateRange = CAFrameRateRange(
            minimum: Float(max(1, fps * 0.5)), maximum: Float(fps), preferred: Float(fps))
    }

    fileprivate func step(_ link: CADisplayLink) {
        guard shouldAnimate else {
            retune()
            return
        }
        let now = link.timestamp
        let delta = lastFrame == 0 ? 0 : min(0.25, max(0, now - lastFrame))
        lastFrame = now
        if delta > 0 {
            // Eased towards the latest sample over about half a second, so a
            // new reading glides in rather than jolting the pace.
            smoothedLoad += (load - smoothedLoad) * (1 - exp(-delta / 0.6))
            let current = rate
            let deliverable = scheduledRate > 0 ? min(current.fps, scheduledRate) : current.fps
            clock += min(current.pace, deliverable / Visualizer.minimumFramesPerCycle) * delta
        }
        present()
        retune()
    }
}
