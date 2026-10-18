import AppKit
import Combine
import SwiftUI
import RexBoingKit

/// The menu bar: one rex for the whole fleet, plus one for each pinned
/// server, and the popover they open.
@MainActor
final class StatusController: NSObject, NSPopoverDelegate {
    private let fleet: Fleet
    private let store: ServerStore
    private let settings: AppSettings
    private let navigation = Navigation()

    private var fleetItem: RexItem!
    private var pinnedItems: [Server.ID: RexItem] = [:]
    private let popover = NSPopover()
    private var cancellables = Set<AnyCancellable>()
    private var refreshScheduled = false

    init(fleet: Fleet, store: ServerStore, settings: AppSettings) {
        self.fleet = fleet
        self.store = store
        self.settings = settings
        super.init()

        fleetItem = RexItem(autosaveName: "RexBoingRemoteFleet")
        fleetItem.onClick = { [weak self] item, event in self?.clicked(item, event: event, server: nil) }

        popover.behavior = .transient
        popover.animates = true
        popover.delegate = self

        fleet.$revision
            .sink { [weak self] _ in self?.scheduleRefresh() }
            .store(in: &cancellables)
        settings.objectWillChange
            .sink { [weak self] _ in self?.scheduleRefresh() }
            .store(in: &cancellables)

        DistributedNotificationCenter.default().addObserver(
            forName: Notification.Name("AppleInterfaceThemeChangedNotification"), object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.fleetItem.appearanceChanged()
                self?.pinnedItems.values.forEach { $0.appearanceChanged() }
            }
        }
        refresh()

        // A full menu bar on a notched Mac puts new items behind the camera
        // housing, where nobody can click them. Check once things settle.
        DispatchQueue.main.asyncAfter(deadline: .now() + 4) { [weak self] in
            MainActor.assumeIsolated { self?.warnIfHidden() }
        }
    }

    // MARK: - A menu bar with no room

    private static let warnedHiddenKey = "warnedHiddenStatusItem"

    private func warnIfHidden() {
        guard !fleetItem.isOnScreen,
              !UserDefaults.standard.bool(forKey: Self.warnedHiddenKey) else { return }
        UserDefaults.standard.set(true, forKey: Self.warnedHiddenKey)
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Your menu bar is full"
        alert.informativeText = """
            macOS has hidden Rex Boing Remote's rex behind the camera notch, where it can't be clicked.             Hold ⌘ and drag other icons out of the menu bar to make room, or use a menu bar manager.

            Until then, open Rex Boing Remote again from Applications to see your servers in a window.
            """
        alert.addButton(withTitle: "Open Window")
        alert.addButton(withTitle: "OK")
        if alert.runModal() == .alertFirstButtonReturn { openWindow() }
    }

    func openWindow() {
        popover.performClose(nil)
        DashboardWindow.shared.show(fleet: fleet, store: store, settings: settings, actions: PopoverActions(
            addServer: { [weak self] in self?.openAddServer() },
            openSettings: { [weak self] in self?.openSettings() },
            close: { DashboardWindow.shared.close() }))
    }

    // MARK: - Items

    /// Many samples can land in the same instant across a fleet; redrawing
    /// once per run-loop pass is plenty.
    private func scheduleRefresh() {
        guard !refreshScheduled else { return }
        refreshScheduled = true
        DispatchQueue.main.async { [weak self] in
            MainActor.assumeIsolated {
                self?.refreshScheduled = false
                self?.refresh()
            }
        }
    }

    private func refresh() {
        let servers = store.servers
        let total = servers.count
        let live = fleet.liveCount

        // The fleet rex: the busiest live server sets the pace. With nothing
        // live — no servers yet, or all of them down — it rests.
        fleetItem.character = settings.fleetCharacter
        fleetItem.animate = settings.animate
        fleetItem.load = fleet.busiestLoad
        fleetItem.isAsleep = total > 0 && live == 0
        fleetItem.readout = settings.showFleetReadout && total > 0
            ? Self.fleetReadout(live: live, total: total, load: fleet.busiestLoad, needsAttention: fleet.needsAttention)
            : nil
        fleetItem.toolTip = total == 0
            ? "Rex Boing Remote — add a server to start"
            : "Rex Boing Remote — \(live) of \(total) servers live"

        // One item per pinned server, created and removed as pins change.
        let pinned = servers.filter(\.pinned)
        let pinnedIDs = Set(pinned.map(\.id))
        for (id, item) in pinnedItems where !pinnedIDs.contains(id) {
            item.remove()
            pinnedItems[id] = nil
        }
        for server in pinned {
            let item = pinnedItems[server.id] ?? {
                let item = RexItem(autosaveName: "RexBoingRemote-\(server.id.uuidString)")
                item.onClick = { [weak self] item, event in
                    self?.clicked(item, event: event, server: server.id)
                }
                pinnedItems[server.id] = item
                return item
            }()
            let connection = fleet.connection(server.id)
            let snapshot = connection?.snapshot
            let isLive = connection?.state == .live
            item.character = server.character
            item.animate = settings.animate
            item.load = isLive ? snapshot?.cpu.total ?? 0 : 0
            item.isAsleep = !isLive
            item.readout = Self.readout(for: server, snapshot: isLive ? snapshot : nil, unit: settings.temperatureUnit)
            item.toolTip = "\(server.name) — \(Self.stateText(connection?.state ?? .idle))"
        }
    }

    /// The fleet rex's readout: how many servers are live, and the busiest
    /// one's CPU.
    static func fleetReadout(live: Int, total: Int, load: Double, needsAttention: Bool) -> ReadoutCell {
        let caption = needsAttention ? "!\(live)/\(total)" : "\(live)/\(total)"
        let value = live > 0 ? Format.percent(load) : "—"
        return ReadoutCell(
            caption: caption, value: value,
            tint: needsAttention ? NSColor.systemOrange : nil,
            width: StatusBarRenderer.width(value: "100%", caption: "!99/99"))
    }

    static func readout(for server: Server, snapshot: Snapshot?, unit: TemperatureUnit) -> ReadoutCell? {
        let value: String
        let template: String
        switch server.readout {
        case .none:
            return ReadoutCell(caption: server.caption, value: "", width: StatusBarRenderer.width(value: "", caption: server.caption))
        case .cpu:
            value = snapshot.map { Format.percent($0.cpu.total) } ?? "—"
            template = "100%"
        case .memory:
            value = snapshot.map { Format.percent($0.memory.fractionUsed) } ?? "—"
            template = "100%"
        case .gpu:
            value = snapshot.map { $0.gpu.available ? Format.percent($0.gpu.utilization) : "—" } ?? "—"
            template = "100%"
        case .temperature:
            let celsius = snapshot?.thermal.cpuCelsius ?? snapshot?.thermal.peakCelsius
            value = celsius.map { String(format: "%.0f°", Format.temperatureValue($0, unit: unit)) } ?? "—"
            template = "100°"
        case .power:
            value = snapshot?.power.totalWatts.map { Format.watts($0) } ?? "—"
            template = "100.0W"
        }
        return ReadoutCell(
            caption: server.caption, value: value,
            width: StatusBarRenderer.width(value: template, caption: server.caption))
    }

    static func stateText(_ state: ServerConnection.State) -> String {
        switch state {
        case .idle: return "paused"
        case .connecting: return "connecting"
        case .live: return "live"
        case .waiting(let until, let reason):
            let seconds = max(0, Int(until.timeIntervalSinceNow.rounded()))
            return "\(reason) Retrying in \(seconds) s."
        case .attention(let issue): return issue.title
        }
    }

    // MARK: - Clicks

    private func clicked(_ item: RexItem, event: NSEvent?, server: Server.ID?) {
        let rightClick = event?.type == .rightMouseUp
            || (event?.modifierFlags.contains(.control) ?? false)
        if rightClick {
            showMenu(for: item)
            return
        }
        if popover.isShown {
            popover.performClose(nil)
            return
        }
        navigation.selected = server
        show(from: item)
    }

    private func show(from item: RexItem) {
        guard let button = item.statusItem.button else { return }
        let root = PopoverView(
            fleet: fleet, store: store, settings: settings, navigation: navigation,
            actions: PopoverActions(
                addServer: { [weak self] in self?.openAddServer() },
                openSettings: { [weak self] in self?.openSettings() },
                close: { [weak self] in self?.popover.performClose(nil) }))
        var sized = root
        sized.maxHeight = min(760, (button.window?.screen?.visibleFrame.height ?? 900) - 40)
        let controller = NSHostingController(rootView: sized)
        // The popover follows the view's own size, so it grows when a server
        // is opened and shrinks back for the list.
        controller.sizingOptions = [.preferredContentSize]
        popover.contentViewController = controller
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        popover.contentViewController?.view.window?.makeKey()
        NSApp.activate(ignoringOtherApps: true)
    }

    func popoverDidClose(_ notification: Notification) {
        // Release the SwiftUI tree, or it keeps observing every connection.
        // A dashboard in it gives back its claim on full detail as it goes;
        // one in the window keeps its own.
        popover.contentViewController = nil
        navigation.selected = nil
    }

    private func showMenu(for item: RexItem) {
        let menu = NSMenu()
        menu.addItem(withTitle: "Open Window", action: #selector(windowAction), keyEquivalent: "o").target = self
        menu.addItem(withTitle: "Add Server…", action: #selector(addServerAction), keyEquivalent: "n").target = self
        menu.addItem(withTitle: "Settings…", action: #selector(settingsAction), keyEquivalent: ",").target = self
        menu.addItem(withTitle: "Reconnect All", action: #selector(reconnectAction), keyEquivalent: "r").target = self
        menu.addItem(.separator())
        menu.addItem(withTitle: "About Rex Boing Remote", action: #selector(aboutAction), keyEquivalent: "").target = self
        menu.addItem(withTitle: "Quit Rex Boing Remote", action: #selector(quitAction), keyEquivalent: "q").target = self
        item.statusItem.menu = menu
        item.statusItem.button?.performClick(nil)
        item.statusItem.menu = nil
    }

    @objc private func addServerAction() { openAddServer() }
    @objc private func windowAction() { openWindow() }
    @objc private func settingsAction() { openSettings() }
    @objc private func reconnectAction() { fleet.retryAll() }
    @objc private func quitAction() { NSApp.terminate(nil) }
    @objc private func aboutAction() {
        NSApp.activate(ignoringOtherApps: true)
        NSApp.orderFrontStandardAboutPanel(options: [
            .credits: NSAttributedString(
                string: "Watches your Linux, macOS and Windows servers over SSH, with the cards and characters of Rex Boing.\nhttps://github.com/rexyrex/Rex-Boing-Remote",
                attributes: [.font: NSFont.systemFont(ofSize: 11)]),
        ])
    }

    func openAddServer() {
        popover.performClose(nil)
        AddServerWindow.shared.show(store: store, fleet: fleet, settings: settings)
    }

    func openSettings() {
        popover.performClose(nil)
        SettingsWindow.shared.show(store: store, fleet: fleet, settings: settings)
    }
}

/// Which server the popover is showing; nil for the fleet list.
@MainActor
final class Navigation: ObservableObject {
    @Published var selected: Server.ID?
}

struct PopoverActions {
    var addServer: () -> Void
    var openSettings: () -> Void
    var close: () -> Void
}
