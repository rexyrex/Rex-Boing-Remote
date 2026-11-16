import AppKit
import SwiftUI

/// A window that hosts one SwiftUI view, released when it closes so the view
/// stops observing anything.
@MainActor
class HostedWindow: NSObject, NSWindowDelegate {
    private var window: NSWindow?

    func present<Content: View>(title: String, content: Content) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        if let window {
            window.contentViewController = NSHostingController(rootView: content)
            window.makeKeyAndOrderFront(nil)
            return
        }
        let window = NSWindow(contentViewController: NSHostingController(rootView: content))
        window.title = title
        window.styleMask = [.titled, .closable, .miniaturizable]
        window.isReleasedWhenClosed = false
        window.delegate = self
        window.center()
        window.makeKeyAndOrderFront(nil)
        self.window = window
    }

    func close() {
        window?.performClose(nil)
    }

    func windowWillClose(_ notification: Notification) {
        window?.contentViewController = nil
        window = nil
        Self.returnToMenuBarIfNoWindows()
    }

    /// Back to a menu bar app once no window is open.
    static func returnToMenuBarIfNoWindows() {
        DispatchQueue.main.async {
            MainActor.assumeIsolated {
                if !NSApp.windows.contains(where: { $0.isVisible && $0.canBecomeMain }) {
                    NSApp.setActivationPolicy(.accessory)
                }
            }
        }
    }
}

@MainActor
final class AddServerWindow: HostedWindow {
    static let shared = AddServerWindow()

    func show(store: ServerStore, fleet: Fleet, settings: AppSettings) {
        present(
            title: "Add a Server",
            content: AddServerView(store: store, settings: settings, close: { [weak self] in self?.close() }))
    }
}

@MainActor
final class SettingsWindow: HostedWindow {
    static let shared = SettingsWindow()

    func show(store: ServerStore, fleet: Fleet, settings: AppSettings) {
        present(
            title: "Rex Boing Remote Settings",
            content: SettingsView(
                store: store, fleet: fleet, settings: settings,
                addServer: { AddServerWindow.shared.show(store: store, fleet: fleet, settings: settings) }))
    }
}

/// The fleet and its dashboards in an ordinary window: resizable, with the
/// servers down a sidebar and the selected one's cards in columns. It is the
/// way in when the menu bar has no room for the rex, and the way to keep an
/// eye on a server all afternoon. While it is open the app has a Dock icon
/// and a place in ⌘-Tab, like any app with a window.
///
/// Its own controller rather than a `HostedWindow`: showing it again brings
/// the same window forward with its selection and scroll position intact,
/// where the others rebuild their content each time.
@MainActor
final class DashboardWindow: NSObject, NSWindowDelegate {
    static let shared = DashboardWindow()

    /// Demo mode's window keeps a frame of its own, like its other settings.
    private static var frameName: String {
        Demo.isActive ? "RexBoingRemoteWindow-Demo" : "RexBoingRemoteWindow"
    }

    private var window: NSWindow?
    private let model = FleetWindowModel()

    /// Shows the window, on `selecting` if a server is named; a window that
    /// is already open otherwise keeps what it was showing.
    func show(fleet: Fleet, store: ServerStore, settings: AppSettings, actions: PopoverActions,
              selecting server: Server.ID? = nil) {
        NSApp.setActivationPolicy(.regular)

        if let server {
            model.selection = .server(server)
        } else if window == nil {
            model.selection = Self.opening(store.servers)
        }

        if let window {
            if window.isMiniaturized { window.deminiaturize(nil) }
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let hosting = NSHostingController(rootView: FleetWindowView(
            fleet: fleet, store: store, settings: settings, model: model, actions: actions))
        // SwiftUI fills in the title, subtitle and toolbar; the size is the
        // window's own, or the controller would shrink it to the view's
        // ideal each time.
        hosting.sceneBridgingOptions = [.title, .toolbars]
        hosting.sizingOptions = [.minSize]

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1320, height: 860),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered, defer: false)
        window.title = "Rex Boing Remote"
        window.toolbarStyle = .unified
        window.isReleasedWhenClosed = false
        window.tabbingMode = .disallowed
        window.collectionBehavior.insert(.fullScreenPrimary)
        window.delegate = self
        window.contentViewController = hosting
        if !window.setFrameUsingName(Self.frameName) {
            let visible = (window.screen ?? NSScreen.main)?.visibleFrame.size ?? NSSize(width: 1440, height: 900)
            window.setContentSize(NSSize(
                width: min(1320, visible.width - 80), height: min(860, visible.height - 80)))
            window.center()
        }
        window.setFrameAutosaveName(Self.frameName)
        self.window = window

        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// What a freshly opened window shows: the pinned server, or the only
    /// one — the machine the user is here for — and otherwise the fleet.
    private static func opening(_ servers: [Server]) -> FleetSelection {
        if servers.count == 1, let only = servers.first { return .server(only.id) }
        let pinned = servers.filter(\.pinned)
        if pinned.count == 1, let one = pinned.first { return .server(one.id) }
        return .overview
    }

    func close() {
        window?.performClose(nil)
    }

    func windowWillClose(_ notification: Notification) {
        window?.saveFrame(usingName: Self.frameName)
        // Released with the window, so the board gives back its claim on
        // full detail from the server and nothing keeps observing the fleet.
        window?.contentViewController = nil
        window = nil
        HostedWindow.returnToMenuBarIfNoWindows()
    }
}
