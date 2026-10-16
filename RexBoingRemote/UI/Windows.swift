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
        // Back to a menu bar app once no window is open.
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

/// The fleet and dashboards in an ordinary window, for when the menu bar has
/// no room for the rex — or for keeping an eye on a server while working.
@MainActor
final class DashboardWindow: HostedWindow {
    static let shared = DashboardWindow()
    private let navigation = Navigation()

    func show(fleet: Fleet, store: ServerStore, settings: AppSettings, actions: PopoverActions) {
        var view = PopoverView(fleet: fleet, store: store, settings: settings, navigation: navigation, actions: actions)
        view.maxHeight = 720
        present(title: "Rex Boing Remote", content: view)
    }
}
