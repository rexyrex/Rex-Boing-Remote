import AppKit
import SwiftUI

@main
enum RemoteMain {
    @MainActor
    static func main() {
        // ssh runs this same executable as its askpass helper during setup.
        if Askpass.isRequested { Askpass.run() }

        // Writing to the stdin of an ssh that has just exited must be an
        // ordinary error, not a signal that ends the app.
        signal(SIGPIPE, SIG_IGN)

        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        app.run()
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var store: ServerStore?
    private var fleet: Fleet?
    private var status: StatusController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // One copy at a time: a second launch hands over to the first. A demo
        // copy shares nothing with a real one, so each hands over only to its
        // own kind, and the two can run side by side.
        let bundleID = Bundle.main.bundleIdentifier ?? ""
        let others = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
            .filter { $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }
            .filter { Demo.isMarked($0.processIdentifier) == Demo.isActive }
        if let running = others.first {
            // The running copy shows its window when it is reopened.
            NSWorkspace.shared.openApplication(at: running.bundleURL ?? Bundle.main.bundleURL,
                                               configuration: NSWorkspace.OpenConfiguration())
            NSApp.terminate(nil)
            return
        }

        if Demo.isActive { Demo.mark() }

        let settings = AppSettings.shared
        let store = Demo.isActive ? ServerStore(inMemory: Demo.servers) : ServerStore()
        let fleet = Fleet(store: store, settings: settings)
        self.store = store
        self.fleet = fleet
        status = StatusController(fleet: fleet, store: store, settings: settings)

        // The app's key exists before it is first needed, so the install
        // command can be shown at once.
        _ = try? AppKey.publicKey()

        if store.servers.isEmpty {
            status?.openAddServer()
        }
        // On a full menu bar the rexes can be hidden; the window always shows.
        if Demo.isActive {
            status?.openWindow()
        }
    }

    /// Opening the app again while it runs — from Applications, Spotlight or
    /// the Dock — shows the servers in a window, which is also the way in when
    /// macOS has hidden the menu bar item.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        status?.openWindow()
        return false
    }

    func applicationWillTerminate(_ notification: Notification) {
        fleet?.connections.values.forEach { $0.stop() }
        if Demo.isActive { Demo.unmark() }
    }
}
