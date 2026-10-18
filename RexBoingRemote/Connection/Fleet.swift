import AppKit
import Combine
import Network
import RexBoingKit

/// Every server's connection, kept in step with the saved list, and the one
/// place that reacts to the Mac sleeping, waking and changing networks.
@MainActor
final class Fleet: ObservableObject {
    @Published private(set) var connections: [Server.ID: ServerConnection] = [:]
    /// Bumped whenever any connection's state or sample changes, so views of
    /// the whole fleet can observe one object.
    @Published private(set) var revision = 0

    let store: ServerStore
    private let settings: AppSettings
    private var cancellables = Set<AnyCancellable>()
    private var connectionObservers: [Server.ID: AnyCancellable] = [:]
    private var watchdog: Timer?
    private let pathMonitor = NWPathMonitor()
    private var lastPath: (status: NWPath.Status, interfaces: [String])?
    private var networkSettle: Timer?
    private var asleep = false

    init(store: ServerStore, settings: AppSettings) {
        self.store = store
        self.settings = settings

        store.$servers
            .sink { [weak self] servers in self?.sync(servers) }
            .store(in: &cancellables)

        settings.$vitalsInterval
            .sink { [weak self] interval in
                self?.connections.values.forEach { $0.vitalsInterval = interval }
            }
            .store(in: &cancellables)

        let workspace = NSWorkspace.shared.notificationCenter
        workspace.addObserver(
            forName: NSWorkspace.willSleepNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.willSleep() }
        }
        workspace.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.didWake() }
        }

        let reference = WeakReference(self)
        pathMonitor.pathUpdateHandler = { path in
            let status = path.status
            let interfaces = path.availableInterfaces.map(\.name).sorted()
            DispatchQueue.main.async {
                MainActor.assumeIsolated { reference.value?.pathChanged(status: status, interfaces: interfaces) }
            }
        }
        pathMonitor.start(queue: DispatchQueue(label: "com.rexyrex.RexBoingRemote.path"))

        let timer = Timer(timeInterval: 2, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                let now = Date()
                self?.connections.values.forEach { $0.watchdog(now: now) }
            }
        }
        timer.tolerance = 0.5
        RunLoop.main.add(timer, forMode: .common)
        watchdog = timer
    }

    func connection(_ id: Server.ID) -> ServerConnection? { connections[id] }

    /// Servers in the saved order, with their connections.
    var ordered: [(server: Server, connection: ServerConnection)] {
        store.servers.compactMap { server in
            connections[server.id].map { (server, $0) }
        }
    }

    /// The load the fleet rex runs at: the busiest live server's CPU.
    var busiestLoad: Double {
        connections.values.compactMap { connection -> Double? in
            guard connection.state == .live else { return nil }
            return connection.snapshot?.cpu.total
        }.max() ?? 0
    }

    var liveCount: Int { connections.values.filter { $0.state == .live }.count }

    var needsAttention: Bool {
        connections.values.contains { if case .attention = $0.state { return true } else { return false } }
    }

    func retryAll() {
        connections.values.forEach { $0.retryNow() }
    }

    // MARK: - Keeping in step with the saved list

    private func sync(_ servers: [Server]) {
        let ids = Set(servers.map(\.id))
        for (id, connection) in connections where !ids.contains(id) {
            connection.stop()
            connections[id] = nil
            connectionObservers[id] = nil
        }
        for server in servers {
            if let existing = connections[server.id] {
                existing.update(server)
            } else {
                let connection = ServerConnection(server: server)
                connection.vitalsInterval = settings.vitalsInterval
                connections[server.id] = connection
                connectionObservers[server.id] = connection.objectWillChange
                    .sink { [weak self] _ in
                        DispatchQueue.main.async {
                            MainActor.assumeIsolated { self?.revision &+= 1 }
                        }
                    }
                if !asleep { connection.start() }
            }
        }
        revision &+= 1
    }

    // MARK: - Sleep, wake and the network

    /// Ends every stream before the Mac sleeps. The agents exit as their
    /// sessions close, so nothing is left running on the servers, and the
    /// first thing after wake is a clean reconnect rather than a wait for
    /// dead TCP connections to time out.
    private func willSleep() {
        asleep = true
        connections.values.forEach { $0.stop() }
    }

    private func didWake() {
        asleep = false
        // A moment for Wi-Fi to reassociate; the path monitor retries again
        // the instant a route appears, so this only sets the first attempt.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
            MainActor.assumeIsolated {
                guard let self, !self.asleep else { return }
                self.connections.values.forEach { $0.retryNow() }
            }
        }
    }

    private func pathChanged(status: NWPath.Status, interfaces: [String]) {
        defer { lastPath = (status, interfaces) }
        guard !asleep, let lastPath else { return }
        guard status == .satisfied else { return }
        if lastPath.status != .satisfied || lastPath.interfaces != interfaces {
            // Interfaces change in bursts — a VPN or Tailscale coming up adds
            // and renames several within a second or two — so the
            // connections hear about it once, when the burst has settled.
            networkSettle?.invalidate()
            let timer = Timer(timeInterval: 2, repeats: false) { [weak self] _ in
                MainActor.assumeIsolated {
                    guard let self, !self.asleep else { return }
                    let now = Date()
                    self.connections.values.forEach { $0.networkChanged(now: now) }
                }
            }
            RunLoop.main.add(timer, forMode: .common)
            networkSettle = timer
        }
    }
}

/// A weak reference that can cross into a `@Sendable` callback; the value is
/// only ever read back on the main actor.
final class WeakReference<Value: AnyObject>: @unchecked Sendable {
    weak var value: Value?
    init(_ value: Value) { self.value = value }
}
