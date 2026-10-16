import Foundation
import Combine
import OSLog
import RexBoingKit

let connectionLog = Logger(subsystem: "com.rexyrex.RexBoingRemote", category: "connection")

/// Keeps one server's agent stream alive and turns its samples into the
/// `Snapshot` and history Rex Boing's cards draw.
///
/// The rule this type exists to keep: once a server is added, the connection
/// comes back by itself — after the Mac sleeps, after either side reboots,
/// after Wi-Fi changes or a VPN drops — without the user doing anything, and
/// without hammering a server that is genuinely down. Only problems no retry
/// can fix (a changed host key, a removed key) stop it and ask for the user.
@MainActor
final class ServerConnection: ObservableObject, Identifiable {
    enum State: Equatable {
        /// Not running: the Mac is asleep, or the server was just added.
        case idle
        case connecting
        case live
        /// Waiting to retry after a failure the next attempt may not have.
        case waiting(until: Date, reason: String)
        /// Stopped on something retrying cannot fix.
        case attention(Issue)
    }

    enum Issue: Equatable {
        case hostKeyChanged
        case authenticationFailed(String)
        case agentMissing
        case localNetworkDenied
        case incompatibleAgent(String)

        var title: String {
            switch self {
            case .hostKeyChanged: return "The server's identity changed"
            case .authenticationFailed: return "The server refused Rex Boing Remote's key"
            case .agentMissing: return "The agent is missing on the server"
            case .localNetworkDenied: return "Local Network access is off"
            case .incompatibleAgent: return "The agent needs an update"
            }
        }

        var explanation: String {
            switch self {
            case .hostKeyChanged:
                return "Its SSH host key no longer matches the one saved when it was added. "
                    + "That happens after a reinstall, but it is also what an impostor looks like, "
                    + "so Rex Boing Remote stopped. If you expected it, remove the server and add it again."
            case .authenticationFailed(let detail):
                return "The key may have been removed from the server's authorized_keys. "
                    + "Repair reinstalls it. \(detail)"
            case .agentMissing:
                return "The agent's file was removed or moved. Repair copies it back."
            case .localNetworkDenied:
                return "macOS is blocking connections to your local network. Turn on Rex Boing Remote in "
                    + "System Settings › Privacy & Security › Local Network."
            case .incompatibleAgent(let version):
                return "The agent on the server (\(version)) speaks an older protocol. Repair updates it."
            }
        }

        /// Whether a slow retry is still worth it while waiting for the user.
        var retriesSlowly: Bool {
            switch self {
            case .hostKeyChanged, .incompatibleAgent: return false
            case .authenticationFailed, .agentMissing, .localNetworkDenied: return true
            }
        }
    }

    enum Demand: Equatable { case vitals, full }

    let id: Server.ID
    private(set) var server: Server

    @Published private(set) var state: State = .idle
    /// Nil until the first sample of the first session.
    @Published private(set) var snapshot: Snapshot?
    /// Updated just before `snapshot` is published, so a view reading both
    /// gets one coherent pair per sample.
    private(set) var history = MetricsHistory()
    let processHistory = ProcessHistory()
    @Published private(set) var hello: WireHello?
    @Published private(set) var notices: [String: String] = [:]
    @Published private(set) var lastSampleAt: Date?
    /// When the current problem began, for "offline for 3 minutes".
    @Published private(set) var downSince: Date?

    /// What the screen needs from this server right now.
    var demand: Demand = .vitals {
        didSet { if oldValue != demand { sendDemand() } }
    }

    /// Seconds between samples while only vitals are wanted.
    var vitalsInterval: Double = 2 {
        didSet { if oldValue != vitalsInterval { sendDemand() } }
    }

    private var session: AgentSession?
    private var stopping = false
    private var attempt = 0
    private var addressIndex = 0
    private var retryTimer: Timer?
    private var startedAt: Date?
    private var sawHello = false
    private var avoidAgent = true

    init(server: Server) {
        self.id = server.id
        self.server = server
    }

    /// Picks up edits to the saved server. A change to how it is reached
    /// restarts the stream; a cosmetic change (name, character) does not.
    func update(_ newValue: Server) {
        let reconnect = newValue.host != server.host || newValue.user != server.user
            || newValue.port != server.port || newValue.addresses != server.addresses
            || newValue.auth != server.auth || newValue.hostKeyAlias != server.hostKeyAlias
        server = newValue
        if reconnect { restart() }
    }

    // MARK: - Lifecycle

    func start() {
        guard session == nil else { return }
        retryTimer?.invalidate()
        retryTimer = nil
        stopping = false
        sawHello = false
        state = .connecting
        startedAt = Date()
        let target = SSH.Target.forServer(server, address: currentAddress)
        let server = self.server
        Task { [weak self] in
            // Resolving the user's config costs a few milliseconds and tells
            // whether a jump host is involved, which decides whether the
            // user's SSH agent may be needed to get there.
            let config = await SSH.resolve(target.destination)
            guard let self, self.state == .connecting, self.session == nil, !self.stopping else { return }
            self.avoidAgent = !SSH.usesJumpHost(config)
            var arguments = SSH.background(target, auth: server.auth, avoidAgent: self.avoidAgent)
            switch server.auth {
            case .appKey:
                arguments.append("stream")
            case .userSSH:
                arguments.append(server.remoteAgentPath + " stream")
            }
            self.launch(arguments)
        }
    }

    private func launch(_ arguments: [String]) {
        let reference = SessionReference()
        let session = AgentSession(arguments: arguments) { [weak self] event in
            // Only the current session may change state. A session that was
            // stopped or replaced can still deliver a last sample or its end
            // a moment later, and acting on it would mark a dead stream live.
            guard let self, let current = self.session, current === reference.session else { return }
            self.handle(event)
        }
        reference.session = session
        self.session = session
        do {
            try session.start()
            connectionLog.info("\(self.server.name, privacy: .public): started ssh (pid \(session.pid))")
        } catch {
            self.session = nil
            scheduleRetry(reason: "Couldn't start ssh: \(error.localizedDescription)")
        }
    }

    /// Stops the stream on purpose — the Mac is going to sleep, or the
    /// server is being removed. No retry follows.
    func stop() {
        if session != nil { connectionLog.info("\(self.server.name, privacy: .public): stopping") }
        stopping = true
        retryTimer?.invalidate()
        retryTimer = nil
        session?.stop()
        session = nil
        if case .attention = state { return }
        state = .idle
    }

    func restart() {
        stop()
        attempt = 0
        start()
    }

    /// Something suggests the network is back (wake, a new route, the user
    /// asked): try now instead of waiting out the backoff.
    func retryNow() {
        switch state {
        case .waiting:
            attempt = max(0, attempt - 1)
            retryTimer?.invalidate()
            retryTimer = nil
            start()
        case .attention(let issue) where issue.retriesSlowly:
            retryTimer?.invalidate()
            retryTimer = nil
            start()
        case .idle:
            start()
        default:
            break
        }
    }

    /// Called every couple of seconds by the fleet. A stream that has gone
    /// quiet is a dead stream — the link died somewhere ssh's keepalive has
    /// not noticed yet — so it is ended and retried rather than trusted.
    func watchdog(now: Date) {
        switch state {
        case .connecting:
            guard let startedAt, now.timeIntervalSince(startedAt) > 40 else { return }
            if let session {
                connectionLog.notice("\(self.server.name, privacy: .public): no hello in 40 s, ending the attempt")
                session.kill()
            } else {
                // Stuck before ssh even started; begin again.
                start()
            }
        case .live:
            let interval = demand == .full ? 1 : vitalsInterval
            let silence = max(12, interval * 4 + 4)
            guard let last = lastSampleAt, now.timeIntervalSince(last) > silence else { return }
            if let session {
                connectionLog.notice("\(self.server.name, privacy: .public): silent for \(Int(now.timeIntervalSince(last))) s, ending the session")
                session.kill()
            } else {
                // Live with nothing behind it can only be a bug, but the
                // promise is that a connection always comes back: so it does.
                connectionLog.error("\(self.server.name, privacy: .public): live without a session; reconnecting")
                scheduleRetry(reason: "The connection dropped.")
            }
        default:
            break
        }
    }

    /// A network change: a live stream that is already late is probably on a
    /// dead route, so it is restarted now instead of after the watchdog.
    func networkChanged(now: Date) {
        if case .live = state, let last = lastSampleAt,
           now.timeIntervalSince(last) > max(4, vitalsInterval * 2) {
            session?.kill()
        } else {
            retryNow()
        }
    }

    // MARK: - Events

    private func handle(_ event: AgentSession.Event) {
        switch event {
        case .message(let message):
            handle(message)
        case .ended(let status, let stderr):
            session = nil
            guard !stopping else { return }
            connectionLog.notice("\(self.server.name, privacy: .public): ssh ended (status \(status)): \(stderr.suffix(300), privacy: .public)")
            ended(status: status, stderr: stderr)
        }
    }

    private func handle(_ message: WireMessage) {
        switch message {
        case .hello(let hello):
            sawHello = true
            connectionLog.info("\(self.server.name, privacy: .public): hello from agent \(hello.agent?.version ?? "?", privacy: .public)")
            self.hello = hello
            if (hello.protocol ?? 0) < 1 {
                state = .attention(.incompatibleAgent(hello.agent?.version ?? "unknown"))
                session?.stop()
                return
            }
            sendDemand()
        case .sample(let sample):
            let previous = snapshot
            let next = Snapshot(sample: sample, host: hello?.host, previous: previous)
            if sample.resync != true { history.record(next) }
            if sample.processes != nil { processHistory.record(next) }
            snapshot = next
            lastSampleAt = Date()
            if state != .live {
                state = .live
                downSince = nil
            }
            attempt = 0
        case .notice(let code, let message):
            notices[code] = message
        case .other:
            break
        }
    }

    private func sendDemand() {
        guard let session, sawHello else { return }
        switch demand {
        case .vitals:
            session.send(["want": "vitals"])
            session.send(["interval": vitalsInterval])
        case .full:
            session.send(["want": "full"])
            session.send(["interval": 1])
        }
    }

    private func ended(status: Int32, stderr: String) {
        if downSince == nil { downSince = Date() }
        let text = stderr.lowercased()
        let explanation = Self.explain(stderr: stderr, status: status)

        if text.contains("remote host identification has changed")
            || (text.contains("host key verification failed") && server.hostKeyAlias != nil)
            || text.contains("host key for") && text.contains("has changed") {
            state = .attention(.hostKeyChanged)
            return
        }
        if text.contains("host key verification failed") {
            // An unknown key for a server added from the user's SSH config:
            // treated like a change, since the key was saved during setup.
            state = .attention(.hostKeyChanged)
            return
        }
        if text.contains("permission denied") || text.contains("too many authentication failures") {
            state = .attention(.authenticationFailed(explanation))
            scheduleSlowRetry()
            return
        }
        if status == 127 || text.contains("no such file or directory")
            || text.contains("is not recognized as an internal or external command")
            || text.contains("command not found") {
            state = .attention(.agentMissing)
            scheduleSlowRetry()
            return
        }
        if text.contains("no route to host"), LocalNetwork.isLocal(SSH.Target.forServer(server, address: currentAddress).destination) {
            Task { [weak self] in
                let denied = await LocalNetwork.isDenied(host: self?.currentHostForProbe ?? "", port: self?.server.port ?? 22)
                guard let self else { return }
                if denied {
                    self.state = .attention(.localNetworkDenied)
                    self.scheduleSlowRetry()
                } else {
                    self.advanceAddress()
                    self.scheduleRetry(reason: explanation)
                }
            }
            return
        }
        advanceAddress()
        scheduleRetry(reason: explanation)
    }

    /// Delays: 1, 2, 4, 8, 15, 30 seconds, then once a minute, each with a
    /// little jitter so a fleet that dropped together does not retry in
    /// lockstep. A sample resets it.
    private func scheduleRetry(reason: String) {
        attempt += 1
        let steps: [Double] = [1, 2, 4, 8, 15, 30, 60]
        let base = steps[min(attempt - 1, steps.count - 1)]
        let delay = base * Double.random(in: 0.8...1.2)
        let until = Date().addingTimeInterval(delay)
        connectionLog.info("\(self.server.name, privacy: .public): retrying in \(String(format: "%.1f", delay), privacy: .public) s (\(reason, privacy: .public))")
        state = .waiting(until: until, reason: reason)
        arm(after: delay)
    }

    /// While a problem needs the user, keep trying every few minutes in case
    /// it was transient after all — a home directory mounted late, a key
    /// briefly unreadable — without filling the server's auth log.
    private func scheduleSlowRetry() {
        arm(after: 300 * Double.random(in: 0.9...1.1))
    }

    private func arm(after delay: TimeInterval) {
        retryTimer?.invalidate()
        let timer = Timer(timeInterval: delay, repeats: false) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, self.session == nil, !self.stopping else { return }
                self.start()
            }
        }
        timer.tolerance = min(5, delay * 0.1)
        // Common modes, so a retry still fires while a menu is open or an
        // alert is up.
        RunLoop.main.add(timer, forMode: .common)
        retryTimer = timer
    }

    // MARK: - Addresses

    /// For servers added by pairing code: the address to try next. Each
    /// failure moves on to the next one, so a laptop that left the LAN finds
    /// the server over Tailscale or the public address on its own.
    private var currentAddress: String? {
        guard !server.addresses.isEmpty else { return nil }
        return server.addresses[addressIndex % server.addresses.count]
    }

    private var currentHostForProbe: String {
        currentAddress ?? server.host
    }

    private func advanceAddress() {
        guard server.addresses.count > 1 else { return }
        addressIndex = (addressIndex + 1) % server.addresses.count
    }

    // MARK: - Messages

    /// The one line of ssh's stderr worth showing, rephrased where it helps.
    static func explain(stderr: String, status: Int32) -> String {
        let lines = stderr.split(separator: "\n").map {
            $0.trimmingCharacters(in: .whitespaces)
        }.filter { line in
            !line.isEmpty
                // Informational lines newer OpenSSH prints on every connect.
                && !line.hasPrefix("** ")
                && !line.lowercased().contains("post-quantum")
                && !line.lowercased().hasPrefix("warning: permanently added")
        }
        guard let line = lines.last else {
            return status == 0 ? "The server ended the session." : "The connection ended (status \(status))."
        }
        let lower = line.lowercased()
        if lower.contains("could not resolve hostname") { return "Can't find the server's address right now." }
        if lower.contains("operation timed out") || lower.contains("connection timed out") {
            return "The server isn't answering."
        }
        if lower.contains("connection refused") { return "The server refused the connection; SSH may be restarting." }
        if lower.contains("network is unreachable") { return "No network." }
        if lower.contains("no route to host") { return "No route to the server." }
        if lower.contains("broken pipe") || lower.contains("connection reset")
            || lower.contains("closed by remote host") || lower.contains("connection closed") {
            return "The connection dropped."
        }
        return String(line.prefix(200))
    }
}

/// Lets a session's event handler recognise its own session without keeping
/// it alive.
private final class SessionReference: @unchecked Sendable {
    weak var session: AgentSession?
}
