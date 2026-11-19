import Foundation
import OSLog
import RexBoingKit

let mcpLog = Logger(subsystem: "com.rexyrex.RexBoingRemote", category: "mcp")

/// The running app's side of the MCP server: answers the bridge's requests
/// on the message port from what the connections hold.
///
/// Every answer is immediate, because the port's callback runs on the main
/// run loop and must not wait. A tool that needs a server's full detail
/// takes a viewer lease, exactly as an open dashboard does, and answers
/// "retry" until a full sample has come in; the bridge asks again a moment
/// later. Leases are let go a little after the last request, so with no
/// agent asking, every server is back on cheap vitals.
@MainActor
final class MCPAppServer {
    typealias Servers = @MainActor () -> [(server: Server, connection: ServerConnection)]

    /// How long full detail is kept after the last call that wanted it.
    var linger: TimeInterval = 20
    /// How long a call waits for a full sample before answering with what
    /// is held.
    var fullWait: TimeInterval = 12

    /// How long, after the app starts, a call waits for servers still
    /// making their first connection: a bridge that has just started the
    /// app should not report every server as connecting.
    var startupWait: TimeInterval = 10

    private let servers: Servers
    private let portName: String
    private let startedAt = Date()
    private var port: MCPLocalPort?
    private var leases: [Server.ID: Lease] = [:]
    private var sweeper: Timer?

    private struct Lease {
        var lease: ViewerLease
        var since: Date
        var lastUse: Date
    }

    init(servers: @escaping Servers, portName: String = MCPPort.name(demo: Demo.isActive)) {
        self.servers = servers
        self.portName = portName
    }

    /// Off means no port at all: nothing can be asked.
    var enabled = false {
        didSet {
            guard enabled != oldValue else { return }
            if enabled { open() } else { close() }
        }
    }

    var isListening: Bool { port != nil }

    /// Which servers are held in full detail for an agent right now.
    var leasedServers: Set<Server.ID> { Set(leases.keys) }

    private func open() {
        guard port == nil else { return }
        port = MCPLocalPort(name: portName) { [weak self] request in
            self?.handle(request) ?? Self.encode(.failure(MCPToolError(.notRunning, "Rex Boing Remote is quitting.")))
        }
        if port == nil {
            mcpLog.error("Couldn't register the MCP port \(self.portName, privacy: .public); another copy may hold it.")
        }
    }

    private func close() {
        port?.invalidate()
        port = nil
        releaseAll()
    }

    func releaseAll() {
        leases.removeAll()
        sweeper?.invalidate()
        sweeper = nil
    }

    // MARK: - Requests

    enum Reply {
        case result(JSONValue)
        case failure(MCPToolError)
        case retry(afterMs: Int, message: String)
    }

    /// One request from the bridge: `{"tool": …, "arguments": {…}}`.
    func handle(_ request: Data) -> Data {
        guard let message = try? JSONValue.parse(request), let tool = message["tool"]?.stringValue else {
            return Self.encode(.failure(MCPToolError(.internal, "The request from the bridge couldn't be read.")))
        }
        return Self.encode(respond(tool: tool, arguments: message["arguments"] ?? [:]))
    }

    static func encode(_ reply: Reply) -> Data {
        switch reply {
        case .result(let value): return JSONValue.object(["result": value]).serialized()
        case .failure(let error): return error.json.serialized()
        case .retry(let ms, let message):
            return JSONValue.object(["retry": ["afterMs": .int(ms), "message": .string(message)]]).serialized()
        }
    }

    func respond(tool: String, arguments: JSONValue, now: Date = Date()) -> Reply {
        let call: MCPCall
        do {
            call = try MCPTools.parse(tool, arguments, now: now)
        } catch let error as MCPToolError {
            return .failure(error)
        } catch {
            return .failure(MCPToolError(.internal, error.localizedDescription))
        }
        let all = servers()
        if case .listServers(let limit) = call {
            if now.timeIntervalSince(startedAt) < startupWait, all.contains(where: { Self.isFirstConnect($0.connection) }) {
                return .retry(afterMs: 300, message: "Rex Boing Remote has just started and is still connecting to the servers.")
            }
            return .result(MCPPayload.listServers(all.map { Self.view($0.server, $0.connection) }, limit: limit, now: now))
        }
        guard let query = call.server else { return .failure(MCPToolError(.internal, "No server in the call.")) }
        let candidates = all.map { entry in
            MCPResolver.Candidate(
                id: entry.server.id, name: entry.server.name,
                aliases: [entry.server.host, entry.server.destinationLabel, entry.connection.hello?.host?.hostname].compactMap { $0 })
        }
        let index: Int
        switch MCPResolver.resolve(query, among: candidates) {
        case .success(let found): index = found
        case .failure(let error): return .failure(error)
        }
        let (server, connection) = all[index]

        switch call {
        case .listServers:
            return .failure(MCPToolError(.internal, "Unreachable."))
        case .snapshot(_, let sections, let limit):
            switch waitForFull(connection, needsProcesses: false, needsVolumes: sections.contains(.disk), now: now) {
            case .retry(let ms, let message): return .retry(afterMs: ms, message: message)
            case .ready(let waited):
                return .result(MCPPayload.snapshot(Self.view(server, connection), sections: sections, limit: limit, now: now, waited: waited))
            }
        case .processes(_, let sortBy, let limit):
            switch waitForFull(connection, needsProcesses: true, needsVolumes: false, now: now) {
            case .retry(let ms, let message): return .retry(afterMs: ms, message: message)
            case .ready(let waited):
                return .result(MCPPayload.processes(Self.view(server, connection), sortBy: sortBy, limit: limit, now: now, waited: waited))
            }
        case .history(_, let from, let to, let points, let series):
            // A server that keeps history sends it as soon as it connects.
            if now.timeIntervalSince(startedAt) < startupWait, Self.isFirstConnect(connection) {
                return .retry(afterMs: 300, message: "Still connecting to \(server.name).")
            }
            return .result(MCPPayload.history(Self.view(server, connection), from: from, to: to, points: points, series: series, now: now))
        case .processHistory(_, let at, let from, let to, let limit, let rows, let sortBy):
            if now.timeIntervalSince(startedAt) < startupWait, Self.isFirstConnect(connection) {
                return .retry(afterMs: 300, message: "Still connecting to \(server.name).")
            }
            return .result(MCPPayload.processHistory(
                Self.view(server, connection), at: at, from: from, to: to, limit: limit, rows: rows, sortBy: sortBy, now: now))
        }
    }

    /// Connecting, and never yet heard from in this run of the app.
    static func isFirstConnect(_ connection: ServerConnection) -> Bool {
        connection.state == .connecting && connection.lastSample == nil && connection.downSince == nil
    }

    static func view(_ server: Server, _ connection: ServerConnection) -> MCPServerView {
        MCPServerView(
            server: server, state: connection.state, downSince: connection.downSince, lastFailure: connection.lastFailure,
            hello: connection.hello,
            notices: connection.notices, latest: connection.lastSample, latestFull: connection.lastFullSample,
            detailTimes: connection.detailTimes, background: connection.background, rings: connection.rings, appTables: connection.processHistory.samples)
    }

    // MARK: - Full detail

    private enum Readiness {
        case ready(waited: String?)
        case retry(Int, String)
    }

    /// Holds full detail for `connection` and says whether a sample with it
    /// has come in since: one from the last couple of seconds (a dashboard
    /// may already be holding it), or one that arrived after the lease began.
    private func waitForFull(_ connection: ServerConnection, needsProcesses: Bool, needsVolumes: Bool, now: Date) -> Readiness {
        let lease = touch(connection, now: now)
        let waited = now.timeIntervalSince(lease.since)
        // One still making its first connection gets the time a full
        // sample would; one that isn't answering won't send any, so what is
        // held is the answer.
        if Self.isFirstConnect(connection), waited < fullWait {
            return .retry(400, "Still connecting to \(connection.server.name).")
        }
        guard connection.state == .live else { return .ready(waited: nil) }
        // Process tables come with every few full samples, not each one.
        let needed = needsProcesses ? connection.lastProcessTableAt : connection.lastFullSampleAt
        if let at = needed, now.timeIntervalSince(at) <= (needsProcesses ? 5 : 2.5) || at >= lease.since {
            // This repository's agents send the filesystems with every full
            // sample, but a recording (demo mode) or another agent may send
            // them only now and then: when they are asked for, they get a
            // few seconds to come.
            if !needsVolumes || connection.lastFullSample?.disk?.volumes != nil || waited >= 10 {
                return .ready(waited: nil)
            }
        }
        if waited < fullWait {
            return .retry(400, "Asked \(connection.server.name) for full detail; waiting for its next sample.")
        }
        return .ready(waited: "Full detail didn't arrive within \(Int(fullWait)) seconds; these are the newest readings held.")
    }

    private func touch(_ connection: ServerConnection, now: Date) -> Lease {
        if var held = leases[connection.id] {
            held.lastUse = now
            leases[connection.id] = held
            return held
        }
        let lease = Lease(lease: connection.addViewer(), since: now, lastUse: now)
        leases[connection.id] = lease
        mcpLog.info("\(connection.server.name, privacy: .public): full detail for an agent")
        armSweeper()
        return lease
    }

    private func armSweeper() {
        guard sweeper == nil else { return }
        let timer = Timer(timeInterval: 2, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.sweep(now: Date()) }
        }
        timer.tolerance = 0.5
        RunLoop.main.add(timer, forMode: .common)
        sweeper = timer
    }

    /// Lets go of the leases no agent has used for `linger`, and of those
    /// whose server was removed.
    func sweep(now: Date) {
        let all = servers()
        let present = Set(all.map(\.server.id))
        for (id, held) in leases where now.timeIntervalSince(held.lastUse) > linger || !present.contains(id) {
            leases[id] = nil
            let name = all.first { $0.server.id == id }?.server.name ?? id.uuidString
            mcpLog.info("\(name, privacy: .public): no agent asking; full detail let go")
        }
        if leases.isEmpty {
            sweeper?.invalidate()
            sweeper = nil
        }
    }
}
