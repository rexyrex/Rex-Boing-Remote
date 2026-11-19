import Foundation

/// The MCP surface's fixed facts: who the server is, which protocol
/// revisions it speaks, and what every client is told about the tools.
enum MCPServerInfo {
    static let name = "rex-boing-remote"
    static let title = "Rex Boing Remote"

    /// Revisions that open with an `initialize` handshake, newest first.
    static let legacyVersions = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]
    /// Revisions that carry the version in every request's `_meta` instead
    /// (2026-07-28 and later), newest first.
    static let modernVersions = ["2026-07-28"]
    static var supportedVersions: [String] { modernVersions + legacyVersions }

    static var version: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "dev"
        let build = info?["CFBundleVersion"] as? String
        return build.map { "\(short) (\($0))" } ?? short
    }

    /// For `initialize`: the client's version when it is one this server
    /// speaks, otherwise the newest handshake revision.
    static func negotiate(_ requested: String?) -> String {
        guard let requested, legacyVersions.contains(requested) else { return legacyVersions[0] }
        return requested
    }

    static let instructions = """
    Rex Boing Remote is a Mac menu bar app that watches the user's Linux, macOS and Windows servers over SSH. These tools read what it holds about them; none of them changes anything on the Mac or on a server.
    • Servers: `server` takes a server's id or its name (case-insensitive; a unique prefix or word of the name is enough). list_servers gives every server with its state, headline vitals and notices; start there.
    • Units are in the key names: …Percent is 0 to 100 (except a process's cpuPercent, which is percent of one core as top shows it, so it can pass 100), …Bytes, …BytesPerSecond, …Celsius, …Watts, …RPM, …Seconds. A reading a server cannot report is left out, never sent as 0.
    • Times are ISO 8601 with this Mac's UTC offset. Every reading carries sampledAt, and ageSeconds says how old it is. A server that is not answering keeps its last readings and its history, marked with why it is down.
    • Moments and windows take: now; how long ago, such as 90s, 15m, 6h, 2d; a time of day such as 03:00; or ISO 8601.
    • History: the app holds up to 48 hours per server (15 minutes of samples, 4 hours of 30-second means, 48 hours of 5-minute means), and the busiest processes of each quarter hour: from the last 24 hours where the server keeps history in the background, otherwise from while the app was watching. A server can keep up to 30 days on its own disk; that longer history is not reachable here. It is read on the server itself with `~/.local/share/rex-boing-remote/rex-boing-agent history` (`history --help` lists the options).
    • Errors are results with isError and {"error":{"code","message"}}. Codes: not_running (the app is not running), disabled (the user turned AI agent access off), not_ready, not_found (with candidates), bad_input, timeout, internal. The message says what to do next.
    """
}

/// JSON-RPC 2.0 framing: one JSON object per line.
enum JSONRPC {
    static let parseError = -32700
    static let invalidRequest = -32600
    static let methodNotFound = -32601
    static let invalidParams = -32602
    static let internalError = -32603
    /// MCP 2026-07-28's UnsupportedProtocolVersionError.
    static let unsupportedProtocolVersion = -32022

    static func result(id: JSONValue, _ result: JSONValue) -> JSONValue {
        ["jsonrpc": "2.0", "id": id, "result": result]
    }

    static func error(id: JSONValue, code: Int, message: String, data: JSONValue? = nil) -> JSONValue {
        var error: [String: JSONValue] = ["code": .int(code), "message": .string(message)]
        if let data { error["data"] = data }
        return ["jsonrpc": "2.0", "id": id, "error": .object(error)]
    }
}

/// A failure a tool reports to the agent, as an `isError` result rather than
/// a protocol error, so the agent can read it and act on it.
struct MCPToolError: Error, Sendable {
    enum Code: String, Sendable, CaseIterable {
        case notRunning = "not_running"
        case disabled
        case notReady = "not_ready"
        case notFound = "not_found"
        case badInput = "bad_input"
        case timeout
        case `internal`
    }

    var code: Code
    var message: String
    var detail: [String: JSONValue] = [:]

    init(_ code: Code, _ message: String, detail: [String: JSONValue] = [:]) {
        self.code = code
        self.message = message
        self.detail = detail
    }

    var json: JSONValue {
        var error = detail
        error["code"] = .string(code.rawValue)
        error["message"] = .string(message)
        return ["error": .object(error)]
    }

    init?(json: JSONValue) {
        guard let error = json["error"]?.objectValue,
              let code = error["code"]?.stringValue.flatMap(Code.init(rawValue:)),
              let message = error["message"]?.stringValue else { return nil }
        self.init(code, message, detail: error.filter { $0.key != "code" && $0.key != "message" })
    }

    static func badInput(_ message: String) -> MCPToolError { MCPToolError(.badInput, message) }
}

/// Tool results as MCP carries them: one text block of compact JSON.
enum MCPResult {
    static func tool(_ value: JSONValue, isError: Bool = false) -> JSONValue {
        var result: [String: JSONValue] = [
            "content": [["type": "text", "text": .string(value.serializedString())]],
        ]
        if isError { result["isError"] = true }
        return .object(result)
    }

    static func failure(_ error: MCPToolError) -> JSONValue { tool(error.json, isError: true) }
}

/// The protocol side of `Rex Boing Remote mcp`: reads JSON-RPC lines, answers
/// the handshake, discovery, ping and the tool list itself, and hands tool
/// calls to `call`, which reaches the running app. Knows nothing about ports
/// or processes, so the checks can drive it with scripted lines.
final class MCPSession: @unchecked Sendable {
    /// Runs one tool call to its result (a `CallToolResult`). Called off the
    /// reading thread; `isCancelled` turns true if the client cancels.
    typealias Call = @Sendable (_ tool: String, _ arguments: JSONValue, _ isCancelled: @Sendable () -> Bool) -> JSONValue

    private let call: Call
    private let output: @Sendable (Data) -> Void
    private let queue = DispatchQueue(label: "com.rexyrex.RexBoingRemote.mcp.calls", attributes: .concurrent)
    private let group = DispatchGroup()
    private let lock = NSLock()
    private var cancelled = Set<JSONValue>()
    private var inFlight = Set<JSONValue>()

    /// `output` receives each message to write, without its newline.
    init(call: @escaping Call, output: @escaping @Sendable (Data) -> Void) {
        self.call = call
        self.output = output
    }

    /// Waits until every tool call that has started has answered, or
    /// `timeout` passes.
    func drain(timeout: TimeInterval) {
        _ = group.wait(timeout: .now() + timeout)
    }

    func handle(line: Data) {
        // A blank line (or a stray carriage return) is not a message.
        let trimmed = line.drop { $0 == 0x20 || $0 == 0x09 || $0 == 0x0D }
        guard !trimmed.isEmpty else { return }
        guard let message = try? JSONValue.parse(Data(trimmed)) else {
            // Dropped silently, the client would wait on it forever.
            send(JSONRPC.error(id: .null, code: JSONRPC.parseError, message: "Not valid JSON. Send one JSON-RPC message per line."))
            return
        }
        if case .array = message {
            send(JSONRPC.error(id: .null, code: JSONRPC.invalidRequest, message: "Batches aren't supported; send one message per line."))
            return
        }
        guard case .object(let object) = message else {
            send(JSONRPC.error(id: .null, code: JSONRPC.invalidRequest, message: "A message must be a JSON object."))
            return
        }
        let id = object["id"].flatMap { $0 == .null ? nil : $0 }
        guard let method = object["method"]?.stringValue else {
            // A response to a request this server never sends: nothing to do.
            if object["result"] != nil || object["error"] != nil { return }
            send(JSONRPC.error(id: id ?? .null, code: JSONRPC.invalidRequest, message: "A request needs a method."))
            return
        }
        let params = object["params"]?.objectValue ?? [:]

        guard let id else {
            notification(method, params: params)
            return
        }

        // Revisions from 2026-07-28 name their version on every request; a
        // request without one is from a client that opened with initialize.
        let declared = params["_meta"]?["io.modelcontextprotocol/protocolVersion"]?.stringValue
        if let declared, !MCPServerInfo.supportedVersions.contains(declared) {
            send(JSONRPC.error(
                id: id, code: JSONRPC.unsupportedProtocolVersion, message: "Unsupported protocol version",
                data: ["supported": .array(MCPServerInfo.supportedVersions.map(JSONValue.string)), "requested": .string(declared)]))
            return
        }
        let modern = declared.map(MCPServerInfo.modernVersions.contains) ?? false

        switch method {
        case "initialize":
            let version = MCPServerInfo.negotiate(params["protocolVersion"]?.stringValue)
            reply(id, [
                "protocolVersion": .string(version),
                "capabilities": ["tools": [:]],
                "serverInfo": serverInfo,
                "instructions": .string(MCPServerInfo.instructions),
            ], modern: false)
        case "server/discover":
            reply(id, [
                "supportedVersions": .array(MCPServerInfo.supportedVersions.map(JSONValue.string)),
                "capabilities": ["tools": [:]],
                "instructions": .string(MCPServerInfo.instructions),
                "ttlMs": 3_600_000,
                "cacheScope": "private",
            ], modern: true)
        case "ping":
            reply(id, [:], modern: modern)
        case "tools/list":
            var result: [String: JSONValue] = ["tools": .array(MCPTools.all.map(\.listing))]
            if modern {
                // The list is fixed for the life of this executable.
                result["ttlMs"] = 3_600_000
                result["cacheScope"] = "private"
            }
            reply(id, .object(result), modern: modern)
        case "tools/call":
            guard let name = params["name"]?.stringValue else {
                send(JSONRPC.error(id: id, code: JSONRPC.invalidParams, message: "tools/call needs a tool name in params.name."))
                return
            }
            guard MCPTools.tool(named: name) != nil else {
                send(JSONRPC.error(
                    id: id, code: JSONRPC.invalidParams,
                    message: "Unknown tool: \(name). The tools are \(MCPTools.all.map(\.name).joined(separator: ", "))."))
                return
            }
            let arguments = params["arguments"] ?? [:]
            start(id: id, tool: name, arguments: arguments, modern: modern)
        default:
            send(JSONRPC.error(id: id, code: JSONRPC.methodNotFound, message: "Method not found: \(method)"))
        }
    }

    private var serverInfo: JSONValue {
        ["name": .string(MCPServerInfo.name), "title": .string(MCPServerInfo.title), "version": .string(MCPServerInfo.version)]
    }

    private func notification(_ method: String, params: [String: JSONValue]) {
        switch method {
        case "notifications/cancelled":
            guard let request = params["requestId"] else { return }
            lock.lock()
            if inFlight.contains(request) { cancelled.insert(request) }
            lock.unlock()
        default:
            // notifications/initialized and anything else: nothing to do.
            break
        }
    }

    private func start(id: JSONValue, tool: String, arguments: JSONValue, modern: Bool) {
        lock.lock()
        inFlight.insert(id)
        lock.unlock()
        group.enter()
        queue.async { [self] in
            defer { group.leave() }
            let result = call(tool, arguments) { [weak self] in self?.isCancelled(id) ?? true }
            lock.lock()
            let wasCancelled = cancelled.remove(id) != nil
            inFlight.remove(id)
            lock.unlock()
            // A cancelled request gets no further messages.
            if !wasCancelled { reply(id, result, modern: modern) }
        }
    }

    private func isCancelled(_ id: JSONValue) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled.contains(id)
    }

    /// Revisions from 2026-07-28 mark every result complete and name the
    /// server in it.
    private func reply(_ id: JSONValue, _ result: JSONValue, modern: Bool) {
        var result = result
        if modern, case .object(var fields) = result {
            fields["resultType"] = "complete"
            var meta = fields["_meta"]?.objectValue ?? [:]
            meta["io.modelcontextprotocol/serverInfo"] = serverInfo
            fields["_meta"] = .object(meta)
            result = .object(fields)
        }
        send(JSONRPC.result(id: id, result))
    }

    private func send(_ message: JSONValue) {
        output(message.serialized())
    }
}
