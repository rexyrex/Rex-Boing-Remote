import Foundation

/// One tool as `tools/list` describes it.
struct MCPToolDefinition: Sendable {
    var name: String
    var title: String
    var description: String
    var inputSchema: JSONValue

    var listing: JSONValue {
        [
            "name": .string(name),
            "title": .string(title),
            "description": .string(description),
            "inputSchema": inputSchema,
            // Every tool only reads what the app already holds.
            "annotations": [
                "title": .string(title),
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false,
            ],
        ]
    }
}

/// The parts of a server's snapshot an agent can ask for.
enum MCPSnapshotSection: String, CaseIterable, Sendable {
    case host, cpu, gpus, memory, thermal, power, pressure, network, disk, battery, system, notices
}

/// What processes can be ranked by: the agent's own rankings.
enum MCPProcessSort: String, CaseIterable, Sendable {
    case cpu, memory, gpu, disk
}

/// History's series under the names the tools give them, units included.
enum MCPHistorySeries: String, CaseIterable, Sendable {
    case cpuPercent, cpuUserPercent, cpuSystemPercent, memoryPercent, swapPercent, gpuPercent
    case cpuCelsius, gpuCelsius, powerWatts
    case networkReceivedBytesPerSecond, networkSentBytesPerSecond, diskReadBytesPerSecond, diskWriteBytesPerSecond

    var series: HistorySeries {
        switch self {
        case .cpuPercent: return .cpu
        case .cpuUserPercent: return .cpuUser
        case .cpuSystemPercent: return .cpuSystem
        case .memoryPercent: return .memory
        case .swapPercent: return .swap
        case .gpuPercent: return .gpu
        case .cpuCelsius: return .cpuCelsius
        case .gpuCelsius: return .gpuCelsius
        case .powerWatts: return .watts
        case .networkReceivedBytesPerSecond: return .rx
        case .networkSentBytesPerSecond: return .tx
        case .diskReadBytesPerSecond: return .read
        case .diskWriteBytesPerSecond: return .write
        }
    }

    /// History keeps fractions; the tools give percents.
    var scale: Double { rawValue.hasSuffix("Percent") ? 100 : 1 }

    var decimals: Int {
        switch self {
        case .cpuCelsius, .gpuCelsius: return 1
        case .powerWatts: return 2
        case .networkReceivedBytesPerSecond, .networkSentBytesPerSecond,
             .diskReadBytesPerSecond, .diskWriteBytesPerSecond: return 0
        default: return 1
        }
    }
}

/// A tool call whose arguments have been read and checked.
enum MCPCall: Sendable {
    case listServers(limit: Int)
    case snapshot(server: String, sections: [MCPSnapshotSection], limit: Int)
    case processes(server: String, sortBy: MCPProcessSort, limit: Int)
    case history(server: String, from: Date, to: Date, points: Int, series: [MCPHistorySeries])
    case processHistory(server: String, at: Date?, from: Date, to: Date, limit: Int, rows: Int, sortBy: MCPProcessSort)

    var server: String? {
        switch self {
        case .listServers: return nil
        case .snapshot(let server, _, _), .processes(let server, _, _), .history(let server, _, _, _, _),
             .processHistory(let server, _, _, _, _, _, _):
            return server
        }
    }
}

/// The tools: their definitions, and the reading of their arguments. The
/// bridge checks arguments with the same code before it reaches the app, so
/// bad input never launches anything.
enum MCPTools {
    static let listServers = "list_servers"
    static let getServerSnapshot = "get_server_snapshot"
    static let getServerProcesses = "get_server_processes"
    static let getServerHistory = "get_server_history"
    static let getServerProcessHistory = "get_server_process_history"

    // Bounds on every list, so no answer floods an agent's context.
    static let serverLimit = (default: 50, max: 200)
    static let listLimit = (default: 25, max: 200)
    static let processLimit = (default: 10, max: 20)
    static let pointLimit = (default: 60, max: 360)
    static let tableLimit = (default: 6, max: 48)
    static let rowLimit = (default: 5, max: 10)

    static func tool(named name: String) -> MCPToolDefinition? { all.first { $0.name == name } }

    private static let serverProperty: JSONValue = [
        "type": "string", "minLength": 1,
        "description": "The server's id or name, as list_servers gives them. Case-insensitive; a unique prefix or word of the name is enough.",
    ]

    private static func integer(_ description: String, _ bounds: (default: Int, max: Int), minimum: Int = 1) -> JSONValue {
        ["type": "integer", "minimum": .int(minimum), "maximum": .int(bounds.max), "default": .int(bounds.default),
         "description": .string(description)]
    }

    private static func moment(_ description: String, default value: String? = nil) -> JSONValue {
        var schema: [String: JSONValue] = ["type": "string", "minLength": 1, "description": .string(description)]
        if let value { schema["default"] = .string(value) }
        return .object(schema)
    }

    private static func enumeration<T: RawRepresentable & CaseIterable>(_ type: T.Type) -> JSONValue where T.RawValue == String {
        .array(T.allCases.map { .string($0.rawValue) })
    }

    private static func schema(_ properties: [String: JSONValue], required: [String] = []) -> JSONValue {
        var schema: [String: JSONValue] = [
            "type": "object", "properties": .object(properties), "additionalProperties": false,
        ]
        if !required.isEmpty { schema["required"] = .array(required.map(JSONValue.string)) }
        return .object(schema)
    }

    static let all: [MCPToolDefinition] = [
        MCPToolDefinition(
            name: listServers,
            title: "List servers",
            description: "Every server Rex Boing Remote watches: its id and name, how it is reached, its OS and model, "
                + "whether it is live, connecting or down (with why, since when, and when the next try is), its "
                + "headline vitals (CPU, memory, GPU, temperature, power, network, disk), what needs a person "
                + "(reboot needed, failed services, updates, the agent's own notices), the agent's version, and "
                + "whether the server keeps history in the background. Start here: the other tools take a "
                + "server's id or name from this list.",
            inputSchema: schema([
                "limit": integer("The most servers to list.", serverLimit),
            ])),
        MCPToolDefinition(
            name: getServerSnapshot,
            title: "Server snapshot",
            description: "Everything one server's dashboard shows now: the host, CPU per core with load and clocks, "
                + "every GPU with its engines, memory and swap, temperature sensors and fans, power, pressure "
                + "stall, network and its interfaces, disk throughput and every filesystem, battery, and system "
                + "(uptime, reboot needed, updates, failed services, containers), plus the agent's notices. "
                + "Choose parts with `sections`. The app asks the server for full detail while you ask, so a "
                + "first call can take a few seconds. A server that is down returns its last readings, with "
                + "their age and why it is down.",
            inputSchema: schema([
                "server": serverProperty,
                "sections": [
                    "type": "array", "uniqueItems": true, "minItems": 1,
                    "items": ["type": "string", "enum": enumeration(MCPSnapshotSection.self)],
                    "description": "The parts to include. All of them when left out.",
                ],
                "limit": integer("The most entries in each list (sensors, fans, GPUs, interfaces, filesystems, "
                                 + "failed services). Each list says its total and whether it was cut.", listLimit),
            ], required: ["server"])),
        MCPToolDefinition(
            name: getServerProcesses,
            title: "Server processes",
            description: "The top processes on one server now, as its dashboard ranks them by CPU, memory, GPU or "
                + "disk: pid, name, user, command line (the agent removes passwords and tokens before it leaves "
                + "the server), CPU as percent of one core (as top shows it, so it can pass 100), resident "
                + "memory, GPU and disk use, threads and start time. The agent ranks at most 20 per measure. "
                + "Asks the server for full detail while you ask, so a first call can take a few seconds.",
            inputSchema: schema([
                "server": serverProperty,
                "sortBy": ["type": "string", "enum": enumeration(MCPProcessSort.self), "default": "cpu",
                           "description": "The ranking to follow."],
                "limit": integer("The most processes to return.", processLimit),
            ], required: ["server"])),
        MCPToolDefinition(
            name: getServerHistory,
            title: "Server history",
            description: "One server's vitals over a window, from what the app holds: at most the last 48 hours. "
                + "Uses the finest record that covers the window (15 minutes of samples, 4 hours of 30-second "
                + "means, 48 hours of 5-minute means) and evens it out to at most `points` buckets. Each series "
                + "has the mean, min and max of every bucket, and a summary for the whole window with the time "
                + "of its highest reading. bucketEnds lists when each bucket ends. Buckets with no readings (the "
                + "server was off, or the Mac was away without background history) are left out. A server can "
                + "keep up to 30 days on its own disk, read on the server with `rex-boing-agent history`; that "
                + "is not reachable here.",
            inputSchema: schema([
                "server": serverProperty,
                "from": moment("The window's start: " + MCPTime.acceptedForms + ".", default: "1h"),
                "to": moment("The window's end, in the same forms.", default: "now"),
                "points": integer("The most buckets to return.", pointLimit, minimum: 2),
                "series": [
                    "type": "array", "uniqueItems": true, "minItems": 1,
                    "items": ["type": "string", "enum": enumeration(MCPHistorySeries.self)],
                    "description": "The series to include. Every series the server reports when left out.",
                ],
            ], required: ["server"])),
        MCPToolDefinition(
            name: getServerProcessHistory,
            title: "Server process history",
            description: "What was busy, and when: for each quarter hour, the process table of its busiest "
                + "moment (the most CPU). Where the server keeps history in the background these reach back 24 "
                + "hours, the time the Mac was away included; otherwise they cover only the times the app was "
                + "watching in full detail (a dashboard open, or these tools asking). Give `at` for the quarter "
                + "hour holding a moment (\"what was running at 03:00?\"), or a window with `from` and `to` for "
                + "its busiest quarter hours, listed in time order.",
            inputSchema: schema([
                "server": serverProperty,
                "at": moment("A moment whose quarter hour to show, instead of a window: " + MCPTime.acceptedForms + "."),
                "from": moment("The window's start, in the same forms.", default: "24h"),
                "to": moment("The window's end, in the same forms.", default: "now"),
                "limit": integer("The most quarter hours to return; the busiest when there are more.", tableLimit),
                "rows": integer("The most processes in each table.", rowLimit),
                "sortBy": ["type": "string", "enum": ["cpu", "memory"], "default": "cpu",
                           "description": "Which processes lead each table."],
            ], required: ["server"])),
    ]

    // MARK: - Reading arguments

    /// Reads a call's arguments, rejecting anything its schema would.
    static func parse(_ name: String, _ arguments: JSONValue, now: Date = Date()) throws -> MCPCall {
        guard let tool = tool(named: name) else {
            throw MCPToolError.badInput("There is no tool named \(name).")
        }
        var reader = try Reader(tool: tool, arguments: arguments)
        switch name {
        case listServers:
            let limit = try reader.integer("limit", serverLimit)
            try reader.finish()
            return .listServers(limit: limit)
        case getServerSnapshot:
            let server = try reader.server()
            let sections: [MCPSnapshotSection] = try reader.enumArray("sections") ?? MCPSnapshotSection.allCases
            let limit = try reader.integer("limit", listLimit)
            try reader.finish()
            return .snapshot(server: server, sections: sections, limit: limit)
        case getServerProcesses:
            let server = try reader.server()
            let sort: MCPProcessSort = try reader.enumValue("sortBy") ?? .cpu
            let limit = try reader.integer("limit", processLimit)
            try reader.finish()
            return .processes(server: server, sortBy: sort, limit: limit)
        case getServerHistory:
            let server = try reader.server()
            let (from, to) = try reader.window(defaultFrom: "1h", now: now)
            let points = try reader.integer("points", pointLimit, minimum: 2)
            let series: [MCPHistorySeries] = try reader.enumArray("series") ?? MCPHistorySeries.allCases
            try reader.finish()
            return .history(server: server, from: from, to: to, points: points, series: series)
        case getServerProcessHistory:
            let server = try reader.server()
            let at = try reader.moment("at", now: now)
            if at != nil, reader.has("from") || reader.has("to") {
                throw MCPToolError.badInput("Give either `at` (one quarter hour) or `from` and `to` (a window), not both.")
            }
            let (from, to) = try reader.window(defaultFrom: "24h", now: now)
            let limit = try reader.integer("limit", tableLimit)
            let rows = try reader.integer("rows", rowLimit)
            let sort: MCPProcessSort = try reader.enumValue("sortBy") ?? .cpu
            guard sort == .cpu || sort == .memory else {
                throw MCPToolError.badInput("sortBy takes cpu or memory here: the quarter-hour tables keep the leaders by those two.")
            }
            try reader.finish()
            return .processHistory(server: server, at: at, from: from, to: to, limit: limit, rows: rows, sortBy: sort)
        default:
            throw MCPToolError.badInput("There is no tool named \(name).")
        }
    }

    /// Takes the arguments one by one, so whatever is left at the end is an
    /// argument the tool doesn't have.
    private struct Reader {
        let tool: MCPToolDefinition
        var remaining: [String: JSONValue]

        init(tool: MCPToolDefinition, arguments: JSONValue) throws {
            self.tool = tool
            switch arguments {
            case .object(let object): remaining = object
            case .null: remaining = [:]
            default: throw MCPToolError.badInput("\(tool.name) takes its arguments as a JSON object.")
            }
        }

        private var names: String {
            (tool.inputSchema["properties"]?.objectValue?.keys.sorted() ?? []).joined(separator: ", ")
        }

        func has(_ key: String) -> Bool { remaining[key] != nil && remaining[key] != .null }

        mutating func take(_ key: String) -> JSONValue? {
            guard let value = remaining.removeValue(forKey: key), value != .null else { return nil }
            return value
        }

        func finish() throws {
            guard let extra = remaining.keys.sorted().first else { return }
            throw MCPToolError.badInput("\(tool.name) has no argument `\(extra)`. It takes: \(names).")
        }

        mutating func server() throws -> String {
            guard let value = take("server") else {
                throw MCPToolError.badInput("\(tool.name) needs `server`: a server's id or name from list_servers.")
            }
            guard let text = value.stringValue?.trimmingCharacters(in: .whitespaces), !text.isEmpty else {
                throw MCPToolError.badInput("`server` is a server's id or name, as a string.")
            }
            return text
        }

        mutating func integer(_ key: String, _ bounds: (default: Int, max: Int), minimum: Int = 1) throws -> Int {
            guard let value = take(key) else { return bounds.default }
            guard let number = value.intValue, (minimum...bounds.max).contains(number) else {
                throw MCPToolError.badInput("`\(key)` is a whole number from \(minimum) to \(bounds.max) (default \(bounds.default)).")
            }
            return number
        }

        mutating func enumValue<T: RawRepresentable & CaseIterable>(_ key: String) throws -> T? where T.RawValue == String {
            guard let value = take(key) else { return nil }
            guard let text = value.stringValue, let parsed = T(rawValue: text) else {
                throw MCPToolError.badInput("`\(key)` is one of \(T.allCases.map(\.rawValue).joined(separator: ", ")).")
            }
            return parsed
        }

        mutating func enumArray<T: RawRepresentable & CaseIterable>(_ key: String) throws -> [T]? where T.RawValue == String {
            guard let value = take(key) else { return nil }
            let allowed = T.allCases.map(\.rawValue).joined(separator: ", ")
            guard let items = value.arrayValue, !items.isEmpty else {
                throw MCPToolError.badInput("`\(key)` is a non-empty list drawn from: \(allowed).")
            }
            var result: [T] = []
            for item in items {
                guard let text = item.stringValue, let parsed = T(rawValue: text) else {
                    throw MCPToolError.badInput("`\(key)` has \(item.serializedString()), which isn't one of: \(allowed).")
                }
                guard !result.contains(where: { $0.rawValue == parsed.rawValue }) else {
                    throw MCPToolError.badInput("`\(key)` names \(text) twice; list each once.")
                }
                result.append(parsed)
            }
            return result
        }

        mutating func moment(_ key: String, now: Date) throws -> Date? {
            guard let value = take(key) else { return nil }
            guard let text = value.stringValue, let date = MCPTime.parseMoment(text, now: now) else {
                throw MCPToolError.badInput("`\(key)` takes \(MCPTime.acceptedForms). \(value.serializedString()) is none of those.")
            }
            return date
        }

        mutating func window(defaultFrom: String, now: Date) throws -> (Date, Date) {
            let from = try moment("from", now: now) ?? MCPTime.parseMoment(defaultFrom, now: now)!
            // Nothing is held for the future: a later `to` is now.
            let requestedTo = try moment("to", now: now) ?? now
            let to = min(requestedTo, now)
            guard from < to else {
                throw MCPToolError.badInput("`from` (\(MCPTime.format(from))) must come before `to` (\(MCPTime.format(to))).")
            }
            return (from, to)
        }
    }
}
