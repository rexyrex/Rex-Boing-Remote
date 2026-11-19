import Foundation
import RexBoingKit

// Tools/check.sh mcp
//
// The MCP layer, headless: the stdio protocol against scripted lines, every
// tool's schema, payloads built from demo mode's recordings and from
// synthetic samples (units in the key names, missing readings left out,
// lists bounded), naming a server, and the whole path from a bridge through
// the message port to the app's answers over demo connections, leases and
// all.
@main
struct MCPCheck {
    @MainActor static func main() {
        var failures = 0
        func check(_ condition: Bool, _ message: String) {
            print("\(condition ? "PASS" : "FAIL")  \(message)")
            if !condition { failures += 1 }
        }
        let now = Date()

        // MARK: Protocol, against scripted lines

        final class Lines: @unchecked Sendable {
            private let lock = NSLock()
            private var lines: [Data] = []
            func append(_ data: Data) { lock.lock(); lines.append(data); lock.unlock() }
            func take() -> [Data] { lock.lock(); defer { lines = []; lock.unlock() }; return lines }
        }
        let lines = Lines()
        // A stand-in for the app: arguments are checked as the bridge checks
        // them, then the call is echoed. "slow" waits until cancelled.
        let session = MCPSession(call: { tool, arguments, isCancelled in
            if arguments["server"]?.stringValue == "slow" {
                let deadline = Date().addingTimeInterval(5)
                while !isCancelled() && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
                return MCPResult.tool(["slow": true])
            }
            do {
                _ = try MCPTools.parse(tool, arguments)
            } catch let error as MCPToolError {
                return MCPResult.failure(error)
            } catch {
                return MCPResult.failure(MCPToolError(.internal, "\(error)"))
            }
            return MCPResult.tool(["tool": .string(tool), "arguments": arguments])
        }, output: { lines.append($0) })

        func exchange(_ text: String) -> [JSONValue] {
            session.handle(line: Data(text.utf8))
            session.drain(timeout: 10)
            return lines.take().compactMap { try? JSONValue.parse($0) }
        }
        func request(_ id: Int, _ method: String, _ params: JSONValue = [:]) -> JSONValue? {
            exchange(JSONValue.object(["jsonrpc": "2.0", "id": .int(id), "method": .string(method), "params": params]).serializedString()).first
        }

        var reply = request(1, "initialize", ["protocolVersion": "2025-06-18", "capabilities": [:], "clientInfo": ["name": "check", "version": "1"]])
        check(reply?["result"]?["protocolVersion"] == "2025-06-18" && reply?["id"] == 1,
              "initialize echoes a protocol version it speaks")
        check(reply?["result"]?["serverInfo"]?["name"] == "rex-boing-remote"
              && reply?["result"]?["capabilities"] == ["tools": [:]]
              && (reply?["result"]?["instructions"]?.stringValue?.count ?? 0) > 400
              && reply?["result"]?["resultType"] == nil,
              "and names the server, offers tools only, and gives the instructions")
        let instructions = reply?["result"]?["instructions"]?.stringValue ?? ""
        check(["…Percent", "ISO 8601", "48 hours", "rex-boing-agent history", "not_found", "30 days"].allSatisfy(instructions.contains),
              "the instructions cover naming, units, times, the history held and where the longer history lives")
        reply = request(2, "initialize", ["protocolVersion": "1999-01-01"])
        check(reply?["result"]?["protocolVersion"] == .string(MCPServerInfo.legacyVersions[0]),
              "an unknown version gets the newest handshake revision (\(reply?["result"]?["protocolVersion"]?.stringValue ?? "-"))")
        check(exchange(#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).isEmpty, "notifications/initialized gets no answer")
        check(exchange(#"{"jsonrpc":"2.0","method":"notifications/whatever","params":{}}"#).isEmpty, "nor does an unknown notification")
        check(request(3, "ping")?["result"] == [:], "ping answers {}")
        reply = request(4, "tools/list")
        let listed = reply?["result"]?["tools"]?.arrayValue ?? []
        check(listed.count == MCPTools.all.count && listed.count == 5, "tools/list gives the \(listed.count) tools without the app")
        reply = request(5, "server/discover", ["_meta": ["io.modelcontextprotocol/protocolVersion": "2026-07-28"]])
        let supported = reply?["result"]?["supportedVersions"]?.arrayValue ?? []
        check(supported.contains("2026-07-28") && supported.contains("2025-11-25") && reply?["result"]?["resultType"] == "complete"
              && reply?["result"]?["_meta"]?["io.modelcontextprotocol/serverInfo"]?["name"] == "rex-boing-remote",
              "server/discover answers a 2026-07-28 client with every version it speaks")
        reply = request(6, "tools/list", ["_meta": ["io.modelcontextprotocol/protocolVersion": "2026-07-28"]])
        check(reply?["result"]?["ttlMs"] != nil && reply?["result"]?["cacheScope"] == "private" && reply?["result"]?["resultType"] == "complete",
              "a 2026-07-28 tools/list is marked complete and cacheable")
        reply = request(7, "tools/list", ["_meta": ["io.modelcontextprotocol/protocolVersion": "1900-01-01"]])
        check(reply?["error"]?["code"] == .int(JSONRPC.unsupportedProtocolVersion)
              && reply?["error"]?["data"]?["requested"] == "1900-01-01",
              "a version it doesn't speak is refused with -32022 and the list it does")
        check(request(8, "resources/list")?["error"]?["code"] == -32601, "an unknown method is -32601")
        check(exchange("this is not json").first?["error"]?["code"] == -32700, "a malformed line is -32700, and the server goes on")
        check(exchange(#"[{"jsonrpc":"2.0","id":9,"method":"ping"}]"#).first?["error"]?["code"] == -32600, "a batch is -32600")
        check(exchange("42").first?["error"]?["code"] == -32600, "a line that isn't an object is -32600")
        check(exchange("   \r").isEmpty, "a blank line is ignored")
        check(exchange(#"{"jsonrpc":"2.0","id":10,"result":{}}"#).isEmpty, "a stray response is ignored")
        reply = request(11, "tools/call", ["name": "drop_tables", "arguments": [:]])
        check(reply?["error"]?["code"] == -32602 && (reply?["error"]?["message"]?.stringValue ?? "").contains("list_servers"),
              "an unknown tool is -32602, naming the tools")
        check(request(12, "tools/call", ["arguments": [:]])?["error"]?["code"] == -32602, "a call without a name is -32602")

        func callResult(_ id: Int, _ tool: String, _ arguments: JSONValue) -> (payload: JSONValue?, isError: Bool, raw: JSONValue?) {
            let reply = request(id, "tools/call", ["name": .string(tool), "arguments": arguments])
            let result = reply?["result"]
            let content = result?["content"]?.arrayValue ?? []
            let text = content.first?["text"]?.stringValue
            let payload = content.count == 1 && content.first?["type"] == "text" ? text.flatMap { try? JSONValue.parse($0) } : nil
            return (payload, result?["isError"] == true, result)
        }
        let call = callResult(13, "get_server_history", ["server": "home", "from": "6h", "points": 30])
        let text = call.raw?["content"]?.arrayValue?.first?["text"]?.stringValue ?? ""
        check(call.payload?["tool"] == "get_server_history" && !call.isError && !text.contains("\n") && !text.contains(": "),
              "a call's result is one text block of compact JSON")
        let stringID = exchange(#"{"jsonrpc":"2.0","id":"abc","method":"ping"}"#).first
        check(stringID?["id"] == "abc", "string ids are echoed")

        let badInputs: [(String, JSONValue, String)] = [
            ("get_server_snapshot", [:], "a missing server"),
            ("get_server_snapshot", ["server": ""], "an empty server"),
            ("get_server_snapshot", ["server": 7], "a server that isn't a string"),
            ("list_servers", ["limit": 0], "a limit of 0"),
            ("list_servers", ["limit": 1000], "a limit past the cap"),
            ("list_servers", ["limit": 2.5], "a fractional limit"),
            ("list_servers", ["verbose": true], "an argument the tool doesn't have"),
            ("get_server_snapshot", ["server": "home", "sections": ["cpu", "bogus"]], "an unknown section"),
            ("get_server_snapshot", ["server": "home", "sections": []], "an empty section list"),
            ("get_server_processes", ["server": "home", "sortBy": "energy"], "an unknown ranking"),
            ("get_server_processes", ["server": "home", "limit": 21], "more processes than the agent ranks"),
            ("get_server_history", ["server": "home", "from": "last tuesday"], "a moment in no accepted form"),
            ("get_server_history", ["server": "home", "from": "1h", "to": "2h"], "a window that ends before it starts"),
            ("get_server_history", ["server": "home", "points": 1], "one point"),
            ("get_server_process_history", ["server": "home", "at": "03:00", "from": "6h"], "both a moment and a window"),
            ("get_server_process_history", ["server": "home", "sortBy": "gpu"], "a ranking the tables don't keep"),
            ("get_server_snapshot", "not an object", "arguments that aren't an object"),
        ]
        for (index, (tool, arguments, what)) in badInputs.enumerated() {
            let result = callResult(100 + index, tool, arguments)
            check(result.isError && result.payload?["error"]?["code"] == "bad_input"
                  && (result.payload?["error"]?["message"]?.stringValue?.count ?? 0) > 10,
                  "bad_input for \(what): \(result.payload?["error"]?["message"]?.stringValue ?? "-")")
        }
        let momentMessage = callResult(150, "get_server_history", ["server": "home", "from": "soon"]).payload?["error"]?["message"]?.stringValue ?? ""
        check(momentMessage.contains("15m") && momentMessage.contains("ISO 8601"), "and a bad moment's message names the accepted forms")

        // Cancelling a call in flight: no answer is sent for it.
        session.handle(line: Data(#"{"jsonrpc":"2.0","id":200,"method":"tools/call","params":{"name":"get_server_snapshot","arguments":{"server":"slow"}}}"#.utf8))
        Thread.sleep(forTimeInterval: 0.2)
        session.handle(line: Data(#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":200}}"#.utf8))
        session.drain(timeout: 6)
        check(lines.take().isEmpty, "a cancelled call gets no answer")

        // MARK: Schemas

        let keywords: Set<String> = ["type", "properties", "required", "additionalProperties", "description", "minimum",
                                     "maximum", "default", "enum", "items", "uniqueItems", "minItems", "minLength"]
        func wellFormed(_ schema: JSONValue, path: String, isProperty: Bool) -> [String] {
            guard let object = schema.objectValue else { return ["\(path) is not an object"] }
            var problems = object.keys.filter { !keywords.contains($0) }.map { "\(path) has unknown keyword \($0)" }
            let type = object["type"]?.stringValue
            if !["object", "string", "integer", "array", "boolean", "number"].contains(type ?? "") {
                problems.append("\(path) has no usable type")
            }
            if isProperty, (object["description"]?.stringValue?.count ?? 0) < 8 { problems.append("\(path) has no description") }
            if let values = object["enum"]?.arrayValue, values.isEmpty || Set(values).count != values.count || !values.allSatisfy({ $0.stringValue != nil }) {
                problems.append("\(path) has a bad enum")
            }
            if type == "integer" {
                let low = object["minimum"]?.intValue ?? .min, high = object["maximum"]?.intValue ?? .max
                if let value = object["default"]?.intValue, !(low...high).contains(value) { problems.append("\(path)'s default is out of range") }
            }
            if type == "object" {
                let properties = object["properties"]?.objectValue ?? [:]
                if object["additionalProperties"] != false { problems.append("\(path) allows other properties") }
                for name in object["required"]?.arrayValue ?? [] where properties[name.stringValue ?? ""] == nil {
                    problems.append("\(path) requires \(name) it doesn't define")
                }
                for (name, property) in properties { problems += wellFormed(property, path: "\(path).\(name)", isProperty: true) }
            }
            if type == "array" {
                if let items = object["items"] { problems += wellFormed(items, path: "\(path)[]", isProperty: false) } else { problems.append("\(path) has no items") }
            }
            return problems
        }
        func validates(_ value: JSONValue, _ schema: JSONValue) -> Bool {
            if let values = schema["enum"]?.arrayValue, !values.contains(value) { return false }
            switch schema["type"]?.stringValue {
            case "object":
                guard let object = value.objectValue else { return false }
                let properties = schema["properties"]?.objectValue ?? [:]
                for name in schema["required"]?.arrayValue ?? [] where object[name.stringValue ?? ""] == nil { return false }
                for (key, item) in object {
                    guard let property = properties[key] else { return false }
                    if !validates(item, property) { return false }
                }
                return true
            case "string":
                guard let text = value.stringValue else { return false }
                return text.count >= schema["minLength"]?.intValue ?? 0
            case "integer":
                guard let number = value.intValue, value.boolValue == nil else { return false }
                return number >= schema["minimum"]?.intValue ?? .min && number <= schema["maximum"]?.intValue ?? .max
            case "array":
                guard let items = value.arrayValue, items.count >= schema["minItems"]?.intValue ?? 0 else { return false }
                if schema["uniqueItems"] == true, Set(items).count != items.count { return false }
                guard let itemSchema = schema["items"] else { return true }
                return items.allSatisfy { validates($0, itemSchema) }
            default:
                return true
            }
        }
        for tool in MCPTools.all {
            let problems = wellFormed(tool.inputSchema, path: tool.name, isProperty: false)
            check(problems.isEmpty, "\(tool.name)'s schema is well formed\(problems.isEmpty ? "" : ": " + problems.joined(separator: "; "))")
            let listing = tool.listing
            check(tool.name.range(of: #"^(get|list)_[a-z]+(_[a-z]+)*$"#, options: .regularExpression) != nil
                  && tool.description.count > 150 && listing["annotations"]?["readOnlyHint"] == true
                  && listing["annotations"]?["destructiveHint"] == false,
                  "\(tool.name) is snake_case, verb first, described, and marked read-only")
        }
        // The schema and the argument reader agree, either way.
        let samples: [(String, JSONValue)] = [
            ("list_servers", [:]), ("list_servers", ["limit": 5]), ("list_servers", ["limit": 0]), ("list_servers", ["limit": "5"]),
            ("list_servers", ["other": 1]),
            ("get_server_snapshot", ["server": "pi"]), ("get_server_snapshot", ["server": "pi", "sections": ["cpu", "disk"], "limit": 3]),
            ("get_server_snapshot", ["server": "pi", "sections": ["cpu", "cpu"]]), ("get_server_snapshot", ["sections": ["cpu"]]),
            ("get_server_processes", ["server": "pi", "sortBy": "memory", "limit": 20]), ("get_server_processes", ["server": "pi", "sortBy": "power"]),
            ("get_server_history", ["server": "pi", "from": "2h", "to": "1h", "points": 360, "series": ["cpuPercent", "powerWatts"]]),
            ("get_server_history", ["server": "pi", "points": 361]), ("get_server_history", ["server": "pi", "series": ["cpu"]]),
            ("get_server_process_history", ["server": "pi", "at": "03:00", "rows": 10, "limit": 48]),
            ("get_server_process_history", ["server": "pi", "rows": 11]),
        ]
        var agreements = 0
        for (name, arguments) in samples {
            guard let tool = MCPTools.tool(named: name) else { continue }
            let bySchema = validates(arguments, tool.inputSchema)
            // (The reader is stricter on one thing a schema can't say: a
            // moment must be in an accepted form. None of these is.)
            let byReader = (try? MCPTools.parse(name, arguments, now: now)) != nil
            if bySchema == byReader { agreements += 1 }
            else { print("      disagree on \(name) \(arguments.serializedString()): schema \(bySchema), reader \(byReader)") }
        }
        check(agreements == samples.count, "the schemas and the argument reader agree on \(agreements) of \(samples.count) examples")

        // MARK: Times

        let reference = ISO8601DateFormatter().date(from: "2026-11-19T12:00:00Z")!
        check(MCPTime.parseMoment("90s", now: reference) == reference.addingTimeInterval(-90)
              && MCPTime.parseMoment("1h30m", now: reference) == reference.addingTimeInterval(-5400)
              && MCPTime.parseMoment("2d ago", now: reference) == reference.addingTimeInterval(-172_800)
              && MCPTime.parseMoment("now", now: reference) == reference,
              "durations ago are read")
        check(MCPTime.parseMoment("2026-11-19T03:00:00+09:00", now: reference) == ISO8601DateFormatter().date(from: "2026-11-18T18:00:00Z"),
              "ISO 8601 with an offset is read")
        let threeAM = MCPTime.parseMoment("03:00", now: reference)
        check(threeAM.map { $0 <= reference && reference.timeIntervalSince($0) < 86400 } ?? false, "a time of day is its latest past occurrence")
        check(["", "soon", "5x", "25:00", "m", "-5m", "2026-13-40"].allSatisfy { MCPTime.parseMoment($0, now: reference) == nil },
              "anything else is refused")
        let formatted = MCPTime.format(reference)
        check(formatted.range(of: #"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d([+-]\d\d:\d\d|Z)$"#, options: .regularExpression) != nil
              && MCPTime.parseMoment(formatted, now: now) == reference,
              "times are written in ISO 8601 with the Mac's offset (\(formatted)) and read back")

        // MARK: Naming a server

        let names = ["Web 1", "Web 2", "Database", "Raspberry Pi", "Gaming PC", "home-server"]
        let candidates = names.map { MCPResolver.Candidate(id: UUID(), name: $0, aliases: [$0 == "Database" ? "db.lan" : "x"]) }
        func resolved(_ query: String) -> String? {
            if case .success(let index) = MCPResolver.resolve(query, among: candidates) { return candidates[index].name }
            return nil
        }
        func failure(_ query: String) -> MCPToolError? {
            if case .failure(let error) = MCPResolver.resolve(query, among: candidates) { return error }
            return nil
        }
        check(resolved(candidates[3].id.uuidString.lowercased()) == "Raspberry Pi", "a server is found by its id")
        check(resolved("web 1") == "Web 1" && resolved("DATABASE") == "Database" && resolved("  gaming pc ") == "Gaming PC",
              "by its name, in any case")
        check(resolved("db.lan") == "Database", "by its host")
        check(resolved("rasp") == "Raspberry Pi" && resolved("pi") == "Raspberry Pi" && resolved("home") == "home-server"
              && resolved("server") == "home-server", "by a unique prefix of its name or of a word in it")
        let ambiguous = failure("web")
        check(ambiguous?.code == .notFound && ambiguous?.detail["candidates"]?.arrayValue?.count == 2,
              "an ambiguous name is not_found with the candidates: \(ambiguous?.message ?? "-")")
        check(failure("p")?.detail["candidates"]?.arrayValue?.compactMap { $0["name"]?.stringValue }.sorted() == ["Gaming PC", "Raspberry Pi"],
              "a word prefix two names share is ambiguous too")
        let unknown = failure("nas")
        check(unknown?.code == .notFound && unknown?.detail["candidates"]?.arrayValue?.count == names.count
              && (unknown?.message.contains("Database") ?? false), "an unknown name lists the servers there are")

        // MARK: Payloads

        /// Keys whose numbers carry no unit, or a count.
        let unitless: Set<String> = [
            "pid", "processes", "threads", "zombies", "physicalCores", "logicalCores", "performanceCores", "efficiencyCores",
            "coreCount", "index", "updates", "securityUpdates", "containers", "cycleCount", "processCount", "total", "live",
            "protocol", "energyImpact", "wakeupsPerSecond", "oneMinute", "fiveMinutes", "fifteenMinutes", "pointsHeld",
            "keptOnServerDays",
        ]
        let units = ["Percent", "Bytes", "BytesPerSecond", "Celsius", "Watts", "RPM", "Seconds", "MHz", "Mbps"]
        func hasUnit(_ key: String) -> Bool { units.contains { key.hasSuffix($0) } }
        let timeKeys: Set<String> = ["sampledAt", "nextRetryAt", "downSince", "since", "bootedAt", "startedAt", "now", "from", "to",
                                     "at", "heldSince", "maxAt", "quarterHourStart", "quarterHourEnd"]
        /// Every problem with a payload's conventions.
        func audit(_ value: JSONValue, key: String? = nil, unit: String? = nil, inProcess: Bool = false) -> [String] {
            switch value {
            case .double(let number) where !number.isFinite:
                return ["\(key ?? "?") is not finite"]
            case .int, .double:
                let number = value.doubleValue ?? 0
                let named = key.map { hasUnit($0) || unitless.contains($0) || $0.hasSuffix("Total") } ?? false
                guard named || unit != nil else { return ["\(key ?? "an array entry") has no unit in its name"] }
                let percentKey = (key.map(hasUnit) == true ? key : unit) ?? ""
                if percentKey.hasSuffix("Percent"), !(inProcess && percentKey == "cpuPercent"), !(0...100.05).contains(number) {
                    return ["\(percentKey) is \(number), outside 0 to 100"]
                }
                return []
            case .string(let text):
                if let key, timeKeys.contains(key) || key.hasSuffix("SampledAt") || key == "bucketEnds" {
                    if text.range(of: #"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d([+-]\d\d:\d\d|Z)$"#, options: .regularExpression) == nil {
                        return ["\(key) \(text) is not ISO 8601 with an offset"]
                    }
                }
                return []
            case .array(let items):
                let carried = key.flatMap { hasUnit($0) ? $0 : nil } ?? unit
                return items.flatMap { audit($0, key: key == "bucketEnds" ? key : nil, unit: carried, inProcess: inProcess || key == "processes") }
            case .object(let fields):
                let carried = key.flatMap { hasUnit($0) ? $0 : nil } ?? unit
                return fields.flatMap { audit($1, key: $0, unit: carried, inProcess: inProcess) }
            default:
                return []
            }
        }
        /// A payload as a client reads it back: whole numbers come back as integers.
        func wire(_ value: JSONValue) -> JSONValue { (try? JSONValue.parse(value.serialized())) ?? .null }
        func secrets(_ value: JSONValue) -> [String] {
            let text = value.serializedString()
            return ["id_ed25519", "Application Support", "known_hosts", "rbr1:", "ASKPASS", "BEGIN OPENSSH"].filter(text.contains)
        }

        Demo.recordingsDirectory = URL(fileURLWithPath: "RexBoingRemote/Demo/Recordings")
        for machine in Demo.machines {
            guard case .recording(let name) = machine.agent, let url = Demo.recordingURL(name),
                  let content = try? String(contentsOf: url, encoding: .utf8) else { continue }
            var hello: WireHello?
            var recorded: [WireSample] = []
            for line in content.split(separator: "\n") {
                switch WireMessage.decode(Data(line.utf8)) {
                case .hello(let value): hello = value
                case .sample(let value): recorded.append(value)
                default: break
                }
            }
            guard var full = recorded.last(where: { $0.processes != nil }) ?? recorded.last else {
                check(false, "\(name) has samples"); continue
            }
            full.t = Int64(now.timeIntervalSince1970 * 1000) - 4000
            full.detail = "full"
            // What an agent sends when only vitals are wanted.
            var vitals = full
            vitals.t = Int64(now.timeIntervalSince1970 * 1000) - 1000
            vitals.detail = "vitals"
            vitals.processes = nil
            vitals.thermal?.sensors = nil
            vitals.thermal?.fans = nil
            vitals.network?.interfaces = nil
            vitals.disk?.volumes = nil
            // The recording, spread over the last two and a half hours.
            var rings = HistoryRings(interval: 1, started: now.addingTimeInterval(-3 * 3600))
            let spacing = Int64(9_000_000 / max(1, recorded.count))
            for (index, sample) in recorded.enumerated() {
                var point = HistoryPoint(sample: sample)
                point.t = Int64(now.timeIntervalSince1970 * 1000) - Int64(recorded.count - index) * spacing
                rings.add(point)
            }
            let view = MCPServerView(server: machine.server, state: .live, hello: hello, latest: vitals, latestFull: full, rings: rings)
            let raw = [
                MCPPayload.listServers([view], limit: 50, now: now),
                MCPPayload.snapshot(view, sections: MCPSnapshotSection.allCases, limit: 25, now: now),
                MCPPayload.processes(view, sortBy: .cpu, limit: 10, now: now),
                MCPPayload.history(view, from: now.addingTimeInterval(-2 * 3600), to: now, points: 60,
                                   series: MCPHistorySeries.allCases, now: now),
            ]
            var problems: [String] = []
            for payload in raw { problems += audit(payload) + secrets(payload) }
            let (list, snapshot, processes, history) = (wire(raw[0]), wire(raw[1]), wire(raw[2]), wire(raw[3]))
            check(problems.isEmpty, "\(machine.server.name)'s payloads keep the conventions\(problems.isEmpty ? "" : ": " + problems.prefix(6).joined(separator: "; "))")
            let item = list["servers"]?.arrayValue?.first
            check(item?["vitals"]?["cpuPercent"]?.doubleValue == full.cpu?.total.map { JSONObject.round($0 * 100, 1) }
                  && item?["state"] == "live" && item?["model"]?.stringValue == hello?.host?.modelName,
                  "\(machine.server.name): the list's CPU is the sample's, as a percent")
            check(snapshot["thermal"]?["sensors"] != nil || full.thermal?.sensors == nil,
                  "\(machine.server.name): the snapshot takes the sensor list from the last full sample")
            check(snapshot["thermal"]?["sensorsSampledAt"] != nil || full.thermal?.sensors == nil,
                  "and says when that list came")
            let rows = processes["processes"]?.arrayValue ?? []
            let ranked = full.processes?.rank?["cpu"] ?? []
            check(rows.count == min(10, ranked.count) && rows.first?["pid"]?.intValue == ranked.first.map(Int.init),
                  "\(machine.server.name): processes follow the agent's CPU ranking (\(rows.count) rows)")
            let ends = history["bucketEnds"]?.arrayValue ?? []
            check(ends.count > 0 && ends.count <= 60
                  && history["series"]?["cpuPercent"]?["mean"]?.arrayValue?.count == ends.count
                  && history["record"]?["name"] == "30-second means",
                  "\(machine.server.name): two hours of history come from the 30-second record, in at most 60 buckets (\(ends.count))")
            if let gpus = full.gpus, !gpus.isEmpty {
                check(snapshot["gpus"]?.arrayValue?.count == min(gpus.count, 25), "\(machine.server.name): every GPU is listed")
            }
        }

        // Missing is not zero: what a sample leaves out stays out.
        var sparse = WireSample()
        sparse.t = Int64(now.timeIntervalSince1970 * 1000)
        sparse.detail = "full"
        var cpu = WireCPU()
        cpu.total = 0
        sparse.cpu = cpu
        var thermal = WireThermal()
        var hot = WireSensor(); hot.key = "Tc"; hot.label = "CPU"; hot.celsius = 61
        var blank = WireSensor(); blank.key = "Tx"; blank.label = "Unread"
        thermal.sensors = [hot, blank]
        sparse.thermal = thermal
        var volume = WireVolume(); volume.name = "/"; volume.total = 100; volume.available = 40
        var disk = WireDisk(); disk.volumes = [volume]
        sparse.disk = disk
        var row = WireProcessRow(); row.pid = 1; row.name = "init"; row.cpu = 0.5; row.memory = 1000
        var table = WireProcesses(); table.rows = [row]; table.rank = ["cpu": [1]]; table.sampledAt = sparse.t
        sparse.processes = table
        let sparseView = MCPServerView(server: Server(name: "Sparse", host: "sparse"), state: .live, latest: sparse, latestFull: sparse)
        let sparseSnapshot = wire(MCPPayload.snapshot(sparseView, sections: MCPSnapshotSection.allCases, limit: 25, now: now))
        let sparseItem = wire(MCPPayload.listServers([sparseView], limit: 5, now: now))["servers"]?.arrayValue?.first
        check(sparseSnapshot["cpu"] == ["totalPercent": 0], "a CPU at 0 says 0, and nothing more than it was sent")
        check(sparseSnapshot["memory"] == nil && sparseSnapshot["gpus"] == nil && sparseSnapshot["power"] == nil
              && sparseSnapshot["battery"] == nil && sparseSnapshot["pressure"] == nil,
              "sections a sample doesn't have are left out")
        check(sparseSnapshot["thermal"]?["sensors"]?.arrayValue?.count == 1 && sparseSnapshot["thermal"]?["cpuCelsius"] == nil,
              "a sensor with no reading is left out, and no temperature is made up")
        check(sparseSnapshot["disk"]?["volumes"]?.arrayValue?.first?["usedBytes"] == nil
              && sparseSnapshot["disk"]?["volumes"]?.arrayValue?.first?["usedPercent"] == 60
              && sparseSnapshot["disk"]?["readBytesPerSecond"] == nil,
              "a filesystem's used bytes are left out when not sent, and its fullness comes from what was")
        check(sparseItem?["vitals"]?["memoryPercent"] == nil && sparseItem?["vitals"]?["cpuCelsius"] == nil
              && sparseItem?["vitals"]?["powerWatts"] == nil && sparseItem?["vitals"]?["cpuPercent"] == 0,
              "the list's vitals leave out what the server can't report")
        let sparseRow = wire(MCPPayload.processes(sparseView, sortBy: .cpu, limit: 5, now: now))["processes"]?.arrayValue?.first
        check(sparseRow?["gpuPercent"] == nil && sparseRow?["diskReadBytesPerSecond"] == nil && sparseRow?["cpuPercent"] == 0.5,
              "a process row has only what the agent sent")
        var broken = sparse
        broken.cpu?.total = .nan
        broken.cpu?.perCore = [0.5, .infinity]
        let brokenRaw = MCPPayload.snapshot(MCPServerView(server: sparseView.server, state: .live, latest: broken), sections: [.cpu], limit: 5, now: now)
        let brokenSnapshot = wire(brokenRaw)
        check(brokenSnapshot["cpu"]?["totalPercent"] == nil && brokenSnapshot["cpu"]?["perCorePercent"] == [50, nil] && audit(brokenRaw).isEmpty,
              "numbers that aren't finite are dropped")

        // Bounded: long lists are cut, and say so.
        var crowded = sparse
        crowded.thermal?.sensors = (0..<500).map { index in
            var sensor = WireSensor(); sensor.key = "T\(index)"; sensor.celsius = Double(index % 90); return sensor
        }
        crowded.disk?.volumes = (0..<300).map { index in
            var volume = WireVolume(); volume.mount = "/mnt/\(index)"; volume.total = 1000; volume.available = UInt64(index); return volume
        }
        var network = WireNetwork()
        network.interfaces = (0..<100).map { index in var interface = WireInterface(); interface.name = "veth\(index)"; return interface }
        crowded.network = network
        var system = WireSystem(); system.failedServices = (0..<60).map { "unit\($0).service" }
        crowded.system = system
        crowded.gpus = (0..<40).map { index in var gpu = WireGPU(); gpu.name = "GPU \(index)"; gpu.utilization = 0.5; return gpu }
        crowded.processes?.rows = (1...20).map { pid in var row = WireProcessRow(); row.pid = Int32(pid); row.name = "p\(pid)"; row.cpu = Double(pid); return row }
        crowded.processes?.rank = ["cpu": (1...20).reversed().map { Int32($0) }]
        let crowdedView = MCPServerView(server: sparseView.server, state: .live, latest: crowded, latestFull: crowded)
        let crowdedSnapshot = wire(MCPPayload.snapshot(crowdedView, sections: MCPSnapshotSection.allCases, limit: 25, now: now))
        check(crowdedSnapshot["thermal"]?["sensors"]?.arrayValue?.count == 25 && crowdedSnapshot["thermal"]?["sensorsTotal"] == 500
              && crowdedSnapshot["thermal"]?["sensorsTruncated"] == true
              && crowdedSnapshot["thermal"]?["sensors"]?.arrayValue?.first?["temperatureCelsius"] == 89,
              "500 sensors are cut to the 25 hottest, and say so")
        check(crowdedSnapshot["disk"]?["volumes"]?.arrayValue?.count == 25 && crowdedSnapshot["disk"]?["volumesTotal"] == 300
              && crowdedSnapshot["network"]?["interfaces"]?.arrayValue?.count == 25 && crowdedSnapshot["network"]?["interfacesTruncated"] == true
              && crowdedSnapshot["system"]?["failedServices"]?.arrayValue?.count == 25 && crowdedSnapshot["system"]?["failedServicesTotal"] == 60
              && crowdedSnapshot["gpus"]?.arrayValue?.count == 25 && crowdedSnapshot["gpusTruncated"] == true,
              "and so are filesystems, interfaces, failed services and GPUs")
        let crowdedBytes = crowdedSnapshot.serialized().count
        check(crowdedBytes < 64 * 1024, "a crowded snapshot stays small (\(crowdedBytes) bytes)")
        let topFive = wire(MCPPayload.processes(crowdedView, sortBy: .cpu, limit: 5, now: now))
        check(topFive["processes"]?.arrayValue?.count == 5 && topFive["total"] == 20 && topFive["truncated"] == true
              && topFive["processes"]?.arrayValue?.first?["pid"] == 20,
              "processes are cut to the limit, busiest first, and say so")

        var longRings = HistoryRings(interval: 2, started: now.addingTimeInterval(-50 * 3600))
        let nowMS = Int64(now.timeIntervalSince1970 * 1000)
        for step in stride(from: 48 * 1800, through: 1, by: -1) {
            var point = HistoryPoint(t: nowMS - Int64(step) * 2000)
            point[.cpu] = Double(step % 100) / 100
            point[.memory] = 0.5
            point[.watts] = 20
            longRings.add(point)
        }
        let longView = MCPServerView(server: sparseView.server, state: .live, rings: longRings)
        let twoDays = wire(MCPPayload.history(longView, from: now.addingTimeInterval(-47 * 3600), to: now, points: 360,
                                              series: MCPHistorySeries.allCases, now: now))
        let twoDayEnds = twoDays["bucketEnds"]?.arrayValue?.count ?? 0
        check(twoDays["record"]?["name"] == "5-minute means" && twoDayEnds <= 360 && twoDayEnds > 300 && twoDays["downsampled"] == true
              && twoDays["series"]?["memoryPercent"]?["mean"]?.arrayValue?.first == 50
              && twoDays["series"]?["gpuPercent"] == nil && audit(twoDays).isEmpty,
              "47 hours come from the 5-minute record, evened out to at most 360 buckets, in percents (\(twoDayEnds) buckets)")
        check(twoDays.serialized().count < 256 * 1024, "and fit in \(twoDays.serialized().count) bytes")
        let quarter = wire(MCPPayload.history(longView, from: now.addingTimeInterval(-600), to: now, points: 60, series: [.cpuPercent], now: now))
        check(quarter["record"]?["name"] == "samples" && (quarter["bucketEnds"]?.arrayValue?.count ?? 0) == 60
              && quarter["summary"]?["cpuPercent"]?["max"] == 99 && quarter["summary"]?["cpuPercent"]?["maxAt"] != nil,
              "ten minutes come from the samples, with the peak and when it was")
        let older = MCPPayload.history(longView, from: now.addingTimeInterval(-5 * 86400), to: now, points: 60, series: [.cpuPercent], now: now)
        check((older["note"]?.stringValue ?? "").contains("rex-boing-agent history --from 5d"),
              "asking past 48 hours points to the history kept on the server")

        // The quarter-hour tables a background agent kept: "what was busy at 3 a.m."
        // Placed from the quarter hour now is in, not from now itself: "backup"
        // and "cron" are three minutes apart and must share a quarter hour
        // whatever the clock says when the check runs.
        var awayRings = HistoryRings(interval: 2)
        let quarterMS = Int64(HistoryRings.processStep * 1000)
        let anchorMS = nowMS / quarterMS * quarterMS + 5 * 60_000
        for (hoursAgo, name, cpu) in [(5.0, "backup", 95.0), (5.05, "cron", 30.0), (3.0, "rsync", 80.0), (1.0, "node", 12.0)] {
            var row = WireProcessRow(); row.pid = Int32(cpu); row.name = name; row.user = "alex"; row.cpu = cpu; row.memory = 1 << 28
            row.cmd = name + " --password=hunter2-already-redacted-by-the-agent"
            var table = WireProcesses(); table.count = 300; table.interval = 15; table.rows = [row]; table.rank = ["cpu": [row.pid!]]
            table.sampledAt = anchorMS - Int64(hoursAgo * 3_600_000)
            awayRings.add(processes: table)
        }
        let awayView = MCPServerView(server: sparseView.server, state: .live, background: .running(since: now.addingTimeInterval(-86400)), rings: awayRings)
        let fiveHoursBack = Date(timeIntervalSince1970: Double(anchorMS) / 1000 - 5 * 3600)
        let atFive = wire(MCPPayload.processHistory(awayView, at: fiveHoursBack, from: now, to: now, limit: 6, rows: 5,
                                                    sortBy: .cpu, now: now))
        let fiveTable = atFive["tables"]?.arrayValue?.first
        check(atFive["tables"]?.arrayValue?.count == 1 && fiveTable?["source"] == "server"
              && fiveTable?["processes"]?.arrayValue?.first?["name"] == "backup",
              "a moment gives the server's table for its quarter hour, the busiest moment of it")
        let window = wire(MCPPayload.processHistory(awayView, at: nil, from: now.addingTimeInterval(-6 * 3600), to: now, limit: 2, rows: 5,
                                                    sortBy: .cpu, now: now))
        let windowNames = window["tables"]?.arrayValue?.compactMap { $0["processes"]?.arrayValue?.first?["name"]?.stringValue } ?? []
        check(windowNames == ["backup", "rsync"] && window["total"] == 3 && window["truncated"] == true,
              "a window gives its busiest quarter hours, in time order, and says how many there were (\(windowNames))")

        // A server that isn't answering: what is held, said plainly.
        var downView = MCPServerView(server: Demo.machines[0].server, state: .waiting(until: now.addingTimeInterval(30), reason: "The server isn't answering."),
                                     downSince: now.addingTimeInterval(-300), latest: sparse, latestFull: sparse)
        downView.latest?.t = nowMS - 300_000
        let downSnapshot = wire(MCPPayload.snapshot(downView, sections: [.cpu], limit: 5, now: now))
        check(downSnapshot["server"]?["state"] == "down" && downSnapshot["server"]?["reason"] == "The server isn't answering."
              && downSnapshot["server"]?["nextRetryAt"] != nil && downSnapshot["ageSeconds"] == 300
              && (downSnapshot["note"]?.stringValue ?? "").contains("isn't answering")
              && downSnapshot["cpu"] != nil && audit(downSnapshot).isEmpty,
              "a down server's snapshot gives its last readings, their age and why: \(downSnapshot["note"]?.stringValue ?? "-")")
        let attention = MCPServerView(server: Demo.machines[0].server, state: .attention(.hostKeyChanged))
        let attentionItem = MCPPayload.listServers([attention], limit: 5, now: now)["servers"]?.arrayValue?.first
        check(attentionItem?["state"] == "down" && attentionItem?["needsAttention"] == true && attentionItem?["vitals"] == nil,
              "a server stopped on a changed host key needs the user, and has no readings to give")

        // MARK: End to end: bridge → message port → app, over demo connections

        Demo.isActive = true
        Replay.speed = 2
        let demo = Demo.machines.map { (agent: $0.agent, server: $0.server, connection: ServerConnection(server: $0.server)) }
        demo.forEach { $0.connection.start() }
        var deadline = Date().addingTimeInterval(20)
        func settled() -> Bool {
            demo.allSatisfy { machine in
                switch machine.agent {
                case .recording: return machine.connection.state == .live && machine.connection.lastSample != nil
                case .unreachable: if case .waiting = machine.connection.state { return true } else { return false }
                }
            }
        }
        while Date() < deadline && !settled() { RunLoop.main.run(until: Date().addingTimeInterval(0.1)) }
        check(settled(), "the demo servers are up, and the Raspberry Pi is down")
        check(demo.allSatisfy { $0.connection.demand == .vitals }, "with no agent asking, every server is on vitals")

        let portName = "com.rexyrex.RexBoingRemote.mcp.check-\(getpid())"
        let app = MCPAppServer(servers: { demo.map { ($0.server, $0.connection) } }, portName: portName)
        app.linger = 3
        app.enabled = true
        check(app.isListening, "the app's message port is up while the setting is on")
        // The Settings switch, as the bridge reads it; the check leaves the
        // real preferences alone.
        final class Switch: @unchecked Sendable { var on = true }
        let setting = Switch()
        let relay = MCPBridge.Relay(demo: true, mayLaunch: false, portName: portName, isEnabled: { setting.on })

        final class Box: @unchecked Sendable { var value: JSONValue? }
        func relayed(_ tool: String, _ arguments: JSONValue) -> (payload: JSONValue?, isError: Bool, seconds: Double) {
            let box = Box()
            let done = DispatchSemaphore(value: 0)
            let started = Date()
            DispatchQueue.global().async {
                box.value = relay.call(tool: tool, arguments: arguments) { false }
                done.signal()
            }
            let limit = Date().addingTimeInterval(45)
            while done.wait(timeout: .now()) == .timedOut && Date() < limit {
                RunLoop.main.run(until: Date().addingTimeInterval(0.02))
            }
            let text = box.value?["content"]?.arrayValue?.first?["text"]?.stringValue ?? ""
            return ((try? JSONValue.parse(text)), box.value?["isError"] == true, Date().timeIntervalSince(started))
        }

        var answer = relayed("list_servers", [:])
        let servers = answer.payload?["servers"]?.arrayValue ?? []
        let pi = servers.first { $0["name"] == "Raspberry Pi" }
        check(!answer.isError && answer.payload?["total"] == 4 && answer.payload?["live"] == 3,
              "list_servers over the port: 4 servers, 3 live")
        check(pi?["state"] == "down" && pi?["reason"] == "The server isn't answering." && pi?["downSince"] != nil
              && (pi?["nextRetryAt"] != nil || pi?["retrying"] == true) && pi?["vitals"] == nil,
              "the switched-off Pi is down, with why, since when and the next try, and no readings")
        check(demo.allSatisfy { $0.connection.demand == .vitals }, "listing servers asks no server for more than vitals")
        check(audit(answer.payload ?? .null).isEmpty && secrets(answer.payload ?? .null).isEmpty, "and keeps the conventions")

        answer = relayed("get_server_snapshot", ["server": "home"])
        let home = demo[0].connection
        check(!answer.isError && answer.payload?["detail"] == "full" && answer.payload?["disk"]?["volumes"] != nil
              && answer.payload?["thermal"]?["sensors"] != nil,
              String(format: "a snapshot waits for full detail and gets it (%.1f s)", answer.seconds))
        check(home.demand == .full && app.leasedServers.contains(home.id), "while an agent asks, that server is held in full detail")
        check(demo.dropFirst().allSatisfy { $0.connection.demand == .vitals }, "and only that one")
        let liveProblems = audit(answer.payload ?? .null)
        check(liveProblems.isEmpty, "the live snapshot keeps the conventions\(liveProblems.isEmpty ? "" : ": " + liveProblems.prefix(6).joined(separator: "; "))")
        let homeCPU = answer.payload?["cpu"]?["totalPercent"]?.doubleValue
        let heldCPU = home.lastSample?.cpu?.total.map { $0 * 100 }
        check(homeCPU != nil && heldCPU != nil && abs(homeCPU! - heldCPU!) < 15, "its CPU is the connection's (\(homeCPU ?? -1) vs \(heldCPU ?? -1))")

        answer = relayed("get_server_processes", ["server": "gaming", "sortBy": "memory", "limit": 3])
        let memoryRows = answer.payload?["processes"]?.arrayValue ?? []
        let memories = memoryRows.compactMap { $0["memoryBytes"]?.intValue }
        check(!answer.isError && memoryRows.count == 3 && memories == memories.sorted(by: >),
              "processes by memory over the port, biggest first")
        answer = relayed("get_server_history", ["server": "mac mini", "from": "10m"])
        check(!answer.isError && (answer.payload?["bucketEnds"]?.arrayValue?.count ?? 0) > 0 && answer.payload?["record"]?["name"] == "samples",
              "history over the port, from what the app recorded")
        answer = relayed("get_server_process_history", ["server": "home", "from": "15m"])
        check(!answer.isError && answer.payload?["tables"]?.arrayValue?.first?["source"] == "app",
              "the process history has the table the app took while the agent asked")
        answer = relayed("get_server_snapshot", ["server": "raspberry"])
        check(!answer.isError && answer.payload?["server"]?["state"] == "down" && (answer.payload?["note"]?.stringValue ?? "").contains("isn't answering")
              && answer.seconds < 2,
              String(format: "a down server's snapshot comes at once (%.1f s), saying why it is down: ", answer.seconds)
                + (answer.payload?["note"]?.stringValue ?? answer.payload?.serializedString() ?? "-"))
        answer = relayed("get_server_snapshot", ["server": "p"])
        check(answer.isError && answer.payload?["error"]?["code"] == "not_found" && answer.payload?["error"]?["candidates"]?.arrayValue?.count == 2,
              "an ambiguous name over the port is not_found with candidates")
        answer = relayed("get_server_history", ["server": "nas"])
        check(answer.isError && answer.payload?["error"]?["code"] == "not_found", "an unknown one is not_found")

        // Many calls at once through one bridge, as agents make them: quick
        // ones, and ones that wait for a server's full detail.
        final class Burst: @unchecked Sendable {
            let lock = NSLock()
            var errors: [String] = []
            var slowestQuick = 0.0
        }
        func burst(_ calls: [(String, JSONValue)]) -> (errors: [String], slowestQuick: Double, seconds: Double) {
            let results = Burst()
            let group = DispatchGroup()
            let started = Date()
            for (tool, arguments) in calls {
                DispatchQueue.global().async(group: group) {
                    let begun = Date()
                    let value = relay.call(tool: tool, arguments: arguments) { false }
                    let took = Date().timeIntervalSince(begun)
                    results.lock.lock()
                    defer { results.lock.unlock() }
                    if value["isError"] == true {
                        results.errors.append(value["content"]?.arrayValue?.first?["text"]?.stringValue ?? "?")
                    }
                    if tool != "get_server_processes" { results.slowestQuick = max(results.slowestQuick, took) }
                }
            }
            let limit = Date().addingTimeInterval(60)
            while group.wait(timeout: .now()) == .timedOut && Date() < limit {
                RunLoop.main.run(until: Date().addingTimeInterval(0.01))
            }
            results.lock.lock()
            defer { results.lock.unlock() }
            return (results.errors, results.slowestQuick, Date().timeIntervalSince(started))
        }
        let mixed: [(String, JSONValue)] = (0..<10).flatMap { _ -> [(String, JSONValue)] in [
            ("list_servers", [:]), ("get_server_history", ["server": "home", "from": "10m"]),
            ("get_server_processes", ["server": "mac mini", "limit": 3]),
        ] }
        for round in 1...3 {
            let result = burst(mixed)
            check(result.errors.isEmpty,
                  String(format: "round %d: %d calls at once through one bridge all answer (%d failed%@; %.1f s)", round, mixed.count,
                         result.errors.count, result.errors.first.map { ": " + $0 } ?? "", result.seconds))
            check(result.slowestQuick < 3,
                  String(format: "and calls that need nothing new aren't held up by ones waiting for full detail (slowest %.2f s)",
                         result.slowestQuick))
        }

        // The app going away and coming back under the same name, as a quit
        // and a restart do: a call waiting on it then is told it went away,
        // and the next call finds the new one.
        app.linger = 0.5
        app.sweep(now: Date().addingTimeInterval(60))
        // A server whose last process table is old enough that a call for
        // its processes has to wait for a new one.
        let leaseless = demo[1].connection
        func stale() -> Bool {
            leaseless.demand == .vitals && Date().timeIntervalSince(leaseless.lastProcessTableAt ?? .distantPast) > 5.5
        }
        deadline = Date().addingTimeInterval(12)
        while Date() < deadline && !stale() { RunLoop.main.run(until: Date().addingTimeInterval(0.1)) }
        final class Pending: @unchecked Sendable { var value: JSONValue? }
        let pending = Pending()
        let waiting = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            pending.value = relay.call(tool: "get_server_processes", arguments: ["server": "gaming"]) { false }
            waiting.signal()
        }
        RunLoop.main.run(until: Date().addingTimeInterval(0.15))
        app.enabled = false
        deadline = Date().addingTimeInterval(10)
        while waiting.wait(timeout: .now()) == .timedOut && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.02)) }
        let goneText = pending.value?["content"]?.arrayValue?.first?["text"]?.stringValue ?? ""
        check(pending.value?["isError"] == true && goneText.contains("not_running") && goneText.contains("during this call"),
              "a call waiting when the app goes away is told so: \(goneText)")
        app.enabled = true
        answer = relayed("list_servers", [:])
        check(!answer.isError && answer.payload?["total"] == 4, "and the next call reaches the app that took its place")
        let afterRestart = burst(Array(mixed.prefix(9)))
        check(afterRestart.errors.isEmpty, "as do calls at once after it (\(afterRestart.errors.count) failed)")
        app.linger = 3

        // One bridge outliving several quits: each time the app is gone, the
        // calls waiting start it once between them, and every one answers.
        final class Starts: @unchecked Sendable {
            let lock = NSLock()
            var count = 0
            let app: MCPAppServer
            init(_ app: MCPAppServer) { self.app = app }
        }
        let starts = Starts(app)
        let launching = MCPBridge.Relay(
            demo: true, mayLaunch: true, portName: portName, isEnabled: { true }, isAppRunning: { false },
            launchApp: {
                starts.lock.lock(); starts.count += 1; starts.lock.unlock()
                // As `open` does: the app comes up a moment later.
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { MainActor.assumeIsolated { starts.app.enabled = true } }
                return true
            })
        var restartFailures = 0
        for _ in 1...3 {
            app.enabled = false
            let group = DispatchGroup()
            let failed = Burst()
            for (tool, arguments) in mixed.prefix(9) {
                DispatchQueue.global().async(group: group) {
                    let value = launching.call(tool: tool, arguments: arguments) { false }
                    if value["isError"] == true { failed.lock.lock(); failed.errors.append("x"); failed.lock.unlock() }
                }
            }
            let limit = Date().addingTimeInterval(40)
            while group.wait(timeout: .now()) == .timedOut && Date() < limit { RunLoop.main.run(until: Date().addingTimeInterval(0.01)) }
            restartFailures += failed.errors.count
        }
        check(restartFailures == 0 && starts.count == 3,
              "three quits under one bridge: 27 calls answer (\(restartFailures) failed), starting the app \(starts.count) times, once per quit")

        // The lease goes some seconds after the last call.
        deadline = Date().addingTimeInterval(10)
        while Date() < deadline && !(app.leasedServers.isEmpty && demo.allSatisfy { $0.connection.demand == .vitals }) {
            RunLoop.main.run(until: Date().addingTimeInterval(0.1))
        }
        check(app.leasedServers.isEmpty && demo.allSatisfy { $0.connection.demand == .vitals },
              "with no agent asking any more, every server is back on vitals")

        // Off: no port at all, and the bridge says so.
        app.enabled = false
        check(!app.isListening, "turning the setting off takes the port away")
        setting.on = false
        answer = relayed("list_servers", [:])
        check(answer.isError && answer.payload?["error"]?["code"] == "disabled"
              && (answer.payload?["error"]?["message"]?.stringValue ?? "").contains("Settings"),
              "with it off, a call is disabled, saying how to turn it on")
        setting.on = true
        answer = relayed("list_servers", [:])
        check(answer.isError && answer.payload?["error"]?["code"] == "not_running",
              "with no app answering and --no-launch, a call is not_running: \(answer.payload?["error"]?["message"]?.stringValue ?? "-")")
        answer = relayed("list_servers", ["limit": -1])
        check(answer.isError && answer.payload?["error"]?["code"] == "bad_input", "bad input is answered by the bridge alone, app or not")

        demo.forEach { $0.connection.stop() }
        print(failures == 0 ? "All MCP checks passed." : "\(failures) MCP check(s) failed.")
        exit(failures == 0 ? 0 : 1)
    }
}
