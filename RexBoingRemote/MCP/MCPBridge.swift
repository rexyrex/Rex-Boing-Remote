import AppKit
import Darwin
import Foundation

/// `Rex Boing Remote mcp`: the stdio MCP server that Claude Code, Codex,
/// Claude Desktop and the like start.
///
/// It is the app's own executable run with `mcp`, and it never starts
/// NSApplication or shows anything. It is a relay, not a second copy of the
/// app: it answers the handshake, discovery, ping and the tool list itself
/// (so a harness starting up never waits on the app, or launches it, just to
/// learn the tools), and passes each tool call to the running app over its
/// local message port (`MCPPort`). It holds nothing about servers.
///
/// The app may quit, restart or be reinstalled while a bridge runs. A call
/// in flight then gets an error result, and the next call finds the app
/// again, starting it in the background if it isn't running.
enum MCPBridge {
    /// Passed when a bridge starts the app: it comes up quietly in the menu
    /// bar, with no window, as at login.
    static let launchArgument = "--mcp-launch"
    /// The preference the app's Settings switch writes, which the bridge
    /// reads to tell "turned off" from "not running".
    static let enabledKey = "mcpEnabled"

    static let commands: Set<String> = ["mcp", "tools", "call"]

    static var isRequested: Bool {
        CommandLine.arguments.count > 1 && commands.contains(CommandLine.arguments[1])
    }

    /// Whether this copy of the app was started by a bridge.
    static var launchedForAgent: Bool { CommandLine.arguments.contains(launchArgument) }

    static var executablePath: String {
        (Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])).resolvingSymlinksInPath().path
    }

    /// The commands that register this executable with each harness.
    static func registrationCommands(executable: String = executablePath, demo: Bool = Demo.isActive) -> [(client: String, command: String)] {
        let quoted = "\"" + executable.reduce(into: "") { text, character in
            if "\"$`\\".contains(character) { text.append("\\") }
            text.append(character)
        } + "\""
        let name = demo ? "rex-boing-remote-demo" : MCPServerInfo.name
        let arguments = demo ? "mcp --demo" : "mcp"
        return [
            ("Claude Code", "claude mcp add --scope user \(name) -- \(quoted) \(arguments)"),
            ("Codex", "codex mcp add \(name) -- \(quoted) \(arguments)"),
        ]
    }

    static var usage: String {
        let exe = "\"\(executablePath)\""
        return """
        Usage: \(exe) mcp [--demo] [--no-launch]
               \(exe) tools
               \(exe) call <tool> ['{"argument": …}'] [--demo] [--no-launch]

        mcp runs Rex Boing Remote's MCP server on stdin and stdout (newline-delimited JSON-RPC;
        diagnostics on stderr). It answers the handshake and the tool list itself and passes tool
        calls to the running app over a local Mach port, starting the app in the background when
        it isn't running. Every tool only reads what the app holds about your servers.

          --no-launch  never start the app; a call returns not_running instead
          --demo       reach only a copy started with --demo (open "Rex Boing Remote.app" --args --demo)

        tools lists the tools. call runs one and prints its result as JSON.

        Register it with:
          \(registrationCommands().map(\.command).joined(separator: "\n  "))
        """
    }

    /// Runs a command and returns the exit status. `arguments` excludes the
    /// executable.
    static func run(_ arguments: [String]) -> Int32 {
        signal(SIGPIPE, SIG_IGN)
        let command = arguments.first ?? "mcp"
        var mayLaunch = true
        var rest: [String] = []
        for argument in arguments.dropFirst() {
            switch argument {
            case "--no-launch": mayLaunch = false
            case "--demo": break  // Demo.isActive reads it from the command line.
            case "-h", "--help", "help":
                print(usage)
                return 0
            default: rest.append(argument)
            }
        }
        let relay = Relay(demo: Demo.isActive, mayLaunch: mayLaunch)
        switch command {
        case "tools":
            for tool in MCPTools.all {
                print(tool.name.padding(toLength: 30, withPad: " ", startingAt: 0) + tool.title)
            }
            return 0
        case "call":
            return callFromShell(rest, relay: relay)
        default:
            if let unknown = rest.first {
                FileHandle.standardError.write(Data("rex-boing-remote mcp: unknown argument \(unknown); see --help\n".utf8))
                return 2
            }
            return serve(relay: relay)
        }
    }

    // MARK: - stdio

    /// Lines longer than this are not messages anyone sends; they are
    /// dropped rather than buffered without end.
    static let maximumLine = 4 << 20

    private static func serve(relay: Relay) -> Int32 {
        let output = LineWriter()
        let session = MCPSession(
            call: { tool, arguments, isCancelled in relay.call(tool: tool, arguments: arguments, isCancelled: isCancelled) },
            output: { output.write($0) })
        var buffer = Data()
        var discarding = false
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = read(STDIN_FILENO, &chunk, chunk.count)
            if count < 0, errno == EINTR { continue }
            if count <= 0 { break }
            buffer.append(contentsOf: chunk[0..<count])
            while let newline = buffer.firstIndex(of: 0x0A) {
                let line = Data(buffer[buffer.startIndex..<newline])
                buffer.removeSubrange(buffer.startIndex...newline)
                if discarding {
                    discarding = false
                    continue
                }
                session.handle(line: line)
            }
            if buffer.count > maximumLine {
                buffer.removeAll()
                if !discarding { session.handle(line: Data("{".utf8)) }  // answered as not valid JSON
                discarding = true
            }
        }
        if !buffer.isEmpty, !discarding { session.handle(line: buffer) }
        // End of input is the client's way to stop. A scripted client may
        // close it right after its last call, so calls already started still
        // answer, within their own time limits.
        session.drain(timeout: Relay.callLimit + 5)
        return 0
    }

    private static func callFromShell(_ arguments: [String], relay: Relay) -> Int32 {
        guard let tool = arguments.first else {
            FileHandle.standardError.write(Data("Usage: call <tool> ['{\"argument\": …}']\n".utf8))
            return 2
        }
        guard MCPTools.tool(named: tool) != nil else {
            FileHandle.standardError.write(Data("No tool named \(tool). Tools: \(MCPTools.all.map(\.name).joined(separator: ", "))\n".utf8))
            return 2
        }
        var parsed: JSONValue = [:]
        if arguments.count > 1 {
            guard let value = try? JSONValue.parse(arguments[1]), value.objectValue != nil else {
                FileHandle.standardError.write(Data("The arguments must be one JSON object.\n".utf8))
                return 2
            }
            parsed = value
        }
        let result = relay.call(tool: tool, arguments: parsed) { false }
        let text = result["content"]?.arrayValue?.first?["text"]?.stringValue ?? ""
        let value = (try? JSONValue.parse(text)) ?? .string(text)
        print(value.serializedString(pretty: true))
        return result["isError"] == true ? 1 : 0
    }

    // MARK: - Reaching the app

    final class Relay: @unchecked Sendable {
        /// The longest a call waits, for the app to start and then for a
        /// server's full detail.
        static let callLimit: TimeInterval = 30

        let demo: Bool
        let mayLaunch: Bool
        let portName: String
        private let isEnabled: @Sendable () -> Bool
        private let isAppRunning: @Sendable () -> Bool
        private let launchApp: @Sendable () -> Bool
        private let lock = NSLock()
        /// When this bridge last started the app, and whether the app has
        /// answered since: until it does, the start is under way, and calls
        /// arriving meanwhile wait for it rather than start another copy.
        private var launchedAt: Date?
        private var answeredSinceLaunch = true

        /// The other arguments are for the checks, which answer under a port
        /// name of their own, leave the preferences alone and start no app.
        init(demo: Bool, mayLaunch: Bool, portName: String? = nil, isEnabled: (@Sendable () -> Bool)? = nil,
             isAppRunning: (@Sendable () -> Bool)? = nil, launchApp: (@Sendable () -> Bool)? = nil) {
            self.demo = demo
            self.mayLaunch = mayLaunch
            self.portName = portName ?? MCPPort.name(demo: demo)
            self.isEnabled = isEnabled ?? { MCPBridge.isEnabled(demo: demo) }
            self.isAppRunning = isAppRunning ?? { MCPBridge.appIsRunning(demo: demo) }
            self.launchApp = launchApp ?? { MCPBridge.launchApp(demo: demo) }
        }

        private var appName: String { demo ? "Rex Boing Remote (demo mode)" : "Rex Boing Remote" }

        /// One tool call, to its result.
        func call(tool: String, arguments: JSONValue, isCancelled: () -> Bool) -> JSONValue {
            // Bad input is answered here: it never reaches, or starts, the app.
            do {
                _ = try MCPTools.parse(tool, arguments)
            } catch let error as MCPToolError {
                return MCPResult.failure(error)
            } catch {
                return MCPResult.failure(MCPToolError(.internal, error.localizedDescription))
            }
            let request = JSONValue.object(["tool": .string(tool), "arguments": arguments]).serialized()
            let deadline = Date().addingTimeInterval(Self.callLimit)
            var answered = false
            var waitingSince: Date?
            var startedApp = false
            while true {
                if isCancelled() { return MCPResult.failure(MCPToolError(.timeout, "The call was cancelled.")) }
                switch MCPPort.send(request, to: portName, timeout: 10, before: deadline) {
                case .reply(let data):
                    answered = true
                    noteAnswer()
                    guard let reply = try? JSONValue.parse(data) else {
                        return MCPResult.failure(MCPToolError(.internal, "\(appName)'s answer couldn't be read. Call again."))
                    }
                    if let result = reply["result"] { return MCPResult.tool(result) }
                    if let error = MCPToolError(json: reply) { return MCPResult.failure(error) }
                    guard let retry = reply["retry"] else {
                        return MCPResult.failure(MCPToolError(.internal, "\(appName) gave an answer this bridge doesn't know. Update both."))
                    }
                    let delay = Double(min(max(retry["afterMs"]?.intValue ?? 500, 50), 5000)) / 1000
                    guard Date().addingTimeInterval(delay) < deadline else {
                        return MCPResult.failure(MCPToolError(
                            .timeout, (retry["message"]?.stringValue.map { $0 + " " } ?? "")
                                + "Gave up after \(Int(Self.callLimit)) seconds; call again."))
                    }
                    Thread.sleep(forTimeInterval: delay)
                case .failed(let status) where status == kCFMessagePortReceiveTimeout || status == kCFMessagePortSendTimeout:
                    return MCPResult.failure(MCPToolError(
                        .timeout, "\(appName) didn't answer within 10 seconds. It may be busy; call again."))
                case .failed:
                    // The port that was just there went away: the app quit.
                    return gone()
                case .busy:
                    return MCPResult.failure(MCPToolError(
                        .timeout, "\(appName) didn't answer this agent's other calls in time, so this one couldn't "
                            + "be asked. It may be busy; call again."))
                case .noPort:
                    if answered { return gone() }
                    if !isEnabled() {
                        return MCPResult.failure(MCPToolError(
                            .disabled, "AI agent access is turned off in \(appName). The user can turn it on in "
                                + "Rex Boing Remote's Settings › General › \"Let AI agents read your servers' readings\"."))
                    }
                    let now = Date()
                    if waitingSince == nil {
                        waitingSince = now
                        if launching() {
                            startedApp = true
                        } else if !isAppRunning() {
                            guard mayLaunch else {
                                return MCPResult.failure(MCPToolError(
                                    .notRunning, "\(appName) isn't running, and this bridge was started with --no-launch. "
                                        + "Ask the user to open it\(demo ? " with --demo" : ""), then call again."))
                            }
                            startedApp = launchOnce()
                        }
                    }
                    let patience: TimeInterval = startedApp ? 20 : 4
                    if now.timeIntervalSince(waitingSince ?? now) > patience || now > deadline {
                        return MCPResult.failure(MCPToolError(
                            .notRunning,
                            startedApp
                                ? "\(appName) was started but didn't answer within 20 seconds. Check that it opens, then call again."
                                : isAppRunning()
                                    ? "\(appName) is running but isn't answering AI agents. If it is a version from before "
                                        + "it had them, update it; otherwise quit and reopen it."
                                    : "\(appName) isn't running and couldn't be started. Ask the user to open it."))
                    }
                    Thread.sleep(forTimeInterval: 0.25)
                }
            }
        }

        private func gone() -> JSONValue {
            MCPResult.failure(MCPToolError(
                .notRunning, "\(appName) stopped answering during this call: it quit, or is restarting. "
                    + "Call again; the next call finds it, or starts it."))
        }

        private func noteAnswer() {
            lock.lock()
            answeredSinceLaunch = true
            lock.unlock()
        }

        /// Whether a start of the app by this bridge is still under way.
        private func launching() -> Bool {
            lock.lock()
            defer { lock.unlock() }
            return isLaunching
        }

        /// Only while holding `lock`.
        private var isLaunching: Bool {
            guard let launchedAt, !answeredSinceLaunch else { return false }
            return Date().timeIntervalSince(launchedAt) < 25
        }

        /// Starts the app once for every call waiting on it at the same time,
        /// and again whenever a copy it started has answered and then gone.
        private func launchOnce() -> Bool {
            lock.lock()
            defer { lock.unlock() }
            if isLaunching { return true }
            guard launchApp() else { return false }
            launchedAt = Date()
            answeredSinceLaunch = false
            return true
        }
    }

    /// The user's choice in Settings, read from the app's own preferences
    /// (demo mode's, for a demo bridge). On unless turned off.
    static func isEnabled(demo: Bool) -> Bool {
        let domain = (demo ? Demo.defaultsSuite : (Bundle.main.bundleIdentifier ?? "com.rexyrex.RexBoingRemote")) as CFString
        CFPreferencesAppSynchronize(domain)
        return CFPreferencesCopyAppValue(enabledKey as CFString, domain) as? Bool ?? true
    }

    /// Whether a copy of the app of the same kind (demo or not) is running.
    /// Bridges never start NSApplication, so they never register as
    /// running applications and are not counted.
    static func appIsRunning(demo: Bool) -> Bool {
        let identifier = Bundle.main.bundleIdentifier ?? "com.rexyrex.RexBoingRemote"
        let me = getpid()
        return NSRunningApplication.runningApplications(withBundleIdentifier: identifier).contains {
            $0.processIdentifier != me && !$0.isTerminated && Demo.isMarked($0.processIdentifier) == demo
        }
    }

    /// Starts the app this executable belongs to, in the background: a new
    /// instance (so `open` never hands the request to a running copy of the
    /// other kind), not brought forward, hidden, with no window.
    static func launchApp(demo: Bool) -> Bool {
        let bundle = Bundle.main.bundleURL
        guard bundle.pathExtension == "app" else { return false }
        FileHandle.standardError.write(Data("rex-boing-remote mcp: starting \(bundle.lastPathComponent) in the background\n".utf8))
        let open = Process()
        open.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        open.arguments = ["-n", "-g", "-j", bundle.path, "--args", launchArgument] + (demo ? ["--demo"] : [])
        open.standardOutput = FileHandle.nullDevice
        open.standardError = FileHandle.nullDevice
        do {
            try open.run()
            open.waitUntilExit()
            return open.terminationStatus == 0
        } catch {
            return false
        }
    }
}

/// Writes whole lines to stdout, one writer at a time.
private final class LineWriter: @unchecked Sendable {
    private let lock = NSLock()

    func write(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        var payload = data
        payload.append(0x0A)
        payload.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < raw.count {
                let written = Darwin.write(STDOUT_FILENO, base + offset, raw.count - offset)
                if written < 0 {
                    if errno == EINTR { continue }
                    return
                }
                offset += written
            }
        }
    }
}
