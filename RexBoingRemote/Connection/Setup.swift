import Foundation
import CryptoKit
import RexBoingKit

/// The agents shipped inside the app, one per platform, all built from this
/// app's own version so they always match it.
enum BundledAgent {
    struct File {
        var url: URL
        var remoteName: String
        var os: String
        var arch: String
    }

    static var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
    }

    /// The agent for a server's `uname -sm` (or Windows') answer.
    static func file(os: String, arch: String) -> File? {
        let folder: String
        let name: String
        switch (os, arch) {
        case ("linux", "amd64"), ("linux", "arm64"), ("linux", "arm"):
            folder = "linux-\(arch)"; name = "rex-boing-agent"
        case ("darwin", _):
            folder = "darwin-universal"; name = "rex-boing-agent"
        case ("windows", "amd64"), ("windows", "arm64"):
            folder = "windows-\(arch)"; name = "rex-boing-agent.exe"
        default:
            return nil
        }
        let url = Paths.bundledAgents.appendingPathComponent(folder).appendingPathComponent(name)
        guard FileManager.default.isExecutableFile(atPath: url.path)
            || FileManager.default.fileExists(atPath: url.path) else { return nil }
        return File(url: url, remoteName: name, os: os, arch: arch)
    }

    /// Normalises `uname -m` spellings to Go's.
    static func arch(fromUname machine: String) -> String? {
        switch machine.lowercased() {
        case "x86_64", "amd64": return "amd64"
        case "aarch64", "arm64", "armv8l", "armv8b": return "arm64"
        case let value where value.hasPrefix("armv6") || value.hasPrefix("armv7") || value == "arm" || value == "armhf":
            return "arm"
        default: return nil
        }
    }
}

/// Adding, repairing, updating and removing servers. Every step runs ssh as
/// the user would, with any prompt answered in the app's own dialogs.
@MainActor
final class Setup: ObservableObject {
    enum Step: Int, CaseIterable, Comparable {
        case connecting, checking, copying, authorising, verifying, done

        var label: String {
            switch self {
            case .connecting: return "Connecting"
            case .checking: return "Checking the system"
            case .copying: return "Copying the agent"
            case .authorising: return "Adding Rex Boing Remote's key"
            case .verifying: return "Starting the agent"
            case .done: return "Done"
            }
        }

        static func < (lhs: Step, rhs: Step) -> Bool { lhs.rawValue < rhs.rawValue }
    }

    struct Failure: LocalizedError {
        var message: String
        var detail: String?
        var errorDescription: String? { message }
    }

    @Published private(set) var step: Step?
    @Published private(set) var isRunning = false

    // MARK: - From the user's SSH access

    /// Sets a server up over SSH the user can already open: finds its OS,
    /// copies the matching agent, installs the app's restricted key, and
    /// checks that the key alone now starts the agent.
    func add(destination rawDestination: String, name: String?, port: Int?, existing: Server? = nil) async throws -> Server {
        if Demo.isActive { throw Failure(message: Demo.setupRefusal) }
        isRunning = true
        defer { isRunning = false; if step != .done { step = nil } }
        let destination = rawDestination.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !destination.isEmpty else { throw Failure(message: "Enter a server.") }

        step = .connecting
        let publicKey: String
        do { publicKey = try AppKey.publicKey() } catch { throw Failure(message: error.localizedDescription) }
        let control = Paths.controlDirectory
            .appendingPathComponent(String(UUID().uuidString.prefix(8))).path
        let target = SSH.Target(destination: destination, port: port, hostKeyAlias: nil)
        defer { SSH.closeMaster(target, controlPath: control) }

        // Which system, and which agent build it needs.
        var os = "linux"
        var arch = "amd64"
        let unix = await setupRun(target, control: control, ["uname", "-sm"], timeout: 120)
        if unix.status == 0, let line = unix.stdout.split(separator: "\n").last {
            step = .checking
            let parts = line.split(separator: " ")
            guard parts.count >= 2 else {
                throw Failure(message: "The server answered, but not in a way Rex Boing Remote understands.", detail: unix.stdout)
            }
            switch parts[0].lowercased() {
            case "linux": os = "linux"
            case "darwin": os = "darwin"
            default:
                throw Failure(message: "\(parts[0]) isn't supported yet. Rex Boing Remote's agents run on Linux, macOS and Windows.")
            }
            guard let normalised = BundledAgent.arch(fromUname: String(parts[1])) else {
                throw Failure(message: "This server's processor (\(parts[1])) isn't supported yet.")
            }
            arch = normalised
        } else if let failure = Self.connectionFailure(unix) {
            throw failure
        } else {
            // Not a Unix shell. Ask cmd, which every Windows has, whatever the
            // default shell is.
            let windows = await setupRun(
                target, control: control, ["cmd", "/c", "\"ver & echo %PROCESSOR_ARCHITECTURE%\""], timeout: 60)
            step = .checking
            guard windows.status == 0, windows.stdout.lowercased().contains("windows") else {
                throw Self.connectionFailure(windows) ?? Failure(
                    message: "Couldn't tell what system the server runs.",
                    detail: (unix.stderr + windows.stderr).trimmingCharacters(in: .whitespacesAndNewlines))
            }
            os = "windows"
            arch = windows.stdout.uppercased().contains("ARM64") ? "arm64" : "amd64"
        }

        guard let agent = BundledAgent.file(os: os, arch: arch) else {
            throw Failure(message: "This copy of Rex Boing Remote has no agent for \(os) on \(arch).")
        }

        // Copy it over SFTP, which works the same whatever the login shell is.
        step = .copying
        let directory = os == "windows" ? "AppData/Local/RexBoingRemote" : ".local/share/rex-boing-remote"
        let upload = os == "windows" ? "rex-boing-agent-upload.exe" : "rex-boing-agent.upload"
        var batch = os == "windows"
            ? ["-mkdir AppData/Local/RexBoingRemote"]
            : ["-mkdir .local", "-mkdir .local/share", "-mkdir .local/share/rex-boing-remote"]
        batch.append("put \(SSH.quoted(agent.url.path)) \(directory)/\(upload)")
        if os != "windows" { batch.append("chmod 755 \(directory)/\(upload)") }
        let copy = await Run.async(
            SSH.sftp, SSH.sftpArguments(target, controlPath: control),
            environment: SSH.setupEnvironment(),
            input: Data((batch.joined(separator: "\n") + "\n").utf8), timeout: 300)
        if copy.status != 0 {
            // Some servers have SFTP turned off; on a Unix shell, cat works too.
            guard os != "windows" else {
                throw Failure(message: "Couldn't copy the agent to the server.", detail: copy.stderr)
            }
            let fallback = await setupRun(
                target, control: control,
                ["mkdir -p .local/share/rex-boing-remote && cat > .local/share/rex-boing-remote/\(upload) && chmod 755 .local/share/rex-boing-remote/\(upload)"],
                input: try? Data(contentsOf: agent.url), timeout: 300)
            guard fallback.status == 0 else {
                throw Failure(message: "Couldn't copy the agent to the server.", detail: copy.stderr + fallback.stderr)
            }
        }

        // Let the agent install itself and authorise this Mac's key for it.
        step = .authorising
        let label = AppKey.comment.replacingOccurrences(of: "rex-boing-remote:", with: "")
        let uploaded = os == "windows" ? #".\AppData\Local\RexBoingRemote\"# + upload : "./\(directory)/\(upload)"
        let install = await setupRun(
            target, control: control, [uploaded, "install", "--label", label],
            input: Data((publicKey + "\n").utf8), timeout: 60)
        let result = Self.result(install.stdout)
        if os != "windows" {
            _ = await setupRun(target, control: control, ["rm", "-f", "\(directory)/\(upload)"], timeout: 20)
        } else {
            _ = await setupRun(target, control: control, ["cmd", "/c", "del", #"AppData\Local\RexBoingRemote\"# + upload], timeout: 20)
        }

        var server = existing ?? Server(name: name?.isEmpty == false ? name! : destination, host: destination)
        server.host = destination
        server.port = port
        server.os = os
        server.arch = arch
        server.agentVersion = BundledAgent.version
        if let name, !name.isEmpty { server.name = name }

        step = .verifying
        if result?.ok == true, await verify(target, auth: .appKey) {
            server.auth = .appKey
        } else if await verify(target, auth: .userSSH, agentPath: server.remoteAgentPath) {
            // The restricted key could not be used (an administrator's key
            // file on Windows, a centrally managed authorized_keys), but the
            // user's own SSH setup reaches the server without prompts.
            server.auth = .userSSH
        } else {
            let reason = result?.message ?? install.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            throw Failure(
                message: "The agent is installed, but the server didn't accept Rex Boing Remote's key.",
                detail: reason.isEmpty ? nil : reason)
        }
        step = .done
        return server
    }

    // MARK: - From a pairing code

    /// Adds a server that already ran the install command with this Mac's
    /// key: pins its host keys and checks that one of its addresses answers.
    func add(code: PairingCode, existing: Server? = nil) async throws -> Server {
        if Demo.isActive { throw Failure(message: Demo.setupRefusal) }
        isRunning = true
        defer { isRunning = false; if step != .done { step = nil } }
        step = .connecting
        let alias = existing?.hostKeyAlias ?? "rbr-" + String(UUID().uuidString.prefix(8)).lowercased()
        do { try code.pinHostKeys(alias: alias) } catch {
            throw Failure(message: "Couldn't save the server's host keys.", detail: error.localizedDescription)
        }
        var lastError = ""
        for address in code.addresses {
            let target = SSH.Target(destination: "\(code.user)@\(address)", port: code.port, hostKeyAlias: alias)
            step = .verifying
            let check = await Run.async(
                SSH.ssh, SSH.background(target, auth: .appKey, avoidAgent: true) + ["version"],
                environment: SSH.backgroundEnvironment(), timeout: 20)
            if check.status == 0, check.stdout.contains("\"protocol\"") {
                var server = existing ?? Server(name: code.name, host: address)
                server.name = existing?.name ?? code.name
                server.host = address
                server.user = code.user
                server.port = code.port == 22 ? nil : code.port
                // The one that answered first, then the rest in their order.
                server.addresses = [address] + code.addresses.filter { $0 != address }
                server.hostKeyAlias = alias
                server.auth = .appKey
                server.os = code.os
                server.agentVersion = Self.versionField(check.stdout)
                step = .done
                return server
            }
            lastError = check.stderr
            if check.stderr.lowercased().contains("permission denied") {
                if existing == nil { KnownHosts.forget(alias: alias) }
                throw Failure(
                    message: "\(code.name) doesn't have this Mac's key. Run the install command shown here on the server, then paste the code it prints.",
                    detail: ServerConnection.explain(stderr: check.stderr, status: check.status))
            }
        }
        if existing == nil { KnownHosts.forget(alias: alias) }
        throw Failure(
            message: "Couldn't reach \(code.name) at \(code.addresses.joined(separator: ", ")).",
            detail: ServerConnection.explain(stderr: lastError, status: 255))
    }

    // MARK: - Updating and removing

    /// Replaces the agent on a server with the one bundled in this app,
    /// through the restricted key's own upgrade command.
    func upgrade(_ server: Server) async throws {
        if Demo.isActive { throw Failure(message: Demo.setupRefusal) }
        guard server.auth == .appKey, let os = server.os, let arch = server.arch ?? (os == "darwin" ? "arm64" : nil),
              let agent = BundledAgent.file(os: os, arch: arch),
              let data = try? Data(contentsOf: agent.url) else {
            throw Failure(message: "Use Repair to update this server's agent.")
        }
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        let target = SSH.Target.forServer(server)
        let result = await Run.async(
            SSH.ssh,
            SSH.background(target, auth: .appKey, avoidAgent: true)
                + ["upgrade", "--sha256", digest, "--size", String(data.count)],
            environment: SSH.backgroundEnvironment(), input: data, timeout: 300)
        guard Self.result(result.stdout)?.ok == true else {
            throw Failure(message: "The update didn't finish.", detail: Self.result(result.stdout)?.message ?? result.stderr)
        }
    }

    /// Asks the agent to remove its key and itself. Best effort: a server
    /// that is down keeps its agent, which is inert without the app.
    func uninstall(_ server: Server) async -> Bool {
        // A demo server has nothing to remove: it only ever existed in memory.
        if Demo.isActive { return true }
        let target = SSH.Target.forServer(server)
        let command = server.auth == .appKey ? ["uninstall"] : [server.remoteAgentPath + " uninstall"]
        let result = await Run.async(
            SSH.ssh, SSH.background(target, auth: server.auth, avoidAgent: server.auth == .appKey) + command,
            environment: SSH.backgroundEnvironment(), timeout: 30)
        if let alias = server.hostKeyAlias { KnownHosts.forget(alias: alias) }
        return Self.result(result.stdout)?.ok == true
    }

    /// Turns the agent's background mode on or off on a server, through
    /// the same key the stream uses: `install-service` or
    /// `uninstall-service`. An agent too old to know them is updated first
    /// (when it was set up with the app's key). Returns the agent's own
    /// explanation, which says what to do if the server needs more (on
    /// Linux, lingering for the user's services).
    func setBackgroundHistory(_ server: Server, enabled: Bool) async throws -> (message: String, upgraded: Bool) {
        if Demo.isActive { throw Failure(message: Demo.setupRefusal) }
        isRunning = true
        defer { isRunning = false }
        let command = enabled ? "install-service" : "uninstall-service"
        let target = SSH.Target.forServer(server)
        func run() async -> Run.Result {
            await Run.async(
                SSH.ssh,
                SSH.background(target, auth: server.auth, avoidAgent: server.auth == .appKey)
                    + (server.auth == .appKey ? [command] : [server.remoteAgentPath + " " + command]),
                environment: SSH.backgroundEnvironment(), timeout: 90)
        }
        var result = await run()
        var upgraded = false
        if Self.result(result.stdout) == nil, Self.refusedAsUnknown(result.stderr) {
            // An agent from before background mode: it cannot have a
            // service to remove, and needs this app's agent to install one.
            guard enabled else { return ("History was already off.", false) }
            guard server.auth == .appKey else {
                throw Failure(message: "This server's agent is too old for background history. Use Repair to update it, then try again.")
            }
            try await upgrade(server)
            upgraded = true
            result = await run()
        }
        guard let parsed = Self.result(result.stdout) else {
            throw Failure(message: "The server didn't answer.", detail: ServerConnection.explain(stderr: result.stderr, status: result.status))
        }
        guard parsed.ok else {
            throw Failure(message: parsed.message ?? "The server couldn't \(enabled ? "start" : "stop") the background agent.")
        }
        return (parsed.message ?? (enabled ? "Keeping history." : "History is off."), upgraded)
    }

    /// Whether an agent refused a command because it does not know it:
    /// its forced-command check, or its own usage message.
    static func refusedAsUnknown(_ stderr: String) -> Bool {
        let text = stderr.lowercased()
        return text.contains("only run") || text.contains("can only run") || text.contains("unknown command")
            || text.contains("usage:")
    }

    // MARK: - Helpers

    private func setupRun(
        _ target: SSH.Target, control: String, _ command: [String],
        input: Data? = nil, timeout: TimeInterval
    ) async -> Run.Result {
        await Run.async(
            SSH.ssh, SSH.setupCommand(target, controlPath: control, command: command),
            environment: SSH.setupEnvironment(), input: input, timeout: timeout)
    }

    private func verify(_ target: SSH.Target, auth: Server.Auth, agentPath: String? = nil) async -> Bool {
        let command = auth == .appKey ? ["version"] : [(agentPath ?? "") + " version"]
        for attempt in 0..<2 {
            let result = await Run.async(
                SSH.ssh, SSH.background(target, auth: auth, avoidAgent: auth == .appKey) + command,
                environment: SSH.backgroundEnvironment(), timeout: 25)
            if result.status == 0, result.stdout.contains("\"protocol\"") { return true }
            if attempt == 0 { try? await Task.sleep(nanoseconds: 1_000_000_000) }
        }
        return false
    }

    /// A failure to reach or log in to the server at all, worded for people.
    static func connectionFailure(_ result: Run.Result) -> Failure? {
        let text = result.stderr.lowercased()
        if result.status == -2 { return Failure(message: "The server didn't answer in time.") }
        if text.contains("could not resolve hostname") {
            return Failure(message: "Can't find that server. Check the name, or use its IP address.")
        }
        if text.contains("connection refused") {
            return Failure(message: "The server refused the connection. Is SSH turned on there?",
                           detail: Self.setupHint)
        }
        if text.contains("timed out") || text.contains("no route to host") || text.contains("network is unreachable") {
            return Failure(message: "The server isn't answering. Check that it's on and reachable from this Mac.")
        }
        if text.contains("permission denied") {
            return Failure(message: "The server didn't accept your login.",
                           detail: "Rex Boing Remote uses your SSH setup for this one step. Check that `ssh \(result.stderr.isEmpty ? "server" : "…")` works in Terminal, or use the install command instead.")
        }
        if text.contains("host key verification failed") {
            return Failure(message: "The server's identity wasn't confirmed, so nothing was changed.")
        }
        if text.contains("remote host identification has changed") {
            return Failure(message: "The server's host key has changed since you last connected. Check it in Terminal first.")
        }
        if result.status == 255 {
            return Failure(message: "Couldn't connect.", detail: ServerConnection.explain(stderr: result.stderr, status: 255))
        }
        return nil
    }

    static let setupHint = """
        Linux: install and start openssh-server. \
        macOS: System Settings › General › Sharing › Remote Login. \
        Windows: Settings › System › Optional features › OpenSSH Server, then start the sshd service.
        """

    private struct Result: Decodable {
        var ok: Bool
        var error: String?
        var message: String?
    }

    /// The agent's JSON result: the last line of output that parses as one.
    private static func result(_ output: String) -> Result? {
        for line in output.split(separator: "\n").reversed() {
            if let parsed = try? JSONDecoder().decode(Result.self, from: Data(line.utf8)) { return parsed }
        }
        return nil
    }

    private static func versionField(_ output: String) -> String? {
        struct Version: Decodable { var version: String? }
        for line in output.split(separator: "\n") {
            if let parsed = try? JSONDecoder().decode(Version.self, from: Data(line.utf8)) { return parsed.version }
        }
        return nil
    }

    // MARK: - The command for servers set up from their own end

    static let releaseBase = "https://github.com/rexyrex/Rex-Boing-Remote/releases/latest/download"

    static func installCommand(windows: Bool) -> String {
        let key = (try? AppKey.publicKey()) ?? "ssh-ed25519 …"
        if windows {
            return "& ([scriptblock]::Create((irm \(releaseBase)/install.ps1))) -Key '\(key)'"
        }
        return "curl -fsSL \(releaseBase)/install.sh | sh -s -- --key '\(key)'"
    }
}
