import Foundation

/// Builds command lines for the system's own `ssh` and `sftp`.
///
/// The system client is used deliberately, not a Swift SSH library: it honours
/// the user's `~/.ssh/config` — aliases, `ProxyJump`, `ProxyCommand`,
/// `IdentityAgent` (1Password, Secretive), `Include`, `Match` — so any server
/// reachable from Terminal is reachable from here, the same way.
enum SSH {
    /// Variables only so `Tools/connection-check.swift` can point them at a
    /// fake ssh that misbehaves on cue. Nothing in the app changes them.
    nonisolated(unsafe) static var ssh = "/usr/bin/ssh"
    nonisolated(unsafe) static var sftp = "/usr/bin/sftp"
    static let keygen = "/usr/bin/ssh-keygen"

    /// Where to connect and how to verify the server, without the command.
    struct Target: Sendable {
        var destination: String
        var port: Int?
        var hostKeyAlias: String?

        /// The target for one of a server's candidate addresses.
        static func forServer(_ server: Server, address: String? = nil) -> Target {
            let host = address ?? server.addresses.first ?? server.host
            let destination = server.user.map { "\($0)@\(host)" } ?? host
            return Target(destination: destination, port: server.port, hostKeyAlias: server.hostKeyAlias)
        }
    }

    /// Options shared by every connection.
    private static func common(_ target: Target) -> [String] {
        var args = [
            "-o", "ConnectTimeout=12",
            "-o", "LogLevel=ERROR",
        ]
        if let port = target.port { args += ["-p", String(port)] }
        if let alias = target.hostKeyAlias {
            // Added by pairing code: the host keys came in the code and are
            // pinned in the app's own file under the server's own alias, so
            // whichever of its addresses answers has to present them.
            args += ["-o", "HostKeyAlias=\(alias)",
                     "-o", "UserKnownHostsFile=\(quoted(Paths.knownHosts.path))"]
        }
        // Otherwise the user's own known_hosts settings apply untouched, so a
        // server Terminal already trusts needs no second confirmation.
        return args
    }

    /// The long-running agent stream, and the short commands that share its
    /// key: never interactive, never sharing a control socket, and quick to
    /// notice a dead link.
    ///
    /// - `BatchMode` refuses every prompt: a background reconnect must fail
    ///   and retry, never sit waiting for a password nobody is there to type.
    /// - `ControlMaster=no`, `ControlPath=none`: a master connection that
    ///   outlived a network change stalls every client attached to it, so the
    ///   stream never rides on one, whatever the user's config says.
    /// - `ServerAliveInterval` 5 × 3: a link that died while the Mac slept or
    ///   moved networks is noticed within 15 seconds, not two hours.
    static func background(_ target: Target, auth: Server.Auth, avoidAgent: Bool) -> [String] {
        var args = ["-T", "-o", "BatchMode=yes",
                    "-o", "StrictHostKeyChecking=yes",
                    "-o", "ControlMaster=no", "-o", "ControlPath=none",
                    "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3",
                    "-o", "TCPKeepAlive=yes",
                    "-o", "Compression=yes",
                    "-o", "ConnectionAttempts=1",
                    "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
                    "-o", "ClearAllForwardings=yes",
                    "-o", "RequestTTY=no"]
        args += common(target)
        if auth == .appKey {
            args += ["-i", Paths.privateKey.path, "-o", "IdentitiesOnly=yes"]
            // Keep 1Password, Secretive and friends out of it: the app's key is
            // a plain file and needs no agent, and asking one would put an
            // approval prompt in front of every reconnect. Not when a jump
            // host is involved, which may need the agent to get through.
            if avoidAgent { args += ["-o", "IdentityAgent=none"] }
        }
        args.append(target.destination)
        return args
    }

    /// The interactive setup session: prompts allowed (answered by the app's
    /// own askpass dialogs), host keys confirmed rather than refused, and one
    /// shared connection so a password or a hardware-key touch is asked for
    /// once for the whole setup rather than once per step.
    static func setup(_ target: Target, controlPath: String) -> [String] {
        var args = ["-o", "BatchMode=no",
                    "-o", "StrictHostKeyChecking=ask",
                    "-o", "ControlMaster=auto",
                    "-o", "ControlPath=\(quoted(controlPath))",
                    "-o", "ControlPersist=120",
                    "-o", "NumberOfPasswordPrompts=2",
                    "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
                    "-o", "ClearAllForwardings=yes"]
        args += common(target)
        return args
    }

    static func setupCommand(_ target: Target, controlPath: String, command: [String]) -> [String] {
        ["-T"] + setup(target, controlPath: controlPath) + [target.destination] + command
    }

    /// `sftp` over the setup session's control socket.
    static func sftpArguments(_ target: Target, controlPath: String) -> [String] {
        var args = ["-q", "-b", "-"] + setup(target, controlPath: controlPath)
        if let index = args.firstIndex(of: "-p"), index + 1 < args.count {
            // sftp spells the port option -P.
            args[index] = "-P"
        }
        args.append(target.destination)
        return args
    }

    /// Closes the setup session's shared connection.
    static func closeMaster(_ target: Target, controlPath: String) {
        _ = Run.sync(ssh, ["-o", "ControlPath=\(quoted(controlPath))", "-O", "exit", target.destination], timeout: 5)
    }

    /// The environment for setup: prompts go to the app's askpass dialogs.
    static func setupEnvironment() -> [String: String] {
        var environment = ProcessInfo.processInfo.environment
        environment["SSH_ASKPASS"] = Bundle.main.executablePath
        environment["SSH_ASKPASS_REQUIRE"] = "force"
        environment[Askpass.environmentKey] = "1"
        return environment
    }

    /// The environment for background connections: no askpass, ever.
    static func backgroundEnvironment() -> [String: String] {
        var environment = ProcessInfo.processInfo.environment
        environment.removeValue(forKey: "SSH_ASKPASS")
        environment["SSH_ASKPASS_REQUIRE"] = "never"
        environment.removeValue(forKey: Askpass.environmentKey)
        return environment
    }

    /// Resolves what `~/.ssh/config` says about a destination, without
    /// connecting. Used to find jump hosts and the effective user and port.
    static func resolve(_ destination: String) async -> [String: String] {
        let result = await Run.async(ssh, ["-G", destination], timeout: 10)
        var config: [String: String] = [:]
        for line in result.stdout.split(separator: "\n") {
            let parts = line.split(separator: " ", maxSplits: 1)
            guard parts.count == 2 else { continue }
            let key = String(parts[0])
            if config[key] == nil { config[key] = String(parts[1]) }
        }
        return config
    }

    /// Whether the user's config routes this destination through another SSH
    /// host, which may need the user's agent to authenticate.
    static func usesJumpHost(_ config: [String: String]) -> Bool {
        if let jump = config["proxyjump"], jump != "none" { return true }
        if let command = config["proxycommand"], command != "none",
           command.contains("ssh ") || command.hasPrefix("ssh") {
            return true
        }
        return false
    }

    /// Quotes a value for an `-o` option, which ssh parses like a config line.
    static func quoted(_ value: String) -> String {
        "\"" + value.replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}
