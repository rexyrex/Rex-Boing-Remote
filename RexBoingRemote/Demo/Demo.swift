import Foundation
import RexBoingKit

/// Demo mode: `--demo` on the command line swaps the saved servers for a few
/// made-up ones whose agents are recordings (see `Replay`). It is for working
/// on the interface without servers of your own, and for pictures that show
/// nobody's real machines.
///
/// Demo mode never reads or writes the saved server list, never runs ssh,
/// never creates the app's key, and keeps its preferences apart from the
/// real ones.
enum Demo {
    /// Set once at launch. A variable only so the headless tools can turn it
    /// on; nothing in the app changes it.
    nonisolated(unsafe) static var isActive = CommandLine.arguments.contains("--demo")

    /// Where the recordings are. Nil means the app bundle; the tools, which
    /// have no bundle, point it at the repository.
    nonisolated(unsafe) static var recordingsDirectory: URL?

    /// What answers when demo mode connects to one of its servers.
    enum Agent: Sendable {
        /// A recorded `rex-boing-agent stream`, played back.
        case recording(String)
        /// A server that is switched off: ssh times out and says so.
        case unreachable(String)
    }

    struct Machine: Sendable {
        var server: Server
        var agent: Agent
    }

    static let machines: [Machine] = [
        Machine(
            server: Server(
                id: UUID(uuidString: "6D0D2C3A-0001-4C1E-9E7B-DE0000000001")!,
                name: "Home server", host: "home-server.local", user: "alex",
                auth: .appKey, os: "linux", arch: "amd64", agentVersion: "0.1.0",
                pinned: true, character: .rex, readout: .cpu),
            agent: .recording("linux-home-server")),
        Machine(
            server: Server(
                id: UUID(uuidString: "6D0D2C3A-0002-4C1E-9E7B-DE0000000002")!,
                name: "Gaming PC", host: "gaming-pc.local", user: "alex",
                auth: .appKey, os: "windows", arch: "amd64", agentVersion: "0.1.0",
                pinned: true, character: .ninja, readout: .gpu),
            agent: .recording("windows-gaming-pc")),
        Machine(
            server: Server(
                id: UUID(uuidString: "6D0D2C3A-0003-4C1E-9E7B-DE0000000003")!,
                name: "Mac mini", host: "mac-mini.local", user: "alex",
                auth: .appKey, os: "darwin", arch: "arm64", agentVersion: "0.1.0",
                character: .surf),
            agent: .recording("macos-mac-mini")),
        Machine(
            server: Server(
                id: UUID(uuidString: "6D0D2C3A-0004-4C1E-9E7B-DE0000000004")!,
                name: "Raspberry Pi", host: "raspberrypi.local", user: "pi",
                auth: .appKey, os: "linux", arch: "arm", agentVersion: "0.1.0",
                character: .chomp),
            agent: .unreachable("ssh: connect to host raspberrypi.local port 22: Operation timed out")),
    ]

    static var servers: [Server] { machines.map(\.server) }

    /// The agent behind an ssh destination (`user@host` or `host`).
    static func agent(for destination: String) -> Agent? {
        let host = destination.split(separator: "@").last.map(String.init) ?? destination
        return machines.first { $0.server.host == host }?.agent
    }

    static func recordingURL(_ name: String) -> URL? {
        if let recordingsDirectory {
            return recordingsDirectory.appendingPathComponent(name).appendingPathExtension("jsonl")
        }
        return Bundle.main.url(forResource: name, withExtension: "jsonl")
    }

    /// Shown in place of the Mac's own key, so the install command in a
    /// picture is nobody's.
    static let publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f rex-boing-remote:Demo-Mac"

    /// Stand-ins for `~/.ssh/config` and the network, in the Add Server window.
    static let configHosts = ["home-server.local", "nas"]
    static let nearbyHosts = ["Studio-Mac.local"]

    /// Preferences changed in demo mode stay here, away from the real ones.
    /// The figure renderer uses one of its own, so it always starts fresh.
    nonisolated(unsafe) static var defaultsSuite = "com.rexyrex.RexBoingRemote.demo"

    // MARK: - Running beside the real app

    /// A file for each running demo copy, so a real copy and a demo copy each
    /// hand over only to their own kind.
    private static func marker(_ pid: pid_t) -> URL {
        Paths.controlDirectory.appendingPathComponent("demo-\(pid)")
    }

    static func isMarked(_ pid: pid_t) -> Bool {
        FileManager.default.fileExists(atPath: marker(pid).path)
    }

    static func mark() {
        FileManager.default.createFile(atPath: marker(getpid()).path, contents: nil)
    }

    static func unmark() {
        try? FileManager.default.removeItem(at: marker(getpid()))
    }

    static let setupRefusal = "Demo mode replays recordings and never connects to a real server. "
        + "Quit Rex Boing Remote and open it without --demo to add one."
}
