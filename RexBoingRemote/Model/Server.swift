import Foundation
import RexBoingKit

/// One machine the app watches, as saved to disk.
struct Server: Codable, Identifiable, Hashable, Sendable {
    var id = UUID()
    /// What the user calls it. Defaults to the SSH alias or the hostname.
    var name: String

    /// How to reach it. `host` is an alias from `~/.ssh/config` or a plain
    /// hostname or address; with `addresses`, the app tries each in turn.
    var host: String
    var user: String?
    var port: Int?
    /// Addresses from a pairing code, best first. Empty for SSH-config hosts,
    /// whose config already says how to get there.
    var addresses: [String] = []
    /// Set for servers added by pairing code: their host keys are pinned in
    /// the app's own known_hosts under this name, so whichever address
    /// answers, the server has to prove it is the same machine.
    var hostKeyAlias: String?

    var auth: Auth = .appKey
    var os: String?
    var arch: String?
    var agentVersion: String?

    /// Whether the user asked for the agent to keep history on the server
    /// while this Mac is away (a background service there). Optional so
    /// lists saved before it existed still load.
    var keepHistory: Bool?

    var pinned = false
    var character: Visualizer = .rex
    var readout: Readout = .cpu
    var added = Date()

    enum Auth: String, Codable, Sendable {
        /// The app's own key, restricted on the server to running the agent.
        case appKey
        /// The user's own SSH setup, for servers where the app's key could not
        /// be installed. Works only without prompts (an agent or a key file).
        case userSSH
    }

    /// What a pinned server's menu bar item shows beside its rex.
    enum Readout: String, Codable, CaseIterable, Identifiable, Sendable {
        case none, cpu, memory, temperature, gpu, power

        var id: String { rawValue }

        var label: String {
            switch self {
            case .none: return "Nothing"
            case .cpu: return "CPU"
            case .memory: return "Memory"
            case .temperature: return "Temperature"
            case .gpu: return "GPU"
            case .power: return "Power"
            }
        }
    }

    /// The `user@host` form for display.
    var destinationLabel: String {
        var text = user.map { "\($0)@" } ?? ""
        text += addresses.first ?? host
        if let port, port != 22 { text += ":\(port)" }
        return text
    }

    /// A short caption for the menu bar: the first word of the name, capped.
    var caption: String {
        let first = name.split(whereSeparator: { " .-_".contains($0) }).first.map(String.init) ?? name
        return String(first.prefix(6)).uppercased()
    }

    var isWindows: Bool { os == "windows" }

    /// Where the agent lives on the server, relative to the login directory —
    /// which is where an SSH command starts, whatever the shell.
    var remoteAgentPath: String {
        isWindows
            ? #".\AppData\Local\RexBoingRemote\rex-boing-agent.exe"#
            : "./.local/share/rex-boing-remote/rex-boing-agent"
    }
}

extension Server {
    /// Reads a saved server leniently, so a list written by another version
    /// still loads: a key from before it existed takes its default, and a
    /// character, readout or way in this version doesn't know becomes the
    /// default one, rather than failing the whole list. Writing is the
    /// synthesized `encode(to:)`, so the file looks exactly as before.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        func optional<T: Decodable>(_ type: T.Type, _ key: CodingKeys) -> T? {
            (try? container.decodeIfPresent(type, forKey: key)) ?? nil
        }
        self.init(name: try container.decode(String.self, forKey: .name),
                  host: try container.decode(String.self, forKey: .host))
        id = optional(UUID.self, .id) ?? id
        user = optional(String.self, .user)
        port = optional(Int.self, .port)
        addresses = optional([String].self, .addresses) ?? addresses
        hostKeyAlias = optional(String.self, .hostKeyAlias)
        auth = optional(String.self, .auth).flatMap(Auth.init(rawValue:)) ?? auth
        os = optional(String.self, .os)
        arch = optional(String.self, .arch)
        agentVersion = optional(String.self, .agentVersion)
        keepHistory = optional(Bool.self, .keepHistory)
        pinned = optional(Bool.self, .pinned) ?? pinned
        character = optional(String.self, .character).flatMap(Visualizer.init(rawValue:)) ?? character
        readout = optional(String.self, .readout).flatMap(Readout.init(rawValue:)) ?? readout
        added = optional(Date.self, .added) ?? added
    }
}
