import Foundation
import Combine

/// The saved list of servers. Written atomically on every change, so a crash
/// or a forced quit can never leave a half-written file behind.
@MainActor
final class ServerStore: ObservableObject {
    @Published private(set) var servers: [Server] = []
    /// False for demo mode's list, which never touches the saved one.
    private let persistent: Bool

    init() {
        persistent = true
        load()
    }

    /// A list that lives only in memory: nothing is read from disk, and no
    /// change is ever written.
    init(inMemory servers: [Server]) {
        persistent = false
        self.servers = servers
    }

    func server(_ id: Server.ID) -> Server? {
        servers.first { $0.id == id }
    }

    func add(_ server: Server) {
        if let index = servers.firstIndex(where: { $0.id == server.id }) {
            servers[index] = server
        } else {
            servers.append(server)
        }
        save()
    }

    /// Takes in what setup (Repair, or adding a server again) found out:
    /// how to reach the server, how it logs in and what runs there. Every
    /// other field is left as it is now, since setup can take minutes and
    /// the user may rename, pin or restyle the server meanwhile. A server
    /// that isn't in the list is added.
    func applySetup(_ result: Server) {
        guard server(result.id) != nil else { return add(result) }
        update(result.id) { server in
            server.host = result.host
            server.user = result.user
            server.port = result.port
            server.addresses = result.addresses
            server.auth = result.auth
            server.os = result.os
            server.arch = result.arch
            server.agentVersion = result.agentVersion
            server.hostKeyAlias = result.hostKeyAlias
        }
    }

    func update(_ id: Server.ID, _ change: (inout Server) -> Void) {
        guard let index = servers.firstIndex(where: { $0.id == id }) else { return }
        var server = servers[index]
        change(&server)
        guard server != servers[index] else { return }
        servers[index] = server
        save()
    }

    func remove(_ id: Server.ID) {
        servers.removeAll { $0.id == id }
        save()
    }

    func move(from source: IndexSet, to destination: Int) {
        var copy = servers
        let moving = source.map { copy[$0] }
        for index in source.sorted(by: >) { copy.remove(at: index) }
        let target = min(destination - source.filter { $0 < destination }.count, copy.count)
        copy.insert(contentsOf: moving, at: target)
        servers = copy
        save()
    }

    private struct File: Codable {
        var version = 1
        var servers: [Server]
    }

    /// The saved list, keeping every server that can be read even when some
    /// can't; `dropped` says how many couldn't.
    static func decode(_ data: Data) throws -> (servers: [Server], dropped: Int) {
        struct Lenient: Decodable {
            var servers: [Server] = []
            var dropped = 0

            enum CodingKeys: String, CodingKey { case servers }
            struct Skip: Decodable { init(from decoder: Decoder) {} }

            init(from decoder: Decoder) throws {
                var list = try decoder.container(keyedBy: CodingKeys.self).nestedUnkeyedContainer(forKey: .servers)
                while !list.isAtEnd {
                    if let server = try? list.decode(Server.self) {
                        servers.append(server)
                    } else {
                        _ = try list.decode(Skip.self)
                        dropped += 1
                    }
                }
            }
        }
        let file = try JSONDecoder().decode(Lenient.self, from: data)
        return (file.servers, file.dropped)
    }

    private func load() {
        guard let data = try? Data(contentsOf: Paths.hosts) else { return }
        do {
            let file = try Self.decode(data)
            servers = file.servers
            if file.dropped > 0 {
                // The next save writes the list without the servers that
                // couldn't be read: keep a copy of it as it was first.
                let backup = Paths.hosts.deletingPathExtension()
                    .appendingPathExtension("partly-unreadable-\(Int(Date().timeIntervalSince1970)).json")
                try? FileManager.default.copyItem(at: Paths.hosts, to: backup)
            }
        } catch {
            // Keep the unreadable file for the user instead of overwriting it
            // with an empty list on the next save.
            let backup = Paths.hosts.deletingPathExtension()
                .appendingPathExtension("unreadable-\(Int(Date().timeIntervalSince1970)).json")
            try? FileManager.default.moveItem(at: Paths.hosts, to: backup)
        }
    }

    private func save() {
        guard persistent else { return }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(File(servers: servers)) else { return }
        try? data.write(to: Paths.hosts, options: [.atomic])
        chmod(Paths.hosts.path, 0o600)
    }
}
