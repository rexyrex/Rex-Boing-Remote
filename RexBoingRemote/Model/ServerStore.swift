import Foundation
import Combine

/// The saved list of servers. Written atomically on every change, so a crash
/// or a forced quit can never leave a half-written file behind.
@MainActor
final class ServerStore: ObservableObject {
    @Published private(set) var servers: [Server] = []

    init() {
        load()
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

    private func load() {
        guard let data = try? Data(contentsOf: Paths.hosts) else { return }
        do {
            servers = try JSONDecoder().decode(File.self, from: data).servers
        } catch {
            // Keep the unreadable file for the user instead of overwriting it
            // with an empty list on the next save.
            let backup = Paths.hosts.deletingPathExtension()
                .appendingPathExtension("unreadable-\(Int(Date().timeIntervalSince1970)).json")
            try? FileManager.default.moveItem(at: Paths.hosts, to: backup)
        }
    }

    private func save() {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(File(servers: servers)) else { return }
        try? data.write(to: Paths.hosts, options: [.atomic])
        chmod(Paths.hosts.path, 0o600)
    }
}
