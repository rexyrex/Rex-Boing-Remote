import Foundation

/// The `rbr1:` code `install.sh` and `install.ps1` print on a server after
/// installing the agent with this Mac's key. Pasting it adds the server with
/// no prompts at all: it says where the server is, who to log in as, and
/// which host keys it has, so the first connection is already verified.
struct PairingCode: Equatable, Sendable {
    var name: String
    var user: String
    var port: Int
    var os: String
    var addresses: [String]
    var hostKeys: [String]

    enum Failure: LocalizedError {
        case notACode
        case unreadable
        case missing(String)

        var errorDescription: String? {
            switch self {
            case .notACode:
                return "That isn't a Rex Boing Remote pairing code. It starts with rbr1: and is printed at the end of the install command."
            case .unreadable:
                return "The pairing code is damaged. Copy it again, all on one line."
            case .missing(let field):
                return "The pairing code has no \(field)."
            }
        }
    }

    static func parse(_ text: String) throws -> PairingCode {
        // Tolerate the surrounding text a terminal copy brings along.
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let range = trimmed.range(of: "rbr1:") else { throw Failure.notACode }
        let payload = trimmed[range.upperBound...]
            .prefix { !$0.isWhitespace && $0 != "\"" && $0 != "'" }
        var base64 = payload.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64 += "=" }
        guard let data = Data(base64Encoded: base64) else { throw Failure.unreadable }

        struct Raw: Decodable {
            var v: Int?
            var n: String?
            var u: String?
            var p: Int?
            var o: String?
            var a: [String]?
            var k: [String]?
        }
        guard let raw = try? JSONDecoder().decode(Raw.self, from: data) else { throw Failure.unreadable }
        guard let user = raw.u, !user.isEmpty else { throw Failure.missing("user name") }
        let addresses = (raw.a ?? []).filter { !$0.isEmpty }
        guard !addresses.isEmpty else { throw Failure.missing("address") }
        let keys = (raw.k ?? []).filter { $0.hasPrefix("ssh-") || $0.hasPrefix("ecdsa-") }
        guard !keys.isEmpty else { throw Failure.missing("host key") }
        return PairingCode(
            name: raw.n ?? addresses[0], user: user, port: raw.p ?? 22,
            os: raw.o ?? "linux", addresses: addresses, hostKeys: keys)
    }

    /// Pins the host keys in the app's known_hosts under `alias`, replacing
    /// any earlier lines for it.
    func pinHostKeys(alias: String) throws {
        let path = Paths.knownHosts
        let existing = (try? String(contentsOf: path, encoding: .utf8)) ?? ""
        var lines = existing.split(separator: "\n").map(String.init)
            .filter { !$0.hasPrefix(alias + " ") }
        for key in hostKeys {
            let parts = key.split(separator: " ")
            guard parts.count >= 2 else { continue }
            lines.append("\(alias) \(parts[0]) \(parts[1])")
        }
        try (lines.joined(separator: "\n") + "\n").write(to: path, atomically: true, encoding: .utf8)
        chmod(path.path, 0o600)
    }
}

enum KnownHosts {
    /// Removes the lines pinned for a server's alias.
    static func forget(alias: String) {
        let path = Paths.knownHosts
        guard let existing = try? String(contentsOf: path, encoding: .utf8) else { return }
        let lines = existing.split(separator: "\n").map(String.init)
            .filter { !$0.hasPrefix(alias + " ") }
        try? (lines.joined(separator: "\n") + "\n").write(to: path, atomically: true, encoding: .utf8)
    }
}
