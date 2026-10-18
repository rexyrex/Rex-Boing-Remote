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
        case unsafe(String)

        var errorDescription: String? {
            switch self {
            case .notACode:
                return "That isn't a Rex Boing Remote pairing code. It starts with rbr1: and is printed at the end of the install command."
            case .unreadable:
                return "The pairing code is damaged. Copy it again, all on one line."
            case .missing(let field):
                return "The pairing code has no \(field)."
            case .unsafe(let field):
                return "The pairing code's \(field) isn't one Rex Boing Remote will use. Copy the code again from the server, and only paste codes from servers you set up."
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
        // Everything in a code ends up on ssh's command line or in the app's
        // known_hosts, and a code is only as trustworthy as wherever it was
        // copied from: a user name like "-oProxyCommand=…" would run a
        // command on this Mac, and a host key with a line break in it would
        // add a line of the attacker's choosing to known_hosts. So each
        // field must look like what the agents actually write.
        guard let user = raw.u, !user.isEmpty else { throw Failure.missing("user name") }
        guard Self.isUsableUser(user) else { throw Failure.unsafe("user name") }
        let given = (raw.a ?? []).filter { !$0.isEmpty }
        guard !given.isEmpty else { throw Failure.missing("address") }
        let addresses = given.filter(Self.isUsableAddress)
        guard !addresses.isEmpty else { throw Failure.unsafe("address") }
        let port = raw.p ?? 22
        guard (1...65535).contains(port) else { throw Failure.unsafe("port") }
        let keys = (raw.k ?? []).compactMap(Self.hostKey)
        guard !keys.isEmpty else { throw Failure.missing("host key") }
        return PairingCode(
            name: raw.n ?? addresses[0], user: user, port: port,
            os: raw.o ?? "linux", addresses: addresses, hostKeys: keys)
    }

    // MARK: - What a field may be

    /// A login name ssh can be given safely: OpenSSH's own rule for user
    /// names on its command line (no shell metacharacters, nothing that
    /// reads as an option, not even after a space), with no control
    /// characters or line breaks either. Spaces stay allowed for Windows
    /// accounts named "Alex Smith", and a backslash for DOMAIN\user.
    static func isUsableUser(_ user: String) -> Bool {
        guard !user.isEmpty, user.utf8.count <= 256, !user.hasPrefix("-"), !user.hasPrefix(" "),
              !user.hasSuffix(" "), !user.hasSuffix("\\") else { return false }
        let forbidden = Set("'\"`;&<>|(){}$")
        var previous: Character?
        for character in user {
            if forbidden.contains(character) { return false }
            if character.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) { return false }
            if character.isWhitespace, character != " " { return false }
            if character == "-", previous == " " { return false }
            previous = character
        }
        return true
    }

    /// A host name, an IPv4 address, or an IPv6 address (with or without
    /// brackets, with or without a zone after "%"), spelled only with the
    /// characters those use, and never starting with "-".
    static func isUsableAddress(_ address: String) -> Bool {
        guard !address.isEmpty, address.utf8.count <= 255,
              address.unicodeScalars.allSatisfy(\.isASCII) else { return false }
        if address.contains(":") || address.hasPrefix("[") {
            var inner = Substring(address)
            if inner.hasPrefix("[") {
                guard inner.hasSuffix("]"), inner.count > 2 else { return false }
                inner = inner.dropFirst().dropLast()
            }
            let parts = inner.split(separator: "%", maxSplits: 1, omittingEmptySubsequences: false)
            let hex = Set("0123456789abcdefABCDEF:.")
            guard let ip = parts.first, ip.contains(":"), ip.allSatisfy(hex.contains) else { return false }
            if parts.count == 2 {
                let zone = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
                guard !parts[1].isEmpty, parts[1].allSatisfy(zone.contains) else { return false }
            }
            return true
        }
        let name = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
        return !address.hasPrefix("-") && !address.hasPrefix(".") && address.allSatisfy(name.contains)
    }

    /// The key types an OpenSSH server can present as a host key.
    static let hostKeyTypes: Set<String> = [
        "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa",
        "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
    ]

    /// A host key from a code as the "type blob" a known_hosts line takes,
    /// or nil unless it is one: a known type, then base64 whose decoded
    /// data begins with that same type, as every SSH public key does.
    static func hostKey(_ text: String) -> String? {
        guard !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return nil }
        let parts = text.split(separator: " ")
        guard parts.count >= 2, hostKeyTypes.contains(String(parts[0])) else { return nil }
        let type = String(parts[0])
        let blob = String(parts[1])
        let alphabet = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        guard blob.allSatisfy(alphabet.contains), let data = Data(base64Encoded: blob) else { return nil }
        let bytes = [UInt8](data)
        guard bytes.count > 4 else { return nil }
        let length = Int(bytes[0]) << 24 | Int(bytes[1]) << 16 | Int(bytes[2]) << 8 | Int(bytes[3])
        guard length == type.utf8.count, bytes.count >= 4 + length,
              Array(bytes[4..<(4 + length)]) == Array(type.utf8) else { return nil }
        return type + " " + blob
    }

    /// Pins the host keys in the app's known_hosts under `alias`, replacing
    /// any earlier lines for it.
    ///
    /// The keys are checked again here, whatever made this value, and only
    /// lines of the one shape this app writes (a plain alias and a valid
    /// key) are kept from before: a line a damaged or malicious code slipped
    /// in once, such as "* ssh-ed25519 …" vouching for every server, does not
    /// survive the next pin.
    func pinHostKeys(alias: String, file path: URL = Paths.knownHosts) throws {
        guard Self.isPlainAlias(alias) else { throw Failure.unsafe("server alias") }
        let keys = hostKeys.compactMap(Self.hostKey)
        guard !keys.isEmpty else { throw Failure.missing("host key") }
        let existing = (try? String(contentsOf: path, encoding: .utf8)) ?? ""
        var lines = existing.split(separator: "\n").map(String.init).filter { line in
            let parts = line.split(separator: " ", maxSplits: 1).map(String.init)
            return parts.count == 2 && parts[0] != alias && Self.isPlainAlias(parts[0]) && Self.hostKey(parts[1]) == parts[1]
        }
        for key in keys {
            lines.append("\(alias) \(key)")
        }
        try (lines.joined(separator: "\n") + "\n").write(to: path, atomically: true, encoding: .utf8)
        chmod(path.path, 0o600)
    }

    /// The per-server names the app pins keys under ("rbr-1a2b3c4d"): no
    /// wildcards, lists or negations, which known_hosts would read as
    /// patterns.
    static func isPlainAlias(_ alias: String) -> Bool {
        let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        return !alias.isEmpty && alias.count <= 64 && alias.allSatisfy(allowed.contains)
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
