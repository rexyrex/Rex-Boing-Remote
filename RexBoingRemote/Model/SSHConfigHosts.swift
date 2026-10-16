import Foundation

/// The host aliases in the user's `~/.ssh/config`, following `Include`.
///
/// Only names that can be connected to are listed: patterns (`*`, `?`, `!`)
/// describe groups of hosts, not hosts. Everything else about each host —
/// address, user, port, jump hosts, keys — is left to ssh to resolve when it
/// connects, so it is never duplicated or second-guessed here.
enum SSHConfigHosts {
    static func load() -> [String] {
        let home = NSHomeDirectory()
        var seen = Set<String>()
        var result: [String] = []
        var visited = Set<String>()
        read(path: home + "/.ssh/config", base: home + "/.ssh", into: &result, seen: &seen, visited: &visited, depth: 0)
        return result
    }

    private static func read(
        path: String, base: String, into result: inout [String], seen: inout Set<String>,
        visited: inout Set<String>, depth: Int
    ) {
        guard depth < 8, !visited.contains(path),
              let text = try? String(contentsOfFile: path, encoding: .utf8) else { return }
        visited.insert(path)
        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            let (keyword, value) = split(line)
            switch keyword.lowercased() {
            case "host":
                for name in tokens(value) where isConcrete(name) && seen.insert(name).inserted {
                    result.append(name)
                }
            case "include":
                for pattern in tokens(value) {
                    let expanded = expand(pattern, base: base)
                    for file in glob(expanded) {
                        read(path: file, base: base, into: &result, seen: &seen, visited: &visited, depth: depth + 1)
                    }
                }
            default:
                break
            }
        }
    }

    private static func split(_ line: String) -> (String, String) {
        // "Keyword value" or "Keyword=value".
        if let index = line.firstIndex(where: { $0 == " " || $0 == "\t" || $0 == "=" }) {
            let key = String(line[..<index])
            let rest = line[line.index(after: index)...]
                .trimmingCharacters(in: CharacterSet(charactersIn: " \t="))
            return (key, rest)
        }
        return (line, "")
    }

    private static func tokens(_ value: String) -> [String] {
        var out: [String] = []
        var current = ""
        var quoted = false
        for character in value {
            if character == "\"" { quoted.toggle(); continue }
            if !quoted && (character == " " || character == "\t") {
                if !current.isEmpty { out.append(current); current = "" }
            } else {
                current.append(character)
            }
        }
        if !current.isEmpty { out.append(current) }
        return out
    }

    private static func isConcrete(_ name: String) -> Bool {
        !name.contains("*") && !name.contains("?") && !name.hasPrefix("!")
    }

    private static func expand(_ pattern: String, base: String) -> String {
        if pattern.hasPrefix("~/") { return NSHomeDirectory() + pattern.dropFirst(1) }
        if pattern.hasPrefix("/") { return pattern }
        return base + "/" + pattern
    }

    private static func glob(_ pattern: String) -> [String] {
        var result = glob_t()
        defer { globfree(&result) }
        guard Darwin.glob(pattern, 0, nil, &result) == 0 else { return [] }
        return (0..<Int(result.gl_pathc)).compactMap { index in
            result.gl_pathv[index].flatMap { String(cString: $0) }
        }.sorted()
    }
}
