import Foundation

/// Editing `~/.ssh/authorized_keys` without losing anything in it.
///
/// The file is the user's, not the agent's: every line the agent does not
/// own is kept byte for byte, whatever its encoding and line endings, a
/// symlinked file is edited where it points, and its mode is kept. A file
/// that exists but can't be read is an error, never an empty file to start
/// over from. The same rules as the Go agent's, in
/// agent/internal/manage/manage_unix.go.
enum AuthorizedKeys {
    /// The key type, base64 blob and first comment word of a line, past any
    /// options; nil for comments, blank lines and anything else that holds
    /// no key.
    static func key(inLine line: [UInt8]) -> (type: String, blob: String, comment: [UInt8])? {
        let tokens = self.tokens(line)
        guard let first = tokens.first, first.first != UInt8(ascii: "#") else { return nil }
        // The type is the first token, or the second after the options.
        for index in 0..<min(2, tokens.count - 1) {
            let type = String(decoding: tokens[index], as: UTF8.self)
            guard type.hasPrefix("ssh-") || type.hasPrefix("ecdsa-sha2-") || type.hasPrefix("sk-") else { continue }
            let blob = tokens[index + 1]
            guard blob.allSatisfy({ $0 < 0x80 }), Data(base64Encoded: Data(blob)) != nil else { continue }
            let comment = index + 2 < tokens.count ? tokens[index + 2] : []
            return (type, String(decoding: blob, as: UTF8.self), comment)
        }
        return nil
    }

    /// A line split on spaces and tabs outside double quotes, since options
    /// such as command="a b" contain spaces.
    static func tokens(_ line: [UInt8]) -> [[UInt8]] {
        var tokens: [[UInt8]] = []
        var current: [UInt8] = []
        var quoted = false
        var index = 0
        while index < line.count {
            let byte = line[index]
            if byte == UInt8(ascii: "\\"), quoted, index + 1 < line.count, line[index + 1] == UInt8(ascii: "\"") {
                current += [byte, line[index + 1]]
                index += 2
                continue
            }
            if byte == UInt8(ascii: "\"") {
                quoted.toggle()
                current.append(byte)
            } else if (byte == UInt8(ascii: " ") || byte == UInt8(ascii: "\t")) && !quoted {
                if !current.isEmpty { tokens.append(current) }
                current = []
            } else {
                current.append(byte)
            }
            index += 1
        }
        if !current.isEmpty { tokens.append(current) }
        return tokens
    }

    /// The file's lines, each with its own line ending (if it has one).
    static func lines(_ content: [UInt8]) -> [ArraySlice<UInt8>] {
        var lines: [ArraySlice<UInt8>] = []
        var start = 0
        for (index, byte) in content.enumerated() where byte == 0x0A {
            lines.append(content[start...index])
            start = index + 1
        }
        if start < content.count { lines.append(content[start...]) }
        return lines
    }

    /// A line without its line ending, "\r\n" or "\n".
    static func body(_ line: ArraySlice<UInt8>) -> ArraySlice<UInt8> {
        var end = line.endIndex
        while end > line.startIndex, line[end - 1] == 0x0A || line[end - 1] == 0x0D { end -= 1 }
        return line[line.startIndex..<end]
    }

    /// The line ending the file already uses.
    static func lineEnding(_ content: [UInt8]) -> [UInt8] {
        if let newline = content.firstIndex(of: 0x0A), newline > 0, content[newline - 1] == 0x0D { return [0x0D, 0x0A] }
        return [0x0A]
    }

    /// Replaces the line holding `blob` with `line` (dropping any further
    /// copies of it), or appends `line`. Every other line is kept as it
    /// was, as is the file's last line ending, or its absence.
    static func upsert(_ content: [UInt8], line: [UInt8], blob: String) -> (content: [UInt8], replaced: Bool) {
        var out: [UInt8] = []
        var replaced = false
        for existing in lines(content) {
            let body = self.body(existing)
            if key(inLine: Array(body))?.blob == blob {
                if !replaced {
                    out += line + existing[body.endIndex...]
                    replaced = true
                }
                continue
            }
            out += existing
        }
        if !replaced {
            let ending = lineEnding(content)
            if content.isEmpty || content.last == 0x0A {
                out += line + ending
            } else {
                out += ending + line
            }
        }
        return (out, replaced)
    }

    /// Drops every line whose key comment starts with `prefix`.
    static func removeKeys(_ content: [UInt8], commentPrefix prefix: String) -> (content: [UInt8], removed: Int) {
        var out: [UInt8] = []
        var removed = 0
        let prefixBytes = Array(prefix.utf8)
        for existing in lines(content) {
            if let comment = key(inLine: Array(body(existing)))?.comment, comment.starts(with: prefixBytes) {
                removed += 1
                continue
            }
            out += existing
        }
        // Removing the last line must not leave the new last line without
        // the line ending the file had.
        if content.last == 0x0A, !out.isEmpty, out.last != 0x0A { out += lineEnding(content) }
        return (out, removed)
    }

    // MARK: - The file

    struct Failure: LocalizedError {
        var message: String
        var errorDescription: String? { message }

        init(_ message: String) { self.message = message }

        static func posix(_ what: String) -> Failure {
            Failure("\(what): \(String(cString: strerror(errno)))")
        }
    }

    /// The file to edit: `path` itself, or where it points if it is a
    /// symlink, so replacing it keeps the link.
    static func resolve(_ path: String) -> String {
        guard let real = realpath(path, nil) else { return path }
        defer { free(real) }
        return String(cString: real)
    }

    /// The file's bytes and permissions, or nil if there is no file.
    static func read(_ path: String) throws -> (bytes: [UInt8], mode: mode_t)? {
        var info = stat()
        guard stat(path, &info) == 0 else {
            if errno == ENOENT { return nil }
            throw Failure.posix("Cannot read \(path)")
        }
        let data: Data
        do { data = try Data(contentsOf: URL(fileURLWithPath: path)) } catch {
            throw Failure("Cannot read \(path): \(error.localizedDescription)")
        }
        return ([UInt8](data), info.st_mode & 0o7777)
    }

    /// Writes through a temporary file in the same directory, synced, then
    /// renamed over `path`, so a crash never leaves half a file behind.
    static func write(_ bytes: [UInt8], to path: String, mode: mode_t) throws {
        let directory = (path as NSString).deletingLastPathComponent
        var template = Array((directory + "/." + (path as NSString).lastPathComponent + ".rbr-XXXXXX").utf8CString)
        let fd = mkstemp(&template)
        guard fd >= 0 else { throw Failure.posix("Cannot write in \(directory)") }
        let temp = String(cString: template)
        var written = 0
        while written < bytes.count {
            let count = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress! + written, bytes.count - written) }
            if count < 0 {
                if errno == EINTR { continue }
                let failure = Failure.posix("Cannot write \(temp)")
                close(fd)
                unlink(temp)
                throw failure
            }
            written += count
        }
        guard fchmod(fd, mode) == 0, fsync(fd) == 0 else {
            let failure = Failure.posix("Cannot write \(temp)")
            close(fd)
            unlink(temp)
            throw failure
        }
        close(fd)
        guard rename(temp, path) == 0 else {
            let failure = Failure.posix("Cannot replace \(path)")
            unlink(temp)
            throw failure
        }
        let directoryFD = open(directory, O_RDONLY)
        if directoryFD >= 0 { fsync(directoryFD); close(directoryFD) }
    }
}
