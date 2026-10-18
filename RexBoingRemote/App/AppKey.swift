import Foundation
import SystemConfiguration

/// The app's dedicated SSH key.
///
/// Every server the app watches authorises this key with `restrict` and a
/// forced command, so the key can do exactly one thing: start the agent. That
/// is what lets the app reconnect on its own after sleep, a reboot or a
/// network change without asking 1Password, a hardware key or the user for
/// anything. A stolen copy still runs the agent's commands, `upgrade`
/// included, which on all but a signed macOS agent means any binary:
/// SECURITY.md says what that allows.
enum AppKey {
    enum Failure: LocalizedError {
        case generation(String)
        case unreadable(String)

        var errorDescription: String? {
            switch self {
            case .generation(let detail):
                return "Couldn't create Rex Boing Remote's SSH key. \(detail)"
            case .unreadable(let detail):
                return "Couldn't read Rex Boing Remote's SSH key. \(detail)"
            }
        }
    }

    /// The public key line, creating the key pair on first use.
    static func publicKey() throws -> String {
        // Demo mode shows a made-up key and never creates the real one.
        if Demo.isActive { return Demo.publicKey }
        try ensureKeyPair(privateKey: Paths.privateKey, publicKey: Paths.publicKey)
        let line = try String(contentsOf: Paths.publicKey, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return line
    }

    /// Makes sure both halves of the key exist. The private half is what
    /// every server has authorised, so it is only ever created when there is
    /// none: a missing public half is rebuilt from it, and one that can't be
    /// read is an error, never a reason to start over with a new pair that
    /// no server knows.
    static func ensureKeyPair(privateKey: URL, publicKey: URL) throws {
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: privateKey.path) else {
            try generate(privateKey: privateKey, publicKey: publicKey)
            return
        }
        guard !fileManager.fileExists(atPath: publicKey.path) else { return }
        let derived = Run.sync(SSH.keygen, ["-y", "-P", "", "-f", privateKey.path])
        let fields = derived.stdout.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ")
        guard derived.status == 0, fields.count >= 2 else {
            throw Failure.unreadable(derived.stderr.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        // ssh-keygen prints the key's comment too where the file keeps one;
        // the agent takes the Mac's label from it.
        let line = fields.count >= 3 ? fields.joined(separator: " ") : fields.joined(separator: " ") + " " + comment
        do { try (line + "\n").write(to: publicKey, atomically: true, encoding: .utf8) } catch {
            throw Failure.generation(error.localizedDescription)
        }
    }

    /// The comment the key carries; servers show it next to the key, and the
    /// agent uses it as the label for the Mac it belongs to.
    static var comment: String {
        let name = (SCDynamicStoreCopyComputerName(nil, nil) as String?) ?? "mac"
        let safe = name.unicodeScalars.map { scalar -> Character in
            CharacterSet.alphanumerics.contains(scalar) || scalar == "-" || scalar == "."
                ? Character(scalar) : "-"
        }
        return "rex-boing-remote:" + String(safe).trimmingCharacters(in: CharacterSet(charactersIn: "-"))
    }

    private static func generate(privateKey: URL, publicKey: URL) throws {
        // A public half without its private one is of no use to anyone.
        try? FileManager.default.removeItem(at: publicKey)
        let result = Run.sync(
            SSH.keygen,
            ["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", privateKey.path])
        guard result.status == 0 else {
            throw Failure.generation(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        chmod(privateKey.path, 0o600)
    }
}

/// Runs a short command to completion. For the long-running agent stream see
/// `AgentSession`.
enum Run {
    struct Result {
        var status: Int32
        var stdout: String
        var stderr: String
    }

    static func sync(
        _ executable: String, _ arguments: [String],
        environment: [String: String]? = nil, input: Data? = nil, timeout: TimeInterval = 30
    ) -> Result {
        // Demo mode never reaches a real server, whatever asks it to.
        if Demo.isActive, executable == SSH.ssh || executable == SSH.sftp {
            return Result(status: 255, stdout: "", stderr: Demo.setupRefusal)
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        if let environment { process.environment = environment }
        let out = Pipe(), err = Pipe(), inPipe = Pipe()
        process.standardOutput = out
        process.standardError = err
        process.standardInput = input == nil ? FileHandle.nullDevice : inPipe
        // Told by the termination handler, not by waitUntilExit() on another
        // thread: that sometimes never returns for a child that has long
        // exited (seen on macOS 27 with children that exit within
        // milliseconds, like `ssh -G`), which turned a 50 ms command into
        // a ten-second timeout.
        let finished = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in finished.signal() }

        do {
            try process.run()
        } catch {
            return Result(status: -1, stdout: "", stderr: error.localizedDescription)
        }
        // Read both pipes concurrently: a child that fills one pipe while we
        // block on the other never exits. Only once it runs, though: if it
        // never started, nothing would ever close the pipes, and the readers
        // would wait for an end of file forever.
        final class Box: @unchecked Sendable { var data = Data() }
        let outBox = Box(), errBox = Box()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async {
            outBox.data = out.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        group.enter()
        DispatchQueue.global().async {
            errBox.data = err.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        if let input {
            DispatchQueue.global().async {
                try? inPipe.fileHandleForWriting.write(contentsOf: input)
                try? inPipe.fileHandleForWriting.close()
            }
        }
        let deadline = DispatchTime.now() + timeout
        if finished.wait(timeout: deadline) == .timedOut {
            process.terminate()
            _ = finished.wait(timeout: .now() + 2)
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            _ = group.wait(timeout: .now() + 2)
            return Result(
                status: -2, stdout: String(decoding: outBox.data, as: UTF8.self),
                stderr: "Timed out after \(Int(timeout)) seconds.")
        }
        _ = group.wait(timeout: .now() + 5)
        return Result(
            status: process.terminationStatus,
            stdout: String(decoding: outBox.data, as: UTF8.self),
            stderr: String(decoding: errBox.data, as: UTF8.self))
    }

    /// The same, off the main thread.
    static func async(
        _ executable: String, _ arguments: [String],
        environment: [String: String]? = nil, input: Data? = nil, timeout: TimeInterval = 30
    ) async -> Result {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: sync(
                    executable, arguments, environment: environment, input: input, timeout: timeout))
            }
        }
    }
}
