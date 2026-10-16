import Foundation
import SystemConfiguration

/// The app's dedicated SSH key.
///
/// Every server the app watches authorises this key with `restrict` and a
/// forced command, so the key can do exactly one thing: start the agent. That
/// is what lets the app reconnect on its own after sleep, a reboot or a
/// network change without asking 1Password, a hardware key or the user for
/// anything — and what makes a stolen copy of it nearly worthless.
enum AppKey {
    enum Failure: LocalizedError {
        case generation(String)

        var errorDescription: String? {
            switch self {
            case .generation(let detail):
                return "Couldn't create Rex Boing Remote's SSH key. \(detail)"
            }
        }
    }

    /// The public key line, creating the key pair on first use.
    static func publicKey() throws -> String {
        let fileManager = FileManager.default
        if !fileManager.fileExists(atPath: Paths.privateKey.path)
            || !fileManager.fileExists(atPath: Paths.publicKey.path) {
            try generate()
        }
        let line = try String(contentsOf: Paths.publicKey, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return line
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

    private static func generate() throws {
        try? FileManager.default.removeItem(at: Paths.privateKey)
        try? FileManager.default.removeItem(at: Paths.publicKey)
        let result = Run.sync(
            "/usr/bin/ssh-keygen",
            ["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", Paths.privateKey.path])
        guard result.status == 0 else {
            throw Failure.generation(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        chmod(Paths.privateKey.path, 0o600)
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
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        if let environment { process.environment = environment }
        let out = Pipe(), err = Pipe(), inPipe = Pipe()
        process.standardOutput = out
        process.standardError = err
        process.standardInput = input == nil ? FileHandle.nullDevice : inPipe

        // Read both pipes concurrently: a child that fills one pipe while we
        // block on the other never exits.
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
        do {
            try process.run()
        } catch {
            return Result(status: -1, stdout: "", stderr: error.localizedDescription)
        }
        if let input {
            DispatchQueue.global().async {
                try? inPipe.fileHandleForWriting.write(contentsOf: input)
                try? inPipe.fileHandleForWriting.close()
            }
        }
        let deadline = DispatchTime.now() + timeout
        let finished = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            process.waitUntilExit()
            finished.signal()
        }
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
