import Foundation
import RexBoingKit

/// One running `ssh … stream`: the child process, its pipes, and the line
/// framing of the protocol. Knows nothing about retrying; `ServerConnection`
/// decides what to do when a session ends.
///
/// Confined to its own serial queue. Events are delivered on the main actor.
final class AgentSession: @unchecked Sendable {
    enum Event: Sendable {
        case message(WireMessage)
        /// What a background agent kept while the app was away
        /// (PROTOCOL.md, "Background history"). Decoded here, off the main
        /// actor: a two-day history is a few hundred kilobytes.
        case history(WireHistory)
        case ended(status: Int32, stderr: String)
    }

    /// The longest line the protocol allows. A server that sends more is
    /// misbehaving, and the session is dropped rather than buffering forever.
    static let maximumLine = 1 << 20

    private let queue = DispatchQueue(label: "com.rexyrex.RexBoingRemote.session")
    private let process = Process()
    private let stdinPipe = Pipe()
    private let stdoutPipe = Pipe()
    private let stderrPipe = Pipe()
    private var buffer = Data()
    private var stderrTail = Data()
    private var finished = false
    private let onEvent: @MainActor @Sendable (Event) -> Void
    private let decoder = JSONDecoder()
    /// In demo mode, the recording that plays ssh's part; no process runs.
    private let replay: Replay?

    /// The child's process id, once started. Used to stop exactly this
    /// process and nothing else.
    private(set) var pid: pid_t = 0

    init(arguments: [String], onEvent: @escaping @MainActor @Sendable (Event) -> Void) {
        self.onEvent = onEvent
        replay = Demo.isActive ? Replay(arguments: arguments) : nil
        process.executableURL = URL(fileURLWithPath: SSH.ssh)
        process.arguments = arguments
        process.environment = SSH.backgroundEnvironment()
        process.standardInput = stdinPipe
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
    }

    func start() throws {
        // An empty read is end of file. The handler must be removed then, or
        // the file handle keeps calling it with nothing, in a tight loop.
        stdoutPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil }
            guard let self else { return }
            self.queue.async { self.receive(data) }
        }
        stderrPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil }
            guard let self else { return }
            self.queue.async { self.receiveError(data) }
        }
        let exited: @Sendable (Int32) -> Void = { [weak self] status in
            guard let self else { return }
            // A moment for the read handlers to hand over what the child wrote
            // last — often the one line of stderr that explains the exit.
            self.queue.asyncAfter(deadline: .now() + 0.15) { self.finish(status: status) }
        }
        if let replay {
            replay.start(
                stdin: stdinPipe.fileHandleForReading, stdout: stdoutPipe.fileHandleForWriting,
                stderr: stderrPipe.fileHandleForWriting, onExit: exited)
            return
        }
        process.terminationHandler = { process in exited(process.terminationStatus) }
        try process.run()
        pid = process.processIdentifier
    }

    /// Sends one request line. Failures are ignored: a closed pipe means the
    /// session is ending, and the end is reported through `ended`.
    func send(_ object: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: object) else { return }
        queue.async { [stdinPipe] in
            try? stdinPipe.fileHandleForWriting.write(contentsOf: data + Data([0x0A]))
        }
    }

    /// Ends the session: closing stdin is the agent's signal to exit, which
    /// lets ssh close cleanly. If that does not happen promptly the process
    /// is terminated, and killed if it still lingers.
    func stop() {
        queue.async { [self] in
            try? stdinPipe.fileHandleForWriting.close()
            let pid = self.pid
            guard pid > 0 else { return }
            queue.asyncAfter(deadline: .now() + 2) { [self] in
                guard !finished, process.isRunning, process.processIdentifier == pid else { return }
                process.terminate()
                queue.asyncAfter(deadline: .now() + 3) { [self] in
                    guard !finished, process.isRunning, process.processIdentifier == pid else { return }
                    Darwin.kill(pid, SIGKILL)
                }
            }
        }
    }

    /// Stops immediately, for a session that has gone silent.
    func kill() {
        if let replay {
            replay.terminate()
            return
        }
        queue.async { [self] in
            guard !finished, process.isRunning else { return }
            process.terminate()
            let pid = self.pid
            queue.asyncAfter(deadline: .now() + 3) { [self] in
                guard !finished, process.isRunning, process.processIdentifier == pid else { return }
                Darwin.kill(pid, SIGKILL)
            }
        }
    }

    // MARK: - Queue-confined

    private func receive(_ data: Data) {
        guard !finished else { return }
        if data.isEmpty { return }
        buffer.append(data)
        while let newline = buffer.firstIndex(of: 0x0A) {
            let line = buffer[buffer.startIndex..<newline]
            buffer.removeSubrange(buffer.startIndex...newline)
            guard !line.isEmpty else { continue }
            switch WireMessage.decode(Data(line), decoder: decoder) {
            case .other("history"):
                if let history = try? decoder.decode(WireHistory.self, from: Data(line)) {
                    deliver(.history(history))
                }
            case let message?:
                deliver(.message(message))
            case nil:
                break
            }
        }
        if buffer.count > Self.maximumLine {
            buffer.removeAll()
            appendError(Data("The server sent a line longer than the protocol allows.\n".utf8))
            kill()
        }
    }

    private func receiveError(_ data: Data) {
        guard !data.isEmpty else { return }
        appendError(data)
    }

    private func appendError(_ data: Data) {
        stderrTail.append(data)
        if stderrTail.count > 8192 { stderrTail.removeFirst(stderrTail.count - 8192) }
    }

    private func finish(status: Int32) {
        guard !finished else { return }
        // Drain what is still buffered in the pipes before reporting the end,
        // so a final error line from ssh is part of the explanation.
        let rest = stdoutPipe.fileHandleForReading.readDataToEndOfFileNonBlocking()
        receive(rest)
        appendError(stderrPipe.fileHandleForReading.readDataToEndOfFileNonBlocking())
        finished = true
        stdoutPipe.fileHandleForReading.readabilityHandler = nil
        stderrPipe.fileHandleForReading.readabilityHandler = nil
        try? stdinPipe.fileHandleForWriting.close()
        let text = String(decoding: stderrTail, as: UTF8.self)
        deliver(.ended(status: status, stderr: text))
    }

    private func deliver(_ event: Event) {
        let onEvent = onEvent
        DispatchQueue.main.async {
            MainActor.assumeIsolated { onEvent(event) }
        }
    }
}

private extension FileHandle {
    /// Whatever is left in a pipe whose writer has exited.
    func readDataToEndOfFileNonBlocking() -> Data {
        let flags = fcntl(fileDescriptor, F_GETFL)
        _ = fcntl(fileDescriptor, F_SETFL, flags | O_NONBLOCK)
        var result = Data()
        var chunk = [UInt8](repeating: 0, count: 65536)
        while true {
            let count = Darwin.read(fileDescriptor, &chunk, chunk.count)
            if count <= 0 { break }
            result.append(chunk, count: count)
        }
        return result
    }
}
