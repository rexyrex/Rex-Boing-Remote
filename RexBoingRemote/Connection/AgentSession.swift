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
        /// `stderr` is the tail of everything ssh wrote there. `sinceOutput`
        /// is what it wrote after the first line of output, nil if there
        /// was none: once the agent is talking, only that can say why the
        /// session ended, and what the login printed before it (a shell
        /// startup file's complaints) is noise.
        case ended(status: Int32, stderr: String, sinceOutput: String?)
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
    private var stderrSinceOutput: Data?
    private var outputClosed = false
    private var errorsClosed = false
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
            // The read handlers still have to hand over what the child wrote
            // last — often the one line of stderr that explains the exit.
            self.queue.async { self.finish(status: status, giveUpAt: .now() + 1) }
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
        if data.isEmpty { outputClosed = true }
        guard !finished, !data.isEmpty else { return }
        buffer.append(data)
        while let newline = buffer.firstIndex(of: 0x0A) {
            let line = buffer[buffer.startIndex..<newline]
            buffer.removeSubrange(buffer.startIndex...newline)
            guard !line.isEmpty else { continue }
            if stderrSinceOutput == nil { stderrSinceOutput = Data() }
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
        if data.isEmpty { errorsClosed = true }
        guard !finished, !data.isEmpty else { return }
        appendError(data)
    }

    private func appendError(_ data: Data) {
        stderrTail.append(data)
        if stderrTail.count > 8192 { stderrTail.removeFirst(stderrTail.count - 8192) }
        if var late = stderrSinceOutput {
            late.append(data)
            if late.count > 8192 { late.removeFirst(late.count - 8192) }
            stderrSinceOutput = late
        }
    }

    /// Reports the end once both pipes have been read to their end of file,
    /// so the last thing the child wrote is part of it, or after a second
    /// regardless, in case something it left behind holds a pipe open.
    ///
    /// The read handlers stay the only readers until then. Reading the
    /// pipes here as well, or making them non-blocking, while a handler may
    /// be in the middle of `availableData` can make that read fail, which
    /// raises an exception nothing catches.
    private func finish(status: Int32, giveUpAt: DispatchTime) {
        guard !finished else { return }
        if !(outputClosed && errorsClosed), DispatchTime.now() < giveUpAt {
            queue.asyncAfter(deadline: .now() + 0.05) { [self] in finish(status: status, giveUpAt: giveUpAt) }
            return
        }
        finished = true
        stdoutPipe.fileHandleForReading.readabilityHandler = nil
        stderrPipe.fileHandleForReading.readabilityHandler = nil
        try? stdinPipe.fileHandleForWriting.close()
        let text = String(decoding: stderrTail, as: UTF8.self)
        let sinceOutput = stderrSinceOutput.map { String(decoding: $0, as: UTF8.self) }
        deliver(.ended(status: status, stderr: text, sinceOutput: sinceOutput))
    }

    private func deliver(_ event: Event) {
        let onEvent = onEvent
        DispatchQueue.main.async {
            MainActor.assumeIsolated { onEvent(event) }
        }
    }
}
