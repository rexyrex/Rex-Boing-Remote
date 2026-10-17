import Foundation

/// Demo mode's stand-in for `ssh host stream`: a recorded agent stream,
/// written into the very pipes ssh would have used, at the pace the app asks
/// for. `AgentSession` hands its pipes to a replay instead of starting a
/// process, so the line framing, `ServerConnection`, the fleet list and the
/// dashboards all run exactly as they do for a real server.
///
/// It behaves like the agent: hello first, then a sample per interval,
/// `{"want":…}` and `{"interval":…}` honoured from the next sample on, the
/// process table only while a dashboard wants everything, and an exit as
/// soon as its input closes.
///
/// The recording plays forwards, then backwards, over and over, so the
/// graphs never jump where it would otherwise start again. Its times are
/// moved to now, keeping the distances they were recorded with.
final class Replay: @unchecked Sendable {
    /// More than 1 plays faster than real time: the figure renderer wants a
    /// minute and a half of history without waiting for it.
    nonisolated(unsafe) static var speed: Double = 1

    private let destination: String
    private let agent: Demo.Agent?
    private let queue = DispatchQueue(label: "com.rexyrex.RexBoingRemote.replay")

    // Queue-confined from here on.
    private var output: FileHandle?
    private var errors: FileHandle?
    private var input: FileHandle?
    private var onExit: (@Sendable (Int32) -> Void)?
    private var exited = false
    private var timer: DispatchSourceTimer?
    private var requests = Data()

    private var hello: [String: Any] = [:]
    private var samples: [[String: Any]] = []
    private var notices: [[String: Any]] = []
    private var recordedInterval = 1.0
    /// Seconds from the recording's clock to now.
    private var shift = 0.0
    private var firstUptime: Double?
    private var startedAt = Date()

    private var detail = "vitals"
    private var interval = 1.0
    private var position = 0
    private var seq: UInt64 = 0

    /// `arguments` are the ssh arguments `AgentSession` was given; the
    /// destination is the one before the remote command.
    init(arguments: [String]) {
        destination = arguments.count >= 2 ? arguments[arguments.count - 2] : ""
        agent = Demo.agent(for: destination)
    }

    /// Starts playing. `onExit` is called once, with the status ssh would
    /// have exited with, after the output has been closed.
    func start(stdin: FileHandle, stdout: FileHandle, stderr: FileHandle, onExit: @escaping @Sendable (Int32) -> Void) {
        queue.async { [self] in
            input = stdin
            output = stdout
            errors = stderr
            self.onExit = onExit
            stdin.readabilityHandler = { [weak self] handle in
                let data = handle.availableData
                if data.isEmpty { handle.readabilityHandler = nil }
                guard let self else { return }
                self.queue.async { self.received(data) }
            }
            switch agent {
            case .recording(let name):
                do {
                    try load(name)
                } catch {
                    fail("rex-boing-remote demo: can't read the recording \(name): \(error.localizedDescription)", status: 1)
                    return
                }
                // About as long as an ssh login and the agent's first sample take.
                after(0.4) { [self] in
                    send(hello)
                    after(0.6) { [self] in
                        sample()
                        notices.forEach(send)
                        schedule()
                    }
                }
            case .unreachable(let message):
                after(3) { [self] in fail(message, status: 255) }
            case nil:
                fail("ssh: Could not resolve hostname \(destination): no such server in demo mode", status: 255)
            }
        }
    }

    /// What a signal to ssh would do.
    func terminate() {
        queue.async { [self] in exit(status: 15) }
    }

    // MARK: - Queue-confined

    private func load(_ name: String) throws {
        guard let url = Demo.recordingURL(name) else {
            throw CocoaError(.fileNoSuchFile)
        }
        let text = try String(contentsOf: url, encoding: .utf8)
        for line in text.split(separator: "\n") where !line.isEmpty {
            guard let object = try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] else { continue }
            switch object["type"] as? String {
            case "hello": hello = object
            case "sample": samples.append(object)
            case "notice": notices.append(object)
            default: break
            }
        }
        guard !samples.isEmpty else { throw CocoaError(.fileReadCorruptFile) }

        recordedInterval = (samples[0]["interval"] as? Double).map { max(0.5, $0) } ?? 1
        let firstT = (samples[0]["t"] as? NSNumber)?.doubleValue ?? Date().timeIntervalSince1970 * 1000
        shift = Date().timeIntervalSince1970 - firstT / 1000
        startedAt = Date()
        firstUptime = (samples[0]["system"] as? [String: Any])?["uptime"] as? Double
        interval = (hello["interval"] as? Double) ?? 1
        if var host = hello["host"] as? [String: Any], let boot = (host["bootTime"] as? NSNumber)?.doubleValue {
            host["bootTime"] = Int64(boot + shift * 1000)
            hello["host"] = host
        }
    }

    private func schedule() {
        timer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        let period = interval / Self.speed
        timer.schedule(deadline: .now() + period, repeating: period, leeway: .milliseconds(20))
        timer.setEventHandler { [weak self] in self?.sample() }
        timer.resume()
        self.timer = timer
    }

    private func sample() {
        guard !exited else { return }
        var sample = samples[index(position)]
        position += max(1, Int((interval / recordedInterval).rounded()))
        seq += 1
        let now = Date()
        let t = Int64(now.timeIntervalSince1970 * 1000)
        sample["seq"] = seq
        sample["t"] = t
        sample["interval"] = interval
        sample["detail"] = detail
        sample["resync"] = false

        if detail == "full" {
            if var processes = sample["processes"] as? [String: Any] {
                processes["sampledAt"] = t
                if let rows = processes["rows"] as? [[String: Any]] {
                    processes["rows"] = rows.map { row in
                        var row = row
                        if let start = (row["start"] as? NSNumber)?.doubleValue {
                            row["start"] = UInt64(max(0, start + shift * 1_000_000))
                        }
                        return row
                    }
                }
                sample["processes"] = processes
            }
        } else {
            // What the agents leave out when only vitals are wanted.
            sample["processes"] = nil
            strip(&sample, "thermal", ["sensors", "fans"])
            strip(&sample, "network", ["interfaces"])
            strip(&sample, "disk", ["volumes"])
        }
        if let firstUptime, var system = sample["system"] as? [String: Any], system["uptime"] != nil {
            system["uptime"] = (firstUptime + now.timeIntervalSince(startedAt)).rounded()
            sample["system"] = system
        }
        send(sample)
    }

    /// Forwards, then backwards: 0 1 2 … n-1 n-2 … 1 0 1 …
    private func index(_ position: Int) -> Int {
        let count = samples.count
        guard count > 1 else { return 0 }
        let period = 2 * (count - 1)
        let phase = position % period
        return phase < count ? phase : period - phase
    }

    private func strip(_ sample: inout [String: Any], _ section: String, _ keys: [String]) {
        guard var value = sample[section] as? [String: Any] else { return }
        for key in keys { value[key] = nil }
        sample[section] = value
    }

    private func received(_ data: Data) {
        guard !exited else { return }
        // End of input is how an agent learns its session is over.
        if data.isEmpty {
            exit(status: 0)
            return
        }
        requests.append(data)
        while let newline = requests.firstIndex(of: 0x0A) {
            let line = requests[requests.startIndex..<newline]
            requests.removeSubrange(requests.startIndex...newline)
            guard let request = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any] else { continue }
            if let want = request["want"] as? String, want == "vitals" || want == "full" {
                detail = want
            }
            if let value = request["interval"] as? Double {
                let clamped = min(10, max(0.5, value))
                if clamped != interval {
                    interval = clamped
                    if timer != nil { schedule() }
                }
            }
        }
    }

    private func send(_ object: [String: Any]) {
        guard !exited, let output,
              let data = try? JSONSerialization.data(withJSONObject: object) else { return }
        try? output.write(contentsOf: data + Data([0x0A]))
    }

    private func fail(_ message: String, status: Int32) {
        guard !exited else { return }
        try? errors?.write(contentsOf: Data((message + "\n").utf8))
        exit(status: status)
    }

    private func exit(status: Int32) {
        guard !exited else { return }
        exited = true
        timer?.cancel()
        timer = nil
        input?.readabilityHandler = nil
        try? output?.close()
        try? errors?.close()
        let onExit = onExit
        self.onExit = nil
        onExit?(status)
    }

    private func after(_ seconds: Double, _ work: @escaping @Sendable () -> Void) {
        queue.asyncAfter(deadline: .now() + seconds / Self.speed) { [self] in
            guard !exited else { return }
            work()
        }
    }
}
