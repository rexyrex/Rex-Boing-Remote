import Foundation
import RexBoingKit

// Tools/check.sh connection
//
// The connection state machine against a fake ssh that drops, hangs, refuses
// and stays down on cue: every recoverable failure must come back by itself,
// and the two that must not be retried blindly must stop and say why.
@main
struct ConnectionCheck {
    @MainActor static func main() {
        var failures = 0
        func check(_ condition: Bool, _ message: String) {
            print("\(condition ? "PASS" : "FAIL")  \(message)")
            if !condition { failures += 1 }
        }

        let tools = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
        let fake = ProcessInfo.processInfo.environment["FAKE_SSH"] ?? tools.appendingPathComponent("fake-ssh.sh").path
        SSH.ssh = fake

        /// Runs one scenario for up to `seconds`, ticking the watchdog the way
        /// the fleet does, and returns the states it passed through.
        func run(_ scenario: String, seconds: Double, until done: (ServerConnection, [String]) -> Bool) -> (ServerConnection, [String]) {
            let counter = FileManager.default.temporaryDirectory.appendingPathComponent("fake-ssh-\(scenario)-\(getpid())")
            try? FileManager.default.removeItem(at: counter)
            setenv("FAKE_SSH_SCENARIO", scenario, 1)
            setenv("FAKE_SSH_COUNTER", counter.path, 1)
            let connection = ServerConnection(server: Server(name: scenario, host: "fake"))
            var states: [String] = []
            let observer = connection.$state.sink { state in
                let name: String
                switch state {
                case .idle: name = "idle"
                case .connecting: name = "connecting"
                case .live: name = "live"
                case .waiting: name = "waiting"
                case .attention(let issue): name = "attention:\(issue.title)"
                }
                if states.last != name { states.append(name) }
            }
            connection.start()
            let deadline = Date().addingTimeInterval(seconds)
            var lastWatchdog = Date()
            while Date() < deadline && !done(connection, states) {
                RunLoop.main.run(until: Date().addingTimeInterval(0.1))
                if Date().timeIntervalSince(lastWatchdog) >= 1 {
                    connection.watchdog(now: Date())
                    lastWatchdog = Date()
                }
            }
            observer.cancel()
            return (connection, states)
        }

        // A link that drops twice comes back on its own, with history kept.
        var (connection, states) = run("drop-then-recover", seconds: 20) { c, _ in
            c.state == .live && (c.snapshot?.cpu.total ?? 0) > 0 && c.history.cpu.count >= 6
        }
        check(connection.state == .live, "a dropped stream reconnects by itself (\(states.joined(separator: " → ")))")
        check(states.filter { $0 == "waiting" }.count == 2, "each drop waits once, then retries")
        check(connection.history.cpu.count >= 6, "history survives the drops (\(connection.history.cpu.count) points)")
        connection.stop()

        // A stream that goes silent without closing is ended by the watchdog.
        (connection, states) = run("hang-then-recover", seconds: 30) { c, seen in
            seen.contains("waiting") && c.state == .live
        }
        check(connection.state == .live && states.contains("waiting"),
              "a silent stream is killed and replaced (\(states.joined(separator: " → ")))")
        connection.stop()

        // A server that is down for a while is retried with backoff, then found.
        (connection, states) = run("down-then-up", seconds: 25) { c, _ in c.state == .live }
        check(connection.state == .live, "a server that comes back up is reconnected (\(states.joined(separator: " → ")))")
        connection.stop()

        // Restarting over and over leaves exactly one live stream: events from
        // the sessions it replaced must not touch the state.
        (connection, states) = run("steady", seconds: 3) { c, _ in c.state == .live }
        for _ in 0..<5 {
            connection.restart()
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        }
        let settle = Date().addingTimeInterval(8)
        while Date() < settle { RunLoop.main.run(until: Date().addingTimeInterval(0.1)) }
        // Only this process's children: another check running at the same
        // time has fake streams of its own.
        let running = Run.sync("/usr/bin/pgrep", ["-P", String(getpid()), "-f", "fake-ssh.sh"]).stdout
            .split(separator: "\n").count
        check(connection.state == .live && running == 1,
              "rapid restarts leave one live stream (\(running) running, \(connection.state))")
        connection.stop()
        RunLoop.main.run(until: Date().addingTimeInterval(3))

        // A removed key stops and asks for repair instead of hammering the server.
        (connection, states) = run("refused", seconds: 6) { c, _ in
            if case .attention = c.state { return true } else { return false }
        }
        if case .attention(.authenticationFailed) = connection.state {
            check(true, "a refused key stops and asks for repair")
        } else {
            check(false, "a refused key stops and asks for repair (\(states))")
        }
        connection.stop()

        // A changed host key stops for good: no retry, ever.
        (connection, states) = run("host-key", seconds: 4) { _, _ in false }
        check(connection.state == .attention(.hostKeyChanged), "a changed host key stops the connection")
        let attempts = Int((try? String(contentsOf: FileManager.default.temporaryDirectory
            .appendingPathComponent("fake-ssh-host-key-\(getpid())"), encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? "") ?? 0
        check(attempts == 1, "and is never retried on its own (\(attempts) attempt)")
        connection.retryNow()
        check(connection.state == .attention(.hostKeyChanged), "not even by Retry Now")
        connection.stop()

        // Demo mode: the recordings play through the same session and
        // connection code, the switched-off server waits like a real one, and
        // nothing ever runs ssh.
        Demo.isActive = true
        Demo.recordingsDirectory = URL(fileURLWithPath: "RexBoingRemote/Demo/Recordings")
        Replay.speed = 4
        let demoCounter = FileManager.default.temporaryDirectory.appendingPathComponent("fake-ssh-demo-\(getpid())")
        try? FileManager.default.removeItem(at: demoCounter)
        setenv("FAKE_SSH_SCENARIO", "steady", 1)
        setenv("FAKE_SSH_COUNTER", demoCounter.path, 1)
        let demo = Demo.machines.map { (agent: $0.agent, connection: ServerConnection(server: $0.server)) }
        demo.forEach { $0.connection.start() }
        func demoSettled() -> Bool {
            demo.allSatisfy { machine in
                switch machine.agent {
                case .recording: return machine.connection.state == .live && machine.connection.history.cpu.count >= 10
                case .unreachable: if case .waiting = machine.connection.state { return true } else { return false }
                }
            }
        }
        var deadline = Date().addingTimeInterval(20)
        while Date() < deadline && !demoSettled() { RunLoop.main.run(until: Date().addingTimeInterval(0.1)) }
        for machine in demo {
            let connection = machine.connection
            switch machine.agent {
            case .recording(let name):
                check(connection.state == .live && connection.history.cpu.count >= 10 && connection.hello?.host?.hostname != nil,
                      "demo \(name) plays (\(connection.history.cpu.count) samples, \(connection.state))")
            case .unreachable:
                if case .waiting(_, let reason) = connection.state {
                    check(reason == "The server isn't answering." && connection.hello == nil,
                          "the switched-off demo server waits to retry (\(reason))")
                } else {
                    check(false, "the switched-off demo server waits to retry (\(connection.state))")
                }
            }
        }
        // An open dashboard asks for everything, and the process table comes.
        let dashboard = demo[0].connection
        dashboard.demand = .full
        deadline = Date().addingTimeInterval(8)
        while Date() < deadline && dashboard.processHistory.samples.count < 2 {
            RunLoop.main.run(until: Date().addingTimeInterval(0.1))
        }
        check(dashboard.processHistory.samples.count >= 2,
              "a demo dashboard gets the process table (\(dashboard.processHistory.samples.count) tables)")
        demo.forEach { $0.connection.stop() }
        RunLoop.main.run(until: Date().addingTimeInterval(1))
        check(!FileManager.default.fileExists(atPath: demoCounter.path), "demo mode never runs ssh")
        check(Run.sync(SSH.ssh, ["-V"]).status == 255, "and refuses to, whatever asks")

        // MARK: History

        // Back to real connections (the fake ssh) after the demo checks.
        Demo.isActive = false

        // The Go agent's encoder is pinned by agent/internal/history's
        // golden file. The Swift side must read it, and, fed the same
        // samples, must write the same thing: the macOS agent and the app
        // keep history by the same rules as the Go agent.
        let goldenURL = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("agent/internal/history/testdata/history.json")
        if let golden = try? Data(contentsOf: goldenURL),
           let wire = try? JSONDecoder().decode(WireHistory.self, from: golden) {
            let base = Date(timeIntervalSince1970: 1_792_206_000)
            var loaded = HistoryRings(interval: 2, started: base)
            loaded.load(wire, now: base.addingTimeInterval(181))
            check(loaded.fine.points.count == 90 && loaded.medium.points.count == 5 && loaded.coarse.points.isEmpty,
                  "the Go agent's history decodes (\(loaded.fine.points.count) fine, \(loaded.medium.points.count) half-minute points)")
            check(loaded.fine.points[44][.read] == nil && loaded.fine.points[43][.read] == 5,
                  "a missing reading stays missing, not zero")
            check(loaded.processTables.first?.rows?.first?.name == "rsync", "its process table decodes")

            var swift = HistoryRings(interval: 2, started: base)
            for i in 1...90 {
                var sample = WireSample()
                sample.t = Int64(base.timeIntervalSince1970 * 1000) + Int64(i) * 2000
                sample.interval = 2
                sample.resync = false
                let cpu = Double(i % 20) / 20
                var cpuWire = WireCPU()
                cpuWire.total = cpu
                cpuWire.user = cpu * 0.75
                cpuWire.system = cpu * 0.25
                sample.cpu = cpuWire
                var memory = WireMemory()
                memory.total = 1000
                memory.used = 250
                var swap = WireSwap()
                swap.total = 400
                swap.used = 100
                memory.swap = swap
                sample.memory = memory
                var gpu = WireGPU()
                gpu.utilization = 0.125
                sample.gpus = [gpu]
                var thermal = WireThermal()
                thermal.cpuCelsius = 50 + Double(i % 5)
                thermal.gpuCelsius = 45
                sample.thermal = thermal
                var power = WirePower()
                power.packageWatts = 12.5
                sample.power = power
                var network = WireNetwork()
                network.rx = 1000
                network.tx = 10
                sample.network = network
                if i != 45 {
                    var disk = WireDisk()
                    disk.read = 5
                    disk.write = 7
                    sample.disk = disk
                }
                swift.add(sample)
            }
            var table = WireProcesses()
            table.count = 200
            table.sampledAt = Int64(base.timeIntervalSince1970 * 1000) + 100_000
            table.interval = 15
            var rsync = WireProcessRow()
            rsync.pid = 7; rsync.name = "rsync"; rsync.user = "alex"; rsync.cmd = "rsync -a /srv /backup"
            rsync.cpu = 80.5; rsync.memory = 5_000_000
            var postgres = WireProcessRow()
            postgres.pid = 9; postgres.name = "postgres"; postgres.user = "postgres"; postgres.cpu = 2; postgres.memory = 900_000_000
            table.rows = [rsync, postgres]
            swift.add(processes: table)
            let mine = try? JSONSerialization.jsonObject(with: swift.encoded()) as? NSDictionary
            let theirs = try? JSONSerialization.jsonObject(with: golden) as? NSDictionary
            check(mine != nil && mine == theirs, "the Swift rings write what the Go agent writes for the same samples")
            if mine != theirs, let mine {
                print(String(decoding: try! JSONSerialization.data(withJSONObject: mine, options: [.sortedKeys]), as: UTF8.self))
            }

            // An agent's record replaces the app's over the time it covers,
            // and leaves the app's own points outside it alone.
            var app = HistoryRings(interval: 1, started: base)
            for i in 1...300 {
                var point = HistoryPoint(t: Int64(base.timeIntervalSince1970 * 1000) + Int64(i) * 1000)
                point[.cpu] = 0.9
                app.add(point)
            }
            var agent = HistoryRings(interval: 2, started: base)
            for i in 50...100 {
                var point = HistoryPoint(t: Int64(base.timeIntervalSince1970 * 1000) + Int64(i) * 2000)
                point[.cpu] = 0.1
                agent.add(point)
            }
            app.merge(agent.wire(), now: base.addingTimeInterval(301))
            let low = app.fine.points.filter { $0[.cpu] == 0.1 }.count
            let ordered = zip(app.fine.points, app.fine.points.dropFirst()).allSatisfy { $0.t < $1.t }
            check(low == 51 && app.fine.points.count == 99 + 51 + 100 && ordered,
                  "a background agent's points replace the app's where they overlap (\(low) of \(app.fine.points.count))")
        } else {
            check(false, "agent/internal/history/testdata/history.json is readable")
        }

        // A stream that brings history fills the graphs at once.
        var rings = HistoryRings(interval: 2, started: Date().addingTimeInterval(-3600))
        let nowMS = Int64(Date().timeIntervalSince1970 * 1000)
        for i in stride(from: 1800, through: 1, by: -1) {
            var point = HistoryPoint(t: nowMS - Int64(i) * 2000)
            point[.cpu] = 0.4
            point[.memory] = 0.5
            rings.add(point)
        }
        var away = WireProcesses()
        away.count = 10
        away.sampledAt = nowMS - 20 * 60_000
        away.interval = 15
        var row = WireProcessRow()
        row.pid = 42; row.name = "backup"; row.cpu = 95; row.memory = 1 << 30
        away.rows = [row]
        rings.add(processes: away)
        let historyFile = FileManager.default.temporaryDirectory.appendingPathComponent("fake-history-\(getpid()).json")
        try? rings.encoded().write(to: historyFile)
        setenv("FAKE_SSH_HISTORY", historyFile.path, 1)
        (connection, states) = run("history", seconds: 10) { c, _ in c.snapshot != nil }
        check(connection.background != .unknown && connection.background != .absent, "a history line marks the background agent as running")
        check(connection.history.cpu.count == MetricsHistory.capacity,
              "the graphs start full (\(connection.history.cpu.count) points after the first sample)")
        check(connection.rings.medium.points.count >= 100, "the long record holds the server's (\(connection.rings.medium.points.count) half-minutes)")
        check(connection.awayProcesses.samples.first?.rows.first?.name == "backup", "the busiest processes while away are kept")
        connection.stop()

        (connection, states) = run("steady", seconds: 5) { c, _ in c.snapshot != nil }
        check(connection.background == .absent, "an agent without history is marked as such")
        connection.stop()
        try? FileManager.default.removeItem(at: historyFile)

        print(failures == 0 ? "All connection checks passed." : "\(failures) connection check(s) failed.")
        exit(failures == 0 ? 0 : 1)
    }
}
