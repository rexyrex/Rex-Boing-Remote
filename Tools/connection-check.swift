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
        let running = Run.sync("/usr/bin/pgrep", ["-f", "fake-ssh.sh"]).stdout
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

        print(failures == 0 ? "All connection checks passed." : "\(failures) connection check(s) failed.")
        exit(failures == 0 ? 0 : 1)
    }
}
