import Foundation
import RexBoingKit

// Background mode (PROTOCOL.md, "Background history"): `serve` samples on
// its own, keeps HistoryRings, saves them to the install directory, and
// answers on a Unix socket in a directory only this user can enter. `stream`
// asks it for the history message to send after its hello.

enum Background {
    static let defaultInterval = 2.0
    static let processEvery: TimeInterval = 15
    static let saveEvery: TimeInterval = 10 * 60
    static let maxLine = 1 << 20
    static let maxRequest = 4 << 10
    static let maxClients = 8

    static var historyFile: String { Manage.installDir + "/history.json" }

    /// <install dir>/run/serve.sock, or, when a long home directory makes
    /// that too long for a socket address, a directory in this user's own
    /// temporary directory.
    static var socketPath: String {
        let path = Manage.installDir + "/run/serve.sock"
        if path.utf8.count <= 100 { return path }
        return (NSTemporaryDirectory() as NSString).appendingPathComponent("rex-boing-remote-\(getuid())/serve.sock")
    }

    static var runDirectory: String { (socketPath as NSString).deletingLastPathComponent }

    /// Makes sure `path` is a real directory owned by this user that no one
    /// else can enter, creating it if asked.
    static func privateDirectory(_ path: String, create: Bool) -> Bool {
        if create {
            try? FileManager.default.createDirectory(
                atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            mkdir(path, 0o700)
        }
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_uid == getuid() else { return false }
        if info.st_mode & 0o077 != 0 {
            guard create, chmod(path, 0o700) == 0 else { return false }
        }
        return true
    }

    // MARK: - Client

    /// Sends one request to this user's running serve and returns its
    /// one-line answer, or nil when none answers within `timeout`.
    static func ask(_ want: String, timeout: TimeInterval) -> Data? {
        guard privateDirectory(runDirectory, create: false) else { return nil }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        setTimeouts(fd, timeout)
        guard connect(fd, path: socketPath) else { return nil }
        let request = Data(#"{"want":"\#(want)"}"#.utf8 + [0x0A])
        guard writeAll(fd, request) else { return nil }
        guard var line = readLine(fd, limit: maxLine) else { return nil }
        if line.last == 0x0A { line.removeLast() }
        return line
    }

    /// The running serve's history message, checked to be one JSON object
    /// of type history, or nil.
    static func history(timeout: TimeInterval = 2) -> Data? {
        guard let data = ask("history", timeout: timeout), !data.contains(0x0A) else { return nil }
        struct Head: Decodable { var type: String? }
        guard (try? JSONDecoder().decode(Head.self, from: data))?.type == "history" else { return nil }
        return data
    }

    struct Status: Codable {
        var type = "status"
        var pid: Int32
        var version: String
        var started: Int64
        var interval: Double
        var oldest: Int64?
        var endpoint: String
    }

    static func status(timeout: TimeInterval = 2) -> Status? {
        guard let data = ask("status", timeout: timeout) else { return nil }
        return try? JSONDecoder().decode(Status.self, from: data)
    }

    /// Asks the running serve to save and exit; true once it has stopped.
    @discardableResult
    static func stop(wait: TimeInterval = 5) -> Bool {
        guard ask("stop", timeout: 2) != nil else { return false }
        let deadline = Date().addingTimeInterval(wait)
        while Date() < deadline {
            if status(timeout: 0.5) == nil { return true }
            usleep(100_000)
        }
        return false
    }

    // MARK: - Socket helpers

    static func setTimeouts(_ fd: Int32, _ seconds: TimeInterval) {
        var value = timeval(tv_sec: Int(seconds), tv_usec: Int32((seconds - floor(seconds)) * 1_000_000))
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &value, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &value, socklen_t(MemoryLayout<timeval>.size))
    }

    static func address(_ path: String) -> sockaddr_un? {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard bytes.count < capacity else { return nil }
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: bytes)
            buffer[bytes.count] = 0
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        return address
    }

    static func connect(_ fd: Int32, path: String) -> Bool {
        guard var address = address(path) else { return false }
        return withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) == 0
            }
        }
    }

    static func writeAll(_ fd: Int32, _ data: Data) -> Bool {
        data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let written = write(fd, buffer.baseAddress! + offset, buffer.count - offset)
                if written <= 0 {
                    if written < 0, errno == EINTR { continue }
                    return false
                }
                offset += written
            }
            return true
        }
    }

    /// Reads up to and including the first newline, at most `limit` bytes.
    static func readLine(_ fd: Int32, limit: Int) -> Data? {
        var line = Data()
        var chunk = [UInt8](repeating: 0, count: 65536)
        while line.count <= limit {
            let count = read(fd, &chunk, chunk.count)
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { return nil }
            if let newline = chunk[0..<count].firstIndex(of: 0x0A) {
                line.append(contentsOf: chunk[0...newline])
                return line.count <= limit + 1 ? line : nil
            }
            line.append(contentsOf: chunk[0..<count])
        }
        return nil
    }
}

// MARK: - Server

/// The running `serve`. Everything but the socket's accept loop is confined
/// to `queue`.
final class BackgroundServer: @unchecked Sendable {
    let queue = DispatchQueue(label: "rex-boing-agent.serve")
    let sampler = SnapshotSampler()
    var rings: HistoryRings
    var interval: Double
    var timer: DispatchSourceTimer?
    var lastProcessTable: Int64 = 0
    var lastProcessScan = Date.distantPast
    var lastSave = Date()
    var listenFD: Int32 = -1
    let clients = DispatchSemaphore(value: Background.maxClients)
    var signalSources: [DispatchSourceSignal] = []

    init(interval: Double) {
        self.interval = interval
        rings = HistoryRings(interval: interval)
    }

    static func run(interval requested: Double) -> Never {
        let interval = min(10, max(0.5, requested))
        let run = Background.runDirectory
        guard Background.privateDirectory(run, create: true) else {
            fail("\(run) is not a private directory of this user; refusing to use it.")
        }
        // The lock, not the socket, decides who runs.
        let lock = open(run + "/serve.lock", O_RDWR | O_CREAT, 0o600)
        guard lock >= 0 else { fail("cannot open \(run)/serve.lock: \(String(cString: strerror(errno)))") }
        // A serve that was just asked to stop may still be finishing: wait a
        // moment for it rather than giving up at once.
        let deadline = Date().addingTimeInterval(5)
        while flock(lock, LOCK_EX | LOCK_NB) != 0 {
            guard Date() < deadline else {
                FileHandle.standardError.write(Data("rex-boing-agent: already keeping history in the background; nothing to do\n".utf8))
                exit(0)
            }
            usleep(250_000)
        }
        let server = BackgroundServer(interval: interval)
        server.listen()
        server.load()
        server.handleSignals()
        server.queue.async { server.schedule() }
        Thread.detachNewThread { server.acceptLoop() }
        FileHandle.standardError.write(Data("rex-boing-agent: keeping history every \(interval) s, on \(Background.socketPath)\n".utf8))
        dispatchMain()
    }

    static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data("rex-boing-agent: serve: \(message)\n".utf8))
        exit(1)
    }

    func listen() {
        let path = Background.socketPath
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0, var address = Background.address(path) else { Self.fail("cannot create a socket") }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) == 0
            }
        }
        guard bound, chmod(path, 0o600) == 0, Darwin.listen(fd, 16) == 0 else {
            Self.fail("cannot listen on \(path): \(String(cString: strerror(errno)))")
        }
        listenFD = fd
    }

    func load() {
        guard let data = FileManager.default.contents(atPath: Background.historyFile) else { return }
        if let wire = try? JSONDecoder().decode(WireHistory.self, from: data), wire.type == "history" {
            rings.load(wire)
        } else {
            FileHandle.standardError.write(Data("rex-boing-agent: ignoring an unreadable \(Background.historyFile)\n".utf8))
        }
    }

    func handleSignals() {
        for number in [SIGTERM, SIGINT] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: queue)
            source.setEventHandler { [self] in finish() }
            source.resume()
            signalSources.append(source)
        }
    }

    func schedule() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now(), repeating: interval, leeway: .milliseconds(200))
        timer.setEventHandler { [self] in tick() }
        timer.resume()
        self.timer = timer
    }

    func tick() {
        let (snapshot, resync) = sampler.tick(refreshInterval: interval)
        var sample = snapshot.wireSample(full: false)
        sample.resync = resync
        rings.add(sample)
        // The sampler re-reads processes every few seconds on its own; one
        // table every quarter minute is plenty for history.
        let sampledAt = Int64(snapshot.processes.sampledAt.timeIntervalSince1970 * 1000)
        if sampledAt > lastProcessTable, Date().timeIntervalSince(lastProcessScan) >= Background.processEvery - 0.5,
           snapshot.processes.interval > 0, snapshot.processes.interval <= 30,
           let table = snapshot.wireSample(full: true).processes {
            lastProcessTable = sampledAt
            lastProcessScan = Date()
            rings.add(processes: table)
        }
        if Date().timeIntervalSince(lastSave) >= Background.saveEvery {
            lastSave = Date()
            save()
        }
    }

    /// Writes the rings through a temporary file, so a crash or a power cut
    /// leaves the old file or the new one, never half of one.
    func save() {
        let data = rings.encoded(maxLength: .max)
        let path = Background.historyFile
        let temp = path + ".\(getpid()).tmp"
        guard FileManager.default.createFile(atPath: temp, contents: data, attributes: [.posixPermissions: 0o600]) else { return }
        let fd = open(temp, O_RDONLY)
        if fd >= 0 { fsync(fd); close(fd) }
        if rename(temp, path) != 0 { unlink(temp) }
    }

    func acceptLoop() {
        while true {
            let fd = accept(listenFD, nil, nil)
            if fd < 0 {
                if errno == EINTR { continue }
                usleep(100_000)
                continue
            }
            var uid: uid_t = 0
            var gid: gid_t = 0
            guard getpeereid(fd, &uid, &gid) == 0, uid == getuid() else {
                close(fd)
                continue
            }
            guard clients.wait(timeout: .now()) == .success else {
                close(fd) // busy: the client tries again on its next session
                continue
            }
            DispatchQueue.global(qos: .utility).async { [self] in
                defer { clients.signal() }
                handle(fd)
            }
        }
    }

    /// Answers one request line with one line, then waits briefly for the
    /// client to hang up, so the whole answer is read before the close.
    func handle(_ fd: Int32) {
        defer { close(fd) }
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        Background.setTimeouts(fd, 2)
        guard let line = Background.readLine(fd, limit: Background.maxRequest) else { return }
        struct Request: Decodable { var want: String? }
        let want = (try? JSONDecoder().decode(Request.self, from: line))?.want
        var answer: Data
        var stopping = false
        switch want {
        case "history":
            answer = queue.sync { rings.encoded(maxLength: Background.maxLine - 1) }
        case "status":
            let status = queue.sync {
                Background.Status(pid: getpid(), version: agentVersion, started: rings.started, interval: interval,
                                  oldest: rings.oldest.map { Int64($0.timeIntervalSince1970 * 1000) },
                                  endpoint: Background.socketPath)
            }
            answer = (try? JSONEncoder().encode(status)) ?? Data()
        case "stop":
            answer = Data(#"{"type":"stopping"}"#.utf8)
            stopping = true
        default:
            answer = Data(#"{"type":"error","message":"unknown request"}"#.utf8)
        }
        Background.setTimeouts(fd, 10)
        guard Background.writeAll(fd, answer + [0x0A]) else { return }
        var scratch = [UInt8](repeating: 0, count: 512)
        while read(fd, &scratch, scratch.count) > 0 {}
        if stopping {
            queue.async { [self] in finish() }
        }
    }

    /// Saves the rings and exits, leaving no socket behind.
    func finish() -> Never {
        save()
        unlink(Background.socketPath)
        exit(0)
    }
}
