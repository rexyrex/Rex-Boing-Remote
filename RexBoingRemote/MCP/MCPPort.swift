import Foundation

/// The link between `Rex Boing Remote mcp` and the running app: a local Mach
/// message port (`CFMessagePort`), registered by name in this login
/// session's bootstrap namespace. It is neither a network listener nor a
/// file: only processes of this user's session can look it up, and nothing
/// else on the Mac or the network can reach it.
///
/// One request, one reply. The app answers on its main run loop, at once;
/// an answer that needs a fresh sample says "retry", and the bridge asks
/// again a moment later (see `MCPAppServer`).
///
/// A process sends one request at a time. `CFMessagePortCreateRemote` hands
/// every caller in a process the same remote port object for a name, and
/// that object has a single reply port and one table of pending replies:
/// requests sent through it from several threads at once lose replies (the
/// sender waits out its timeout), see the port invalidated under them, and
/// can crash. The app answers one request at a time on its main run loop
/// anyway, so taking turns costs concurrent tool calls nothing; only the
/// exchange itself is serialized, never the waits between retries.
enum MCPPort {
    /// Demo mode's copy answers under a name of its own, so a demo bridge can
    /// only ever reach the demo copy, and a normal one only the normal copy.
    static func name(demo: Bool) -> String {
        demo ? "com.rexyrex.RexBoingRemote.mcp.demo" : "com.rexyrex.RexBoingRemote.mcp"
    }

    static let requestID: Int32 = 1

    enum Outcome {
        case reply(Data)
        /// Nothing has the name: the app isn't running, or isn't answering
        /// agents.
        case noPort
        /// The port was there, but the exchange failed: it went away during
        /// the call (the app quit), or did not answer in time.
        case failed(Int32)
        /// Other requests from this process held the port until `before`
        /// passed: the app is not answering them either.
        case busy
    }

    private static let turn = NSLock()
    /// The remote ports in use, by name. Only touched while holding `turn`.
    nonisolated(unsafe) private static var remotes: [String: CFMessagePort] = [:]

    /// Sends one request and waits for its reply on the calling thread,
    /// after any request from another thread of this process has had its
    /// answer, or until `before`.
    static func send(_ data: Data, to name: String, timeout: TimeInterval, before deadline: Date) -> Outcome {
        guard turn.lock(before: deadline) else { return .busy }
        defer { turn.unlock() }
        // A port kept from an earlier request may belong to a copy of the
        // app that has quit since; CF marks it invalid when it notices, and a
        // send that finds it dead first says so. Either way it is dropped and
        // the name looked up again, once, so a restarted app is found at once.
        for _ in 0..<2 {
            var fresh = false
            if let kept = remotes[name], !CFMessagePortIsValid(kept) { remotes[name] = nil }
            if remotes[name] == nil {
                guard let found = CFMessagePortCreateRemote(nil, name as CFString) else { return .noPort }
                remotes[name] = found
                fresh = true
            }
            guard let remote = remotes[name] else { return .noPort }
            var reply: Unmanaged<CFData>?
            let status = CFMessagePortSendRequest(
                remote, requestID, data as CFData, 2, timeout, CFRunLoopMode.defaultMode.rawValue, &reply)
            let received = reply?.takeRetainedValue() as Data?
            if status == kCFMessagePortSuccess, let received { return .reply(received) }
            // A slow answer is not a dead port: keep it.
            if status == kCFMessagePortSendTimeout || status == kCFMessagePortReceiveTimeout { return .failed(status) }
            // Safe to invalidate: no other request can be using it now.
            CFMessagePortInvalidate(remote)
            remotes[name] = nil
            if fresh { return .failed(status == kCFMessagePortSuccess ? kCFMessagePortTransportError : status) }
        }
        return .failed(kCFMessagePortTransportError)
    }
}

/// The app's end of the port. Requests are answered on the main run loop by
/// `handler`, which must return straight away.
@MainActor
final class MCPLocalPort {
    private final class Box {
        let handler: @MainActor (Data) -> Data
        init(_ handler: @escaping @MainActor (Data) -> Data) { self.handler = handler }
    }

    private let port: CFMessagePort
    private let source: CFRunLoopSource
    private let box: Box

    /// Nil when the name is taken (another copy of the same kind already
    /// answers under it) or the port can't be made.
    init?(name: String, handler: @escaping @MainActor (Data) -> Data) {
        let box = Box(handler)
        var context = CFMessagePortContext(
            version: 0, info: Unmanaged.passUnretained(box).toOpaque(), retain: nil, release: nil, copyDescription: nil)
        var shouldFree: DarwinBoolean = false
        let callback: CFMessagePortCallBack = { _, _, data, info in
            guard let info else { return nil }
            let box = Unmanaged<Box>.fromOpaque(info).takeUnretainedValue()
            let request = (data as Data?) ?? Data()
            // The source is on the main run loop, so this is the main thread.
            let reply = MainActor.assumeIsolated { box.handler(request) }
            // The port releases the reply once it is sent.
            return Unmanaged.passRetained(reply as CFData)
        }
        guard let port = CFMessagePortCreateLocal(nil, name as CFString, callback, &context, &shouldFree),
              !shouldFree.boolValue,
              let source = CFMessagePortCreateRunLoopSource(nil, port, 0) else { return nil }
        self.port = port
        self.source = source
        self.box = box
        // Common modes: answered while a menu is open or an alert is up too.
        CFRunLoopAddSource(CFRunLoopGetMain(), source, .commonModes)
    }

    func invalidate() {
        CFRunLoopRemoveSource(CFRunLoopGetMain(), source, .commonModes)
        CFMessagePortInvalidate(port)
    }
}
