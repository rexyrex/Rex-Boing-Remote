import Foundation
import Network

/// macOS's Local Network privacy, as it affects the `ssh` children this app
/// starts: the app is their responsible process, so if the user has not
/// allowed Local Network access, their connections to LAN addresses fail
/// with a bare "No route to host" and no alert. Probing with Network
/// framework first both triggers the system prompt and lets the app say what
/// is actually wrong.
enum LocalNetwork {
    /// Whether a destination looks like it is on the local network: a private
    /// or link-local address, or a `.local` name.
    static func isLocal(_ destination: String) -> Bool {
        let host = destination.split(separator: "@").last.map(String.init) ?? destination
        if host.hasSuffix(".local") { return true }
        let parts = host.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4 else { return host.hasPrefix("fe80:") || host.hasPrefix("fd") }
        switch (parts[0], parts[1]) {
        case (10, _), (192, 168), (169, 254): return true
        case (172, 16...31): return true
        default: return false
        }
    }

    /// Opens a TCP connection to the host with Network framework and reports
    /// whether it was refused for Local Network privacy. Times out quietly.
    static func isDenied(host: String, port: Int) async -> Bool {
        guard !host.isEmpty, let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else { return false }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp)
        return await withCheckedContinuation { continuation in
            final class Once: @unchecked Sendable {
                private var done = false
                private let lock = NSLock()
                func run(_ body: () -> Void) {
                    lock.lock()
                    defer { lock.unlock() }
                    guard !done else { return }
                    done = true
                    body()
                }
            }
            let once = Once()
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready, .failed, .cancelled:
                    once.run {
                        connection.cancel()
                        continuation.resume(returning: false)
                    }
                case .waiting:
                    let denied = connection.currentPath?.unsatisfiedReason == .localNetworkDenied
                    once.run {
                        connection.cancel()
                        continuation.resume(returning: denied)
                    }
                default:
                    break
                }
            }
            connection.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + 4) {
                once.run {
                    connection.cancel()
                    continuation.resume(returning: false)
                }
            }
        }
    }
}
