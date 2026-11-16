import AppKit
import SwiftUI
import RexBoingKit

// What makes a Rex Boing Remote surface read as Remote's and not Rex Boing's.
//
// The two apps draw with the same cards and the same characters, on purpose,
// and until now they also shared a colour: Rex Boing's blue led both headers,
// so a Remote popover open beside a Rex Boing one was told apart by reading
// it. Remote's own colour is the violet of its icon. It leads everything
// Remote says about itself — its name, its characters, its window's ground —
// and it frames every dashboard with a banner saying whose numbers these are,
// because the one thing a remote monitor must never leave in doubt is which
// machine is on screen.

enum Brand {
    /// The icon's violet, lifted on a dark ground where the plate's own
    /// shade is too deep to set small type in.
    static let ink = NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            ? NSColor(srgbRed: 0.66, green: 0.55, blue: 1.00, alpha: 1)
            : NSColor(srgbRed: 0.42, green: 0.26, blue: 0.82, alpha: 1)
    }

    static let violet = Color(nsColor: ink)

    /// The mark beside every Remote rex in the menu bar, as a symbol.
    static let signalSymbol = "dot.radiowaves.up.forward"
}

/// The name, with "Remote" as the word that carries the colour: it is the
/// half of the name Rex Boing does not have.
struct RemoteWordmark: View {
    var size: CGFloat = 17

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: size * 0.28) {
            Text("Rex Boing \(Text("Remote").foregroundStyle(Brand.violet))")
                .font(.system(size: size, weight: .bold, design: .rounded))
                .tracking(-0.3)
                .lineLimit(1)
            Image(systemName: Brand.signalSymbol)
                .font(.system(size: size * 0.62, weight: .bold))
                .foregroundStyle(Brand.violet)
                .accessibilityHidden(true)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Rex Boing Remote")
    }
}

/// A server's character with Remote's signal mark at its shoulder, the way
/// the menu bar draws the pair.
struct RemoteCharacter: View {
    var character: Visualizer
    var isLive: Bool
    var width: CGFloat = Visualizer.canvasSize.width

    /// Raised on a selected sidebar row, whose ground is the accent colour —
    /// Remote's violet, on which a violet rex is not there at all.
    @Environment(\.backgroundProminence) private var prominence

    var body: some View {
        Image(nsImage: CharacterIcon.image(for: character))
            .renderingMode(.template)
            .resizable()
            .interpolation(.high)
            .frame(width: width, height: width * Visualizer.canvasSize.height / Visualizer.canvasSize.width)
            .foregroundStyle(ink)
            .accessibilityHidden(true)
    }

    private var ink: Color {
        if prominence == .increased { return isLive ? .white : Color.white.opacity(0.55) }
        return isLive ? Brand.violet : Color.secondary.opacity(0.5)
    }
}

/// What a server runs, as a small chip.
struct PlatformChip: View {
    var os: String?
    var arch: String?

    var body: some View {
        HStack(spacing: 3) {
            Image(systemName: symbol)
                .font(.system(size: 8.5, weight: .semibold))
            Text(label)
                .font(.system(size: 9.5, weight: .semibold))
        }
        .foregroundStyle(Brand.violet)
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
        .background(Capsule(style: .continuous).fill(Brand.violet.opacity(0.15)))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
    }

    private var symbol: String {
        switch os {
        case "darwin": return "apple.logo"
        case "windows": return "pc"
        default: return "server.rack"
        }
    }

    private var label: String {
        let name: String
        switch os {
        case "darwin": name = "macOS"
        case "windows": name = "Windows"
        case "linux": name = "Linux"
        case .some(let other) where !other.isEmpty: name = other
        default: name = "Server"
        }
        guard let arch, !arch.isEmpty else { return name }
        return "\(name) · \(arch)"
    }
}

/// The strip at the head of every dashboard: which machine this is, how the
/// app reaches it, and whether what is on screen is still arriving.
///
/// Rex Boing has no such thing and needs none — its numbers are this Mac's.
/// Here they are another machine's, read over a connection that can drop,
/// and the strip is where both of those facts live.
struct ServerBanner: View {
    var server: Server
    @ObservedObject var connection: ServerConnection

    var body: some View {
        HStack(spacing: 9) {
            Image(systemName: Brand.signalSymbol)
                .font(.system(size: 12, weight: .bold))
                .foregroundStyle(isLive ? Brand.violet : Color.secondary)
                .frame(width: 26, height: 26)
                .background(
                    RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .fill(Brand.violet.opacity(isLive ? 0.18 : 0.08)))
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text("Remote")
                        .font(.system(size: 9.5, weight: .bold))
                        .kerning(0.7)
                        .textCase(.uppercase)
                        .foregroundStyle(Brand.violet)
                    Text(server.destinationLabel)
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                Text(route)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 6)

            PlatformChip(os: server.os, arch: server.arch)

            TimelineView(.periodic(from: .now, by: 1)) { context in
                HStack(spacing: 5) {
                    StateDot(state: connection.state)
                    Text(status(now: context.date))
                        .font(.system(size: 10.5, weight: .medium))
                        .monospacedDigit()
                        .foregroundStyle(isLive ? Color.primary : Color.secondary)
                        .lineLimit(1)
                }
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(
            RoundedRectangle(cornerRadius: 11, style: .continuous)
                .fill(Brand.violet.opacity(0.09)))
        .overlay(
            RoundedRectangle(cornerRadius: 11, style: .continuous)
                .strokeBorder(Brand.violet.opacity(0.28), lineWidth: 1))
        .accessibilityElement(children: .combine)
    }

    private var isLive: Bool { connection.state == .live }

    /// How the app gets there and what answers: "over SSH · agent 0.2.0 ·
    /// keeps history while this Mac is away".
    private var route: String {
        var parts = ["over SSH"]
        if let version = connection.hello?.agent?.version ?? server.agentVersion {
            parts.append("agent \(version)")
        }
        if server.keepHistory == true { parts.append("keeps history while this Mac is away") }
        return parts.joined(separator: " · ")
    }

    private func status(now: Date) -> String {
        switch connection.state {
        case .live:
            guard let last = connection.lastSampleAt else { return "Live" }
            let age = max(0, now.timeIntervalSince(last))
            return age < 5 ? "Live" : "Live · \(Int(age)) s ago"
        case .connecting: return "Connecting…"
        case .waiting(let until, _):
            return "Retrying in \(max(0, Int(until.timeIntervalSince(now).rounded()))) s"
        case .attention: return "Needs attention"
        case .idle: return "Paused"
        }
    }
}

extension ServerConnection {
    /// The server in one line: model, chip, threads, memory, system, uptime.
    func hostLine(for server: Server) -> String {
        guard let host = hello?.host else { return server.destinationLabel }
        var parts: [String] = []
        if let model = host.modelName ?? host.hostname { parts.append(model) }
        if let chip = host.chipName, !chip.isEmpty { parts.append(chip) }
        if let cores = host.logicalCores { parts.append("\(cores) threads") }
        if let memory = host.memoryBytes { parts.append(Format.bytes(memory)) }
        if let os = [host.osName, host.osVersion].compactMap({ $0 }).joined(separator: " ").nilIfEmpty {
            parts.append(os)
        }
        if let uptime = snapshot?.extras.system?.uptime {
            parts.append("up \(Format.duration(uptime))")
        }
        return parts.joined(separator: " · ")
    }

    /// What is wrong with the stream, if anything, in a few words.
    var issueTitle: String? {
        switch state {
        case .live, .idle: return nil
        case .connecting: return snapshot == nil ? nil : "Reconnecting…"
        case .waiting(_, let reason): return reason
        case .attention(let issue): return issue.title
        }
    }

    /// What to say in place of a dashboard that has nothing to show yet.
    func waitingText(for server: Server) -> String {
        switch state {
        case .connecting: return "Connecting to \(server.name)…"
        case .waiting(_, let reason): return reason
        case .attention(let issue): return issue.explanation(for: server)
        case .idle: return "Paused."
        case .live: return "Taking the first sample…"
        }
    }
}
