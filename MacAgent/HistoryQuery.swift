import Foundation
import RexBoingKit

// `history`: what the background agent kept between two moments, for people
// and for the agents they ask (PROTOCOL.md, "Reading history on the
// server"). The same command, options and output as the Go agent's
// (agent/internal/history/query.go and the Go main's cmdHistory).

enum HistoryCommand {
    static func run(_ args: [String]) -> Int32 {
        var from: String?, to: String?, at: String?
        var json = false, utc = false
        var index = 0
        while index < args.count {
            let arg = args[index]
            func value() -> String? {
                index += 1
                return index < args.count ? args[index] : nil
            }
            switch arg {
            case "--from": from = value()
            case "--to": to = value()
            case "--at": at = value()
            case "--json": json = true
            case "--utc": utc = true
            case "-h", "--help":
                FileHandle.standardError.write(Data(help.utf8))
                return 0
            default: return fail("unknown option \(arg)\n\n" + help, status: 2)
            }
            index += 1
        }
        let zone = utc ? TimeZone(identifier: "UTC")! : TimeZone.current
        let now = Date()
        var start: Date, end: Date
        if let at {
            guard from == nil, to == nil else { return fail("use --at, or --from and --to, not both", status: 2) }
            guard let moment = parseMoment(at, now: now, zone: zone) else { return fail("--at: \(notAMoment(at))", status: 2) }
            let step = HistoryRings.processStep
            end = Date(timeIntervalSince1970: (moment.timeIntervalSince1970 / step).rounded(.up) * step)
            start = end.addingTimeInterval(-step)
        } else {
            end = now
            if let to {
                guard let moment = parseMoment(to, now: now, zone: zone) else { return fail("--to: \(notAMoment(to))", status: 2) }
                end = moment
            }
            start = end.addingTimeInterval(-86400)
            if let from {
                guard let moment = parseMoment(from, now: now, zone: zone) else { return fail("--from: \(notAMoment(from))", status: 2) }
                start = moment
            }
        }
        guard start < end else { return fail("the start must come before the end", status: 2) }

        var data = Background.export()
        if data == nil {
            guard let saved = FileManager.default.contents(atPath: Background.historyFile) else {
                return fail("no history is kept on this machine. Turn on Keep history in Rex Boing Remote › Settings › Servers, "
                    + "and the background agent records from then on.", status: 1)
            }
            var when = ""
            if let modified = (try? FileManager.default.attributesOfItem(atPath: Background.historyFile))?[.modificationDate] as? Date {
                when = " at " + format(modified, "EEE MMM d HH:mm", zone)
            }
            FileHandle.standardError.write(Data("rex-boing-agent: the background agent is not running; this is what it last saved\(when).\n".utf8))
            data = saved
        }
        guard let data, let range = HistoryRange(data, from: ms(start), to: ms(end)) else {
            return fail("the history cannot be read", status: 1)
        }
        FileHandle.standardOutput.write(json ? range.json() + [0x0A] : Data(range.text(zone: zone).utf8))
        return 0
    }

    static let help = """
        Usage: rex-boing-agent history [--from T] [--to T] [--at T] [--json] [--utc]
          --from T   the start; default 24 hours before the end
          --to T     the end; default now
          --at T     the quarter hour holding T, instead of --from and --to
          --json     print the range as a history message (PROTOCOL.md)
          --utc      show times in UTC rather than this machine's time zone
        A moment T is: now; how long ago (90m, 6h, 3d, 2w, 1h30m); ms or seconds since the epoch;
        RFC 3339; a date and time (2026-11-17 03:00); a date; or a time of day (today's, or
        yesterday's if today's is still to come).

        """

    static func fail(_ message: String, status: Int32) -> Int32 {
        FileHandle.standardError.write(Data("rex-boing-agent: \(message)\n".utf8))
        return status
    }

    static func notAMoment(_ text: String) -> String {
        "\"\(text)\" is not a moment: try 2026-11-17 03:00, 03:00, 6h or 3d"
    }

    static func ms(_ date: Date) -> Int64 { Int64((date.timeIntervalSince1970 * 1000).rounded()) }

    static func format(_ date: Date, _ pattern: String, _ zone: TimeZone) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = zone
        formatter.dateFormat = pattern
        return formatter.string(from: date)
    }

    /// A moment as the history command takes it: "now", how long ago ("90m",
    /// "6h", "3d", "2w", "1h30m"), ms or seconds since the epoch, RFC 3339,
    /// a date and time in `zone` ("2026-11-17 03:00"), a date (its
    /// midnight), or a time of day: today's, or yesterday's if today's is
    /// still to come.
    static func parseMoment(_ input: String, now: Date, zone: TimeZone) -> Date? {
        let text = input.trimmingCharacters(in: .whitespaces)
        if text.isEmpty || text == "now" { return now }
        if let ago = agoSeconds(text) { return now.addingTimeInterval(-ago) }
        if text.allSatisfy(\.isNumber), let n = Int64(text), n > 0 {
            return Date(timeIntervalSince1970: n >= 100_000_000_000 ? Double(n) / 1000 : Double(n))
        }
        let iso = ISO8601DateFormatter()
        if let date = iso.date(from: text) { return date }
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = iso.date(from: text) { return date }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = zone
        formatter.isLenient = false
        for pattern in ["yyyy-MM-dd'T'HH:mm:ss", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd'T'HH:mm", "yyyy-MM-dd HH:mm", "yyyy-MM-dd"] {
            formatter.dateFormat = pattern
            if let date = formatter.date(from: text) { return date }
        }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = zone
        for pattern in ["HH:mm", "HH:mm:ss"] {
            formatter.dateFormat = pattern
            guard let time = formatter.date(from: text) else { continue }
            let parts = calendar.dateComponents([.hour, .minute, .second], from: time)
            guard var date = calendar.date(bySettingHour: parts.hour ?? 0, minute: parts.minute ?? 0, second: parts.second ?? 0, of: now)
            else { continue }
            if date > now { date = calendar.date(byAdding: .day, value: -1, to: date) ?? date }
            return date
        }
        return nil
    }

    /// "90m", "6h", "3d", "2w", "45s", "1.5h", or a Go-style "1h30m".
    static func agoSeconds(_ text: String) -> TimeInterval? {
        let units: [String: TimeInterval] = ["s": 1, "m": 60, "min": 60, "h": 3600, "d": 86400, "w": 604_800]
        let simple = text.replacingOccurrences(of: " ", with: "")
        if let unit = units.keys.sorted(by: { $0.count > $1.count }).first(where: { simple.hasSuffix($0) }),
           let n = Double(simple.dropLast(unit.count)), n >= 0, simple.first?.isNumber == true {
            return n * units[unit]!
        }
        // Several parts, each a number and one of h, m, s.
        var total: TimeInterval = 0
        var number = ""
        var parts = 0
        for character in text {
            if character.isNumber || character == "." {
                number.append(character)
            } else if let value = Double(number), let unit = ["h": 3600.0, "m": 60, "s": 1][String(character)] {
                total += value * unit
                number = ""
                parts += 1
            } else {
                return nil
            }
        }
        return number.isEmpty && parts > 0 && total > 0 ? total : nil
    }
}

/// The history kept between two moments.
struct HistoryRange {
    var from, to: Int64
    var started: Int64?
    var interval: Double
    var keepDays: Int
    var oldest: Int64 = 0
    var tiers: [(step: Double, points: [HistoryPoint])] = []
    var processes: [WireProcesses] = []
    var usage: [WireUsage] = []

    /// Keeps what overlaps (from, to] in an exported history message: the
    /// points, process tables and usage whose windows reach into it.
    init?(_ data: Data, from: Int64, to: Int64) {
        guard let wire = try? JSONDecoder().decode(WireHistory.self, from: data), wire.type == "history" else { return nil }
        self.from = from
        self.to = to
        started = wire.started
        interval = wire.interval ?? 2
        keepDays = max(wire.keepDays ?? HistoryRings.defaultKeepDays, HistoryRings.defaultKeepDays)
        func overlaps(_ end: Int64, _ step: Double) -> Bool { end > from && Double(end) - step * 1000 < Double(to) }
        for tier in wire.tiers ?? [] {
            guard let step = tier.step else { continue }
            let points = tier.points
            if let first = points.first?.t, oldest == 0 || first < oldest { oldest = first }
            tiers.append((step, points.filter { overlaps($0.t, step) }))
        }
        tiers.sort { $0.step < $1.step }
        let quarter = HistoryRings.processStep
        processes = (wire.processes ?? []).filter {
            overlaps(HistoryRings.bucketEnd($0.sampledAt ?? 0, step: quarter), quarter)
        }
        usage = (wire.usage ?? []).filter { overlaps($0.end ?? 0, quarter) }
    }

    /// The range as a history message, with "from" and "to".
    func json() -> Data {
        var wire = WireHistory()
        wire.started = started
        wire.interval = interval
        wire.keepDays = keepDays
        wire.from = from
        wire.to = to
        wire.tiers = tiers.map { tier in
            var out = WireHistory.Tier(step: tier.step)
            out.t = tier.points.map(\.t)
            for series in HistorySeries.allCases where tier.points.contains(where: { $0[series] != nil }) {
                let scale = pow(10, Double(series.decimals))
                out[series] = tier.points.map { point in point[series].map { ($0 * scale).rounded() / scale } }
            }
            return out
        }
        if !processes.isEmpty { wire.processes = processes }
        if !usage.isEmpty { wire.usage = usage }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return (try? encoder.encode(wire)) ?? Data(#"{"type":"history"}"#.utf8)
    }

    /// The tier that best covers the range: the one whose points reach back
    /// furthest into it, the finer of two that reach as far.
    var vitals: (step: Double, points: [HistoryPoint]) {
        var best: (step: Double, points: [HistoryPoint]) = (0, [])
        var bestStart = Int64.max
        for tier in tiers {
            guard let first = tier.points.first else { continue }
            let start = max(first.t - Int64(tier.step * 1000), from)
            if start < bestStart { (best, bestStart) = (tier, start) }
        }
        return best
    }

    func text(zone: TimeZone) -> String {
        func date(_ ms: Int64) -> Date { Date(timeIntervalSince1970: Double(ms) / 1000) }
        let sameDay = HistoryCommand.format(date(from), "yyyy-MM-dd", zone) == HistoryCommand.format(date(to), "yyyy-MM-dd", zone)
        func full(_ ms: Int64) -> String { HistoryCommand.format(date(ms), "EEE MMM d HH:mm", zone) }
        func at(_ ms: Int64) -> String { sameDay ? HistoryCommand.format(date(ms), "HH:mm", zone) : full(ms) }
        func window(_ end: Int64, _ step: TimeInterval) -> String {
            at(end - Int64(step * 1000)) + "–" + HistoryCommand.format(date(end), "HH:mm", zone)
        }
        var out = ""
        let offset = zone.secondsFromGMT(for: date(to))
        let abbreviation = zone.abbreviation(for: date(to)) ?? zone.identifier
        let zoneText = offset == 0 && (abbreviation == "UTC" || abbreviation == "GMT")
            ? "UTC" : "\(abbreviation), UTC\(Self.utcOffset(offset))"
        out += "History from \(full(from)) to \(full(to)) (\(zoneText)).\n"
        out += "The background agent samples every \(String(format: "%g", interval)) s and keeps "
            + HistoryRings.retentionText(days: keepDays)
        if oldest > 0 { out += "; it has history back to \(full(oldest))" }
        out += ".\n"

        let v = vitals
        if let first = v.points.first, let last = v.points.last {
            out += "\nVitals (\(Self.stepName(v.step))), \(at(first.t - Int64(v.step * 1000))) to \(at(last.t)):\n"
            out += vitalsText(v, at: at, window: window)
        } else {
            out += "\nNo vitals were recorded in this time.\n"
        }
        if usage.isEmpty {
            guard !processes.isEmpty else { return out + "\nNo processes were recorded in this time.\n" }
            out += "\nBusiest moment of each quarter hour (no per-process usage was recorded; an older agent?):\n"
            for table in processes {
                let rows = (table.rows ?? []).enumerated().sorted {
                    let (a, b) = (HistoryRings.finite($0.element.cpu), HistoryRings.finite($1.element.cpu))
                    return a != b ? a > b : $0.offset < $1.offset
                }.prefix(3).map { "\($0.element.name ?? "?") \(String(format: "%.0f%%", HistoryRings.finite($0.element.cpu)))" }
                out += "  \(at(table.sampledAt ?? 0))  \(rows.joined(separator: ", "))\n"
            }
            return out
        }
        out += processesText { window($0, HistoryRings.processStep) }
        out += quartersText(v) { window($0, HistoryRings.processStep) }
        return out
    }

    static func utcOffset(_ seconds: Int) -> String {
        let sign = seconds < 0 ? "-" : "+"
        let s = abs(seconds)
        return String(format: "%@%02d:%02d", sign, s / 3600, s % 3600 / 60)
    }

    static func stepName(_ step: Double) -> String {
        if step >= 60 { return String(format: "%g-minute means", step / 60) }
        if step >= 30 { return String(format: "%g-second means", step) }
        return String(format: "every sample, %g s apart", step)
    }

    static func percent(_ v: Double) -> String { String(format: "%.0f%%", v * 100) }
    static func rate(_ v: Double) -> String { bytes(v) + "/s" }

    /// A size in decimal units, as the app shows them.
    static func bytes(_ value: Double) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var v = value
        var i = 0
        while v >= 1000, i < units.count - 1 {
            v /= 1000
            i += 1
        }
        return i == 0 ? String(format: "%.0f B", v) : String(format: "%.1f %@", v, units[i])
    }

    /// Pads to a width in bytes, as Go's %-*s does.
    static func pad(_ text: String, _ width: Int) -> String {
        text + String(repeating: " ", count: max(0, width - text.utf8.count))
    }

    static let vitalRows: [(HistorySeries, String, (Double) -> String)] = [
        (.cpu, "CPU", percent), (.memory, "Memory", percent), (.swap, "Swap", percent), (.gpu, "GPU", percent),
        (.cpuCelsius, "CPU temperature", { String(format: "%.1f °C", $0) }),
        (.gpuCelsius, "GPU temperature", { String(format: "%.1f °C", $0) }),
        (.watts, "Power", { String(format: "%.1f W", $0) }),
        (.rx, "Network in", rate), (.tx, "Network out", rate), (.read, "Disk read", rate), (.write, "Disk write", rate),
    ]

    func vitalsText(_ v: (step: Double, points: [HistoryPoint]), at: (Int64) -> String,
                    window: (Int64, TimeInterval) -> String) -> String {
        let width = Self.vitalRows.map(\.1.utf8.count).max() ?? 0
        func when(_ end: Int64) -> String { v.step < 60 ? "at " + at(end) : "in " + window(end, v.step) }
        var out = ""
        for (series, name, format) in Self.vitalRows {
            var sum = 0.0, n = 0
            var peak = -Double.infinity, peakAt: Int64 = 0
            for point in v.points {
                guard let value = point[series] else { continue }
                sum += value
                n += 1
                let high = series == .cpu ? (point[.cpuPeak] ?? value) : value
                if high > peak { (peak, peakAt) = (high, point.t) }
            }
            guard n > 0 else { continue }
            out += "  \(Self.pad(name, width))  mean \(Self.pad(format(sum / Double(n)), 9)) peak \(format(peak)) \(when(peakAt))\n"
        }
        return out
    }

    /// One process name's work over the range, summed from the quarter
    /// hours it led in.
    final class Total {
        var name, user, cmd: String
        var pids = Set<Int32>()
        var cpuSeconds = 0.0, gpuSeconds = 0.0, read = 0.0, write = 0.0
        var memory: UInt64 = 0, memoryAt: Int64 = 0
        var cpuPeak = 0.0, cpuPeakAt: Int64 = 0

        init(name: String, user: String, cmd: String) {
            self.name = name
            self.user = user
            self.cmd = cmd
        }

        var who: String {
            var parts: [String] = []
            if !user.isEmpty { parts.append(user) }
            if pids.count > 1 { parts.append("\(pids.count) processes") } else if let pid = pids.first { parts.append("pid \(pid)") }
            return "\(name) (\(parts.joined(separator: ", ")))"
        }

        var cmdText: String {
            guard !cmd.isEmpty, cmd != name else { return "" }
            var text = cmd
            if text.utf8.count > 80 {
                var cut = ""
                for character in text {
                    if cut.utf8.count + String(character).utf8.count > 80 { break }
                    cut.append(character)
                }
                text = cut + "…"
            }
            return "\n             " + text
        }
    }

    var totals: [Total] {
        var byName: [String: Total] = [:]
        for window in usage {
            let seconds = window.seconds ?? 0
            for row in window.rows ?? [] {
                let name = row.name ?? "", user = row.user ?? ""
                let total = byName[name + "\u{0}" + user] ?? Total(name: name, user: user, cmd: row.cmd ?? "")
                byName[name + "\u{0}" + user] = total
                if let pid = row.pid { total.pids.insert(pid) }
                total.cpuSeconds += (row.cpu ?? 0) / 100 * seconds
                total.gpuSeconds += (row.gpu ?? 0) / 100 * seconds
                total.read += (row.diskRead ?? 0) * seconds
                total.write += (row.diskWrite ?? 0) * seconds
                if let memory = row.memory, memory > total.memory { (total.memory, total.memoryAt) = (memory, window.end ?? 0) }
                if let peak = row.cpuPeak, peak > total.cpuPeak { (total.cpuPeak, total.cpuPeakAt) = (peak, window.end ?? 0) }
            }
        }
        return byName.values.sorted { $0.name < $1.name }
    }

    static func duration(_ seconds: Double) -> String {
        if seconds >= 3600 { return String(format: "%.1f h", seconds / 3600) }
        if seconds >= 60 { return String(format: "%.0f min", seconds / 60) }
        return String(format: "%.0f s", seconds)
    }

    func processesText(_ at: (Int64) -> String) -> String {
        let totals = totals
        let quarters = usage.count == 1 ? "1 quarter hour" : "\(usage.count) quarter hours"
        var out = "\nProcesses that used the most, over \(quarters) "
            + "(each quarter hour keeps its top \(HistoryRings.processRows) by CPU, memory, disk and GPU):\n"
        // Lines start at a second of CPU or GPU time, or a byte.
        func section(_ title: String, _ value: (Total) -> Double, _ line: (Total) -> String) {
            let lines = totals.enumerated()
                .sorted { value($0.element) != value($1.element) ? value($0.element) > value($1.element) : $0.offset < $1.offset }
                .map(\.element)
                .prefix(while: { value($0) >= 1 })
                .prefix(8)
            guard !lines.isEmpty else { return }
            out += "  \(title):\n"
            for total in lines { out += "    " + line(total) + "\n" }
        }
        section("CPU time (core-hours: 1 h is one core busy for an hour)", { $0.cpuSeconds }) {
            "\(Self.pad(Self.duration($0.cpuSeconds), 8)) \($0.who), peak \(String(format: "%.0f", $0.cpuPeak))% of a core in "
                + "\(at($0.cpuPeakAt))\($0.cmdText)"
        }
        section("Memory (most resident at once)", { Double($0.memory) }) {
            "\(Self.pad(Self.bytes(Double($0.memory)), 8)) \($0.who), in \(at($0.memoryAt))\($0.cmdText)"
        }
        section("Disk (read + written)", { $0.read + $0.write }) {
            "\(Self.pad(Self.bytes($0.read + $0.write), 8)) \($0.who): \(Self.bytes($0.read)) read, \(Self.bytes($0.write)) written\($0.cmdText)"
        }
        section("GPU time", { $0.gpuSeconds }) { "\(Self.pad(Self.duration($0.gpuSeconds), 8)) \($0.who)\($0.cmdText)" }
        return out
    }

    /// The quarter hours: all of them for a short range, otherwise the
    /// busiest by CPU.
    func quartersText(_ v: (step: Double, points: [HistoryPoint]), window: (Int64) -> String) -> String {
        let step = Int64(HistoryRings.processStep * 1000)
        var quarters: [(usage: WireUsage, cpu: Double?)] = usage.map { entry in
            let end = entry.end ?? 0
            let values = v.points.filter { $0.t > end - step && $0.t <= end }.compactMap { $0[.cpu] }
            return (entry, values.isEmpty ? nil : values.reduce(0, +) / Double(values.count))
        }
        func busy(_ q: (usage: WireUsage, cpu: Double?)) -> Double {
            q.cpu ?? (q.usage.rows ?? []).reduce(0) { $0 + ($1.cpu ?? 0) } / 1e4
        }
        let shown = 12
        var out: String
        if quarters.count > shown {
            quarters = Array(quarters.enumerated()
                .sorted { busy($0.element) != busy($1.element) ? busy($0.element) > busy($1.element) : $0.offset < $1.offset }
                .prefix(shown).map(\.element))
                .sorted { ($0.usage.end ?? 0) < ($1.usage.end ?? 0) }
            out = "\nThe \(shown) busiest quarter hours by CPU, in time order:\n"
        } else {
            out = "\nEach quarter hour:\n"
        }
        for q in quarters {
            var head = window(q.usage.end ?? 0)
            if let cpu = q.cpu { head += "  CPU \(Self.percent(cpu))" }
            if let seconds = q.usage.seconds, seconds < 0.9 * HistoryRings.processStep {
                // Still open, or the agent was not running for all of it.
                head += "  (\(Self.duration(seconds)) of it recorded)"
            }
            out += "  \(head)\n"
            let rows = Dictionary((q.usage.rows ?? []).compactMap { row in row.pid.map { ($0, row) } }, uniquingKeysWith: { $1 })
            func leaders(_ metric: String, _ text: (WireUsage.Row) -> String) -> String {
                (q.usage.rank?[metric] ?? []).compactMap { rows[$0] }.prefix(3).map(text).joined(separator: ", ")
            }
            let lines = [
                ("cpu", leaders("cpu") { "\($0.name ?? "?") \(String(format: "%.0f", $0.cpu ?? 0))%" }),
                ("memory", leaders("memory") { "\($0.name ?? "?") \(Self.bytes(Double($0.memory ?? 0)))" }),
                ("disk", leaders("disk") { "\($0.name ?? "?") \(Self.rate(($0.diskRead ?? 0) + ($0.diskWrite ?? 0)))" }),
                ("gpu", leaders("gpu") { "\($0.name ?? "?") \(String(format: "%.0f", $0.gpu ?? 0))%" }),
            ]
            for (name, text) in lines where !text.isEmpty { out += "    \(Self.pad(name, 7)) \(text)\n" }
        }
        return out
    }
}
