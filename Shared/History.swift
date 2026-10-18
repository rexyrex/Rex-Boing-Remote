import Foundation
import RexBoingKit

// The history message (PROTOCOL.md, "Background history") and the rings it
// describes. Compiled into both the macOS agent, whose `serve` keeps the
// rings and sends them, and the app, which keeps the same rings from the
// samples it sees and merges in what an agent kept while the Mac was away.
// agent/internal/history is the Go agent's copy of the same rules.

/// One line of type "history". Every field is optional on the wire.
struct WireHistory: Codable, Sendable {
    var type: String = "history"
    /// When the background agent began, milliseconds since the epoch.
    var started: Int64?
    /// Seconds between its samples.
    var interval: Double?
    /// Finest first.
    var tiers: [Tier]?
    /// The busiest table of every quarter hour, oldest first.
    var processes: [WireProcesses]?

    /// One ring, columnar: every series has one entry per time in `t`, null
    /// where that reading was not available. A series the machine never
    /// reported is left out.
    struct Tier: Codable, Sendable {
        /// Seconds each point covers, ending at its time.
        var step: Double?
        /// Milliseconds since the epoch, oldest first.
        var t: [Int64]?
        var cpu, cpuPeak, cpuUser, cpuSystem, memory, swap, gpu: [Double?]?
        var cpuCelsius, gpuCelsius, watts, rx, tx, read, write: [Double?]?

        init(step: Double?) { self.step = step }

        subscript(series: HistorySeries) -> [Double?]? {
            get {
                switch series {
                case .cpu: return cpu
                case .cpuPeak: return cpuPeak
                case .cpuUser: return cpuUser
                case .cpuSystem: return cpuSystem
                case .memory: return memory
                case .swap: return swap
                case .gpu: return gpu
                case .cpuCelsius: return cpuCelsius
                case .gpuCelsius: return gpuCelsius
                case .watts: return watts
                case .rx: return rx
                case .tx: return tx
                case .read: return read
                case .write: return write
                }
            }
            set {
                switch series {
                case .cpu: cpu = newValue
                case .cpuPeak: cpuPeak = newValue
                case .cpuUser: cpuUser = newValue
                case .cpuSystem: cpuSystem = newValue
                case .memory: memory = newValue
                case .swap: swap = newValue
                case .gpu: gpu = newValue
                case .cpuCelsius: cpuCelsius = newValue
                case .gpuCelsius: gpuCelsius = newValue
                case .watts: watts = newValue
                case .rx: rx = newValue
                case .tx: tx = newValue
                case .read: read = newValue
                case .write: write = newValue
                }
            }
        }

        /// The points this tier holds, skipping any whose series do not
        /// line up with its times.
        var points: [HistoryPoint] {
            guard let times = t else { return [] }
            var points = times.map { HistoryPoint(t: $0) }
            for series in HistorySeries.allCases {
                guard let values = self[series], values.count == times.count else { continue }
                for (index, value) in values.enumerated() {
                    if let value, value.isFinite { points[index][series] = value }
                }
            }
            return points
        }
    }
}

/// The values a history point records.
enum HistorySeries: Int, CaseIterable, Sendable {
    case cpu, cpuPeak, cpuUser, cpuSystem, memory, swap, gpu, cpuCelsius, gpuCelsius, watts, rx, tx, read, write

    /// Decimals kept on the wire: fractions to 0.01 %, degrees to a tenth,
    /// watts to a hundredth, byte rates to whole bytes.
    var decimals: Int {
        switch self {
        case .cpu, .cpuPeak, .cpuUser, .cpuSystem, .memory, .swap, .gpu: return 4
        case .cpuCelsius, .gpuCelsius: return 1
        case .watts: return 2
        case .rx, .tx, .read, .write: return 0
        }
    }
}

/// The machine over one window, ending at `t` (milliseconds since the epoch).
struct HistoryPoint: Sendable, Equatable {
    var t: Int64
    private var values: [Double]

    init(t: Int64) {
        self.t = t
        values = Array(repeating: .nan, count: HistorySeries.allCases.count)
    }

    subscript(series: HistorySeries) -> Double? {
        get {
            let value = values[series.rawValue]
            return value.isNaN ? nil : value
        }
        set { values[series.rawValue] = newValue.flatMap { $0.isFinite ? $0 : nil } ?? .nan }
    }

    var date: Date { Date(timeIntervalSince1970: Double(t) / 1000) }

    static func == (lhs: HistoryPoint, rhs: HistoryPoint) -> Bool {
        lhs.t == rhs.t && zip(lhs.values, rhs.values).allSatisfy { $0 == $1 || ($0.isNaN && $1.isNaN) }
    }

    /// The vitals history keeps from one sample.
    init(sample: WireSample) {
        self.init(t: sample.t ?? 0)
        self[.cpu] = sample.cpu?.total
        self[.cpuUser] = sample.cpu?.user
        self[.cpuSystem] = sample.cpu?.system
        if let memory = sample.memory, let total = memory.total, total > 0, let used = memory.used {
            self[.memory] = Double(used) / Double(total)
            if let swap = memory.swap, let swapTotal = swap.total, swapTotal > 0, let swapUsed = swap.used {
                self[.swap] = Double(swapUsed) / Double(swapTotal)
            }
        }
        self[.gpu] = sample.gpus?.first?.utilization
        self[.cpuCelsius] = sample.thermal?.cpuCelsius ?? sample.thermal?.socCelsius
        self[.gpuCelsius] = sample.thermal?.gpuCelsius
        // Whole-machine draw, in the order the power graph prefers it.
        self[.watts] = sample.power?.systemTotalWatts ?? sample.power?.systemWatts ?? sample.power?.packageWatts
        self[.rx] = sample.network?.rx
        self[.tx] = sample.network?.tx
        self[.read] = sample.disk?.read
        self[.write] = sample.disk?.write
    }

    /// A sample carrying this point's vitals, for code that reads samples.
    /// Memory and swap come back as fractions of `memoryTotal` (or of a
    /// nominal size when it is unknown).
    func sample(step: Double, memoryTotal: UInt64?) -> WireSample {
        var sample = WireSample()
        sample.t = t
        sample.interval = step
        sample.detail = "vitals"
        sample.resync = false
        if let total = self[.cpu] {
            var cpu = WireCPU()
            cpu.total = total
            cpu.user = self[.cpuUser]
            cpu.system = self[.cpuSystem]
            sample.cpu = cpu
        }
        if let fraction = self[.memory] {
            let total = memoryTotal ?? 1 << 30
            var memory = WireMemory()
            memory.total = total
            memory.used = UInt64(max(0, min(1, fraction)) * Double(total))
            if let swapFraction = self[.swap] {
                var swap = WireSwap()
                swap.total = 1 << 30
                swap.used = UInt64(max(0, min(1, swapFraction)) * Double(1 << 30))
                memory.swap = swap
            }
            sample.memory = memory
        }
        if let utilization = self[.gpu] {
            var gpu = WireGPU()
            gpu.utilization = utilization
            sample.gpus = [gpu]
        }
        if self[.cpuCelsius] != nil || self[.gpuCelsius] != nil {
            var thermal = WireThermal()
            thermal.cpuCelsius = self[.cpuCelsius]
            thermal.gpuCelsius = self[.gpuCelsius]
            sample.thermal = thermal
        }
        if let watts = self[.watts] {
            var power = WirePower()
            power.systemTotalWatts = watts
            sample.power = power
        }
        if self[.rx] != nil || self[.tx] != nil {
            var network = WireNetwork()
            network.rx = self[.rx] ?? 0
            network.tx = self[.tx] ?? 0
            sample.network = network
        }
        if self[.read] != nil || self[.write] != nil {
            var disk = WireDisk()
            disk.read = self[.read] ?? 0
            disk.write = self[.write] ?? 0
            sample.disk = disk
        }
        return sample
    }
}

/// One ring: points in time order, none older than `span` seconds.
struct HistoryTier: Sendable {
    /// Seconds each point covers; 0 for the finest tier, whose points are
    /// samples.
    let step: TimeInterval
    let span: TimeInterval
    private(set) var points: [HistoryPoint] = []

    init(step: TimeInterval, span: TimeInterval) {
        self.step = step
        self.span = span
    }

    mutating func append(_ point: HistoryPoint) {
        // A wall clock that stepped back leaves the newer timeline.
        truncate(from: point.t)
        points.append(point)
        prune(now: point.t)
    }

    mutating func truncate(from ms: Int64) {
        if let last = points.last, last.t < ms { return }
        points.removeAll { $0.t >= ms }
    }

    mutating func prune(now ms: Int64) {
        let cut = ms - Int64(span * 1000)
        if let first = points.first, first.t > cut { return }
        points.removeAll { $0.t <= cut }
    }

    /// Replaces this tier's points between the first and last of `other`
    /// with `other`, keeping what lies outside that range: an agent's record
    /// wins where it has one. Then drops what has aged out, unless `prune`
    /// is false.
    mutating func merge(_ other: [HistoryPoint], now ms: Int64, prune: Bool = true) {
        var incoming: [HistoryPoint] = []
        for point in other where point.t <= ms && point.t > (incoming.last?.t ?? .min) {
            incoming.append(point)
        }
        guard let first = incoming.first?.t, let last = incoming.last?.t else { return }
        let before = points.filter { $0.t < first }
        let after = points.filter { $0.t > last }
        points = before + incoming + after
        if prune { self.prune(now: ms) }
    }
}

/// The three rings and the process tables, with the windows still open.
struct HistoryRings: Sendable {
    static let fineSpan: TimeInterval = 15 * 60
    static let mediumStep: TimeInterval = 30
    static let mediumSpan: TimeInterval = 4 * 3600
    static let coarseStep: TimeInterval = 5 * 60
    static let coarseSpan: TimeInterval = 48 * 3600
    static let processStep: TimeInterval = 15 * 60
    static let processSpan: TimeInterval = 24 * 3600
    static let processRows = 5
    static let maxCommand = 200

    /// Seconds between the samples given to `add`.
    var interval: Double
    /// When these rings began, milliseconds since the epoch.
    var started: Int64

    private(set) var fine = HistoryTier(step: 0, span: fineSpan)
    private(set) var medium = HistoryTier(step: mediumStep, span: mediumSpan)
    private(set) var coarse = HistoryTier(step: coarseStep, span: coarseSpan)
    private var mediumBucket = Bucket()
    private var coarseBucket = Bucket()

    private(set) var processes: [WireProcesses] = []
    private var processBest: WireProcesses?
    private var processScore: Double = 0
    private var processEnd: Int64 = 0

    init(interval: Double, started: Date = Date()) {
        self.interval = interval
        self.started = Int64(started.timeIntervalSince1970 * 1000)
    }

    /// Records one sample's vitals. Samples whose rates are not valid are
    /// skipped, as they are everywhere else.
    mutating func add(_ sample: WireSample) {
        guard sample.resync != true, let t = sample.t, t > 0 else { return }
        add(HistoryPoint(sample: sample))
    }

    mutating func add(_ point: HistoryPoint) {
        if let last = fine.points.last, point.t < last.t {
            medium.truncate(from: point.t)
            coarse.truncate(from: point.t)
            mediumBucket = Bucket()
            coarseBucket = Bucket()
        }
        fine.append(point)
        Self.fold(point, into: &medium, bucket: &mediumBucket)
        Self.fold(point, into: &coarse, bucket: &coarseBucket)
    }

    private static func fold(_ point: HistoryPoint, into tier: inout HistoryTier, bucket: inout Bucket) {
        let end = bucketEnd(point.t, step: tier.step)
        if bucket.end != 0, bucket.end != end {
            // A window that ends at or before the tier's newest point is
            // already covered: an agent's record, merged in since the window
            // opened (the app's last window before it went away). Appending
            // it would cut away everything after it, since append keeps the
            // tier in time order by truncating, so it is dropped instead.
            // Samples arriving in order never take this path.
            if bucket.end > (tier.points.last?.t ?? .min) { tier.append(bucket.point) }
            bucket = Bucket()
        }
        bucket.end = end
        bucket.add(point)
        tier.prune(now: point.t)
    }

    /// Windows are aligned to the epoch, so every 5-minute point falls on
    /// :00, :05 and so on, whichever side made it.
    static func bucketEnd(_ ms: Int64, step: TimeInterval) -> Int64 {
        let s = Int64(step * 1000)
        return (ms + s - 1) / s * s
    }

    /// Offers one process table. Each quarter hour keeps the table of its
    /// busiest moment, trimmed to the leaders by CPU and by memory.
    mutating func add(processes table: WireProcesses) {
        // An interval that is not a positive number is not a measurement,
        // and JSON could not carry it.
        guard let at = table.sampledAt, at > 0, let interval = table.interval, interval.isFinite, interval > 0,
              !(table.rows ?? []).isEmpty else { return }
        if at < processEnd - Int64(Self.processStep * 1000) {
            processes.removeAll { ($0.sampledAt ?? 0) >= at }
            processBest = nil
            processEnd = 0
        }
        let end = Self.bucketEnd(at, step: Self.processStep)
        if let best = processBest, end != processEnd {
            processes.append(best)
            processBest = nil
        }
        processEnd = end
        let score = Self.score(table.rows ?? [])
        if processBest == nil || score > processScore {
            processBest = Self.trim(table)
            processScore = score
        }
        let cut = at - Int64(Self.processSpan * 1000)
        processes.removeAll { ($0.sampledAt ?? 0) <= cut }
    }

    /// A reading that is not a number, as 0.
    static func finite(_ value: Double?) -> Double {
        guard let value, value.isFinite else { return 0 }
        return value
    }

    /// How busy a table's moment was: the CPU across its rows. A row whose
    /// CPU is not a number counts as idle, so one bad reading can't make
    /// the score NaN, which loses every comparison and keeps the table.
    static func score(_ rows: [WireProcessRow]) -> Double {
        rows.reduce(0) { $0 + finite($1.cpu) }
    }

    /// The leaders by CPU and by memory, with only the columns history
    /// shows. A CPU that is not a number is kept as 0: JSON can't carry
    /// it, and one such table would take every table with it out of the
    /// history message for as long as it was kept.
    static func trim(_ table: WireProcesses) -> WireProcesses {
        let rows = table.rows ?? []
        func leaders(_ value: (WireProcessRow) -> Double) -> [Int32] {
            rows.filter { value($0) > 0 && $0.pid != nil }
                .sorted { value($0) > value($1) }
                .prefix(processRows)
                .compactMap(\.pid)
        }
        var rank: [String: [Int32]] = [:]
        let cpu = leaders { finite($0.cpu) }
        let memory = leaders { Double($0.memory ?? 0) }
        if !cpu.isEmpty { rank["cpu"] = cpu }
        if !memory.isEmpty { rank["memory"] = memory }
        let keep = Set(cpu + memory)
        var out = WireProcesses()
        out.count = table.count
        out.sampledAt = table.sampledAt
        out.interval = table.interval.map { ($0 * 1000).rounded() / 1000 }
        out.gpuAttribution = false
        out.rank = rank
        out.rows = rows.filter { $0.pid.map(keep.contains) ?? false }.map { row in
            var kept = WireProcessRow()
            kept.pid = row.pid
            kept.name = row.name
            kept.user = row.user
            kept.start = row.start
            kept.cmd = row.cmd.map { truncate($0, bytes: maxCommand) }
            kept.cpu = row.cpu.map { (finite($0) * 10).rounded() / 10 }
            kept.memory = row.memory
            kept.threads = row.threads
            return kept
        }
        return out
    }

    private static func truncate(_ text: String, bytes: Int) -> String {
        guard text.utf8.count > bytes else { return text }
        var result = ""
        for character in text {
            if result.utf8.count + String(character).utf8.count > bytes { break }
            result.append(character)
        }
        return result + "…"
    }

    /// Every table kept, the open window's best included: it is a real table.
    var processTables: [WireProcesses] {
        processes + (processBest.map { [$0] } ?? [])
    }

    /// The point of the finest tier whose window holds `ms`, and that
    /// window's length in seconds.
    func point(containing ms: Int64) -> (point: HistoryPoint, step: Double)? {
        for tier in [medium, coarse] {
            let step = Int64(tier.step * 1000)
            if let point = tier.points.first(where: { $0.t >= ms && $0.t - step < ms }) {
                return (point, tier.step)
            }
        }
        return nil
    }

    /// The oldest point kept.
    var oldest: Date? {
        [fine, medium, coarse].compactMap { $0.points.first?.t }.min()
            .map { Date(timeIntervalSince1970: Double($0) / 1000) }
    }

    // MARK: - Wire

    func wire(includeProcesses: Bool = true, includeFine: Bool = true) -> WireHistory {
        var wire = WireHistory()
        wire.started = started
        wire.interval = interval
        var tiers: [WireHistory.Tier] = []
        for tier in includeFine ? [fine, medium, coarse] : [medium, coarse] {
            var out = WireHistory.Tier(step: tier.step == 0 ? interval : tier.step)
            out.t = tier.points.map(\.t)
            for series in HistorySeries.allCases where tier.points.contains(where: { $0[series] != nil }) {
                let scale = pow(10, Double(series.decimals))
                out[series] = tier.points.map { point in point[series].map { ($0 * scale).rounded() / scale } }
            }
            tiers.append(out)
        }
        wire.tiers = tiers
        if includeProcesses {
            let tables = processTables
            if !tables.isEmpty { wire.processes = tables }
        }
        return wire
    }

    /// The history message as one JSON line's bytes, kept under `maxLength`
    /// by leaving out the process tables, then the finest tier, if it must.
    func encoded(maxLength: Int = 1 << 20 - 1) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        for (processes, fine) in [(true, true), (false, true), (false, false)] {
            if let data = try? encoder.encode(wire(includeProcesses: processes, includeFine: fine)),
               data.count <= maxLength {
                return data
            }
        }
        return Data(#"{"type":"history"}"#.utf8)
    }

    /// Restores rings an agent saved, dropping what has aged out since or
    /// lies in the future. `started` keeps its own value.
    mutating func load(_ wire: WireHistory, now: Date = Date()) {
        let nowMS = Int64(now.timeIntervalSince1970 * 1000)
        for tier in wire.tiers ?? [] {
            guard let step = tier.step else { continue }
            let points = tier.points.filter { $0.t <= nowMS }
            switch step {
            case Self.mediumStep: medium.merge(points, now: nowMS, prune: false)
            case Self.coarseStep: coarse.merge(points, now: nowMS, prune: false)
            case 0.1...10: fine.merge(points, now: nowMS, prune: false)
            default: continue
            }
        }
        // The windows that were open when the rings were saved are in no
        // coarser tier yet, only in the finest. Fold its points after each
        // tier's last point into that tier's window again (not into the
        // finest tier, which has them), so the window that spans a restart
        // of serve ends with the same point as if it had kept running, and
        // the app's own open windows match the record it merged. This goes
        // by the rings before anything ages out: a window that closed while
        // serve was down still gets all of its points.
        let saved = fine.points
        let lastMedium = medium.points.last?.t ?? .min
        let lastCoarse = coarse.points.last?.t ?? .min
        fine.prune(now: nowMS)
        medium.prune(now: nowMS)
        coarse.prune(now: nowMS)
        mediumBucket = Bucket()
        coarseBucket = Bucket()
        for point in saved where point.t > lastMedium { Self.fold(point, into: &medium, bucket: &mediumBucket) }
        for point in saved where point.t > lastCoarse { Self.fold(point, into: &coarse, bucket: &coarseBucket) }
        medium.prune(now: nowMS)
        coarse.prune(now: nowMS)
        let cut = nowMS - Int64(Self.processSpan * 1000)
        var tables = (wire.processes ?? []).filter { ($0.sampledAt ?? 0) > cut && ($0.sampledAt ?? 0) <= nowMS }
        tables.sort { ($0.sampledAt ?? 0) < ($1.sampledAt ?? 0) }
        if let last = tables.popLast() {
            processes = tables
            processBest = last
            processScore = Self.score(last.rows ?? [])
            processEnd = Self.bucketEnd(last.sampledAt ?? 0, step: Self.processStep)
        }
    }

    /// Takes in what an agent kept: its points replace this side's over the
    /// time they cover, and its process tables replace these.
    mutating func merge(_ wire: WireHistory, now: Date = Date()) {
        load(wire, now: now)
        let nowMS = Int64(now.timeIntervalSince1970 * 1000)
        let cut = nowMS - Int64(Self.processSpan * 1000)
        processes = (wire.processes ?? [])
            .filter { ($0.sampledAt ?? 0) > cut && ($0.sampledAt ?? 0) <= nowMS }
            .sorted { ($0.sampledAt ?? 0) < ($1.sampledAt ?? 0) }
        processBest = nil
        processEnd = 0
    }

    /// One point per window: the mean of each value over the fine points
    /// in it, and the highest CPU among them as the peak.
    private struct Bucket: Sendable {
        var end: Int64 = 0
        var sum = Array(repeating: 0.0, count: HistorySeries.allCases.count)
        var count = Array(repeating: 0, count: HistorySeries.allCases.count)
        var peak: Double?

        mutating func add(_ point: HistoryPoint) {
            for series in HistorySeries.allCases where series != .cpuPeak {
                if let value = point[series] {
                    sum[series.rawValue] += value
                    count[series.rawValue] += 1
                }
            }
            if let cpu = point[.cpu] { peak = max(peak ?? cpu, cpu) }
        }

        var point: HistoryPoint {
            var point = HistoryPoint(t: end)
            for series in HistorySeries.allCases where count[series.rawValue] > 0 {
                point[series] = sum[series.rawValue] / Double(count[series.rawValue])
            }
            point[.cpuPeak] = peak
            return point
        }
    }
}
