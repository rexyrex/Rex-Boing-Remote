import SwiftUI
import Charts
import RexBoingKit

/// What the server did over the last 15 minutes, 4 hours or 48 hours: from
/// the samples this app saw, and, where the server keeps history in the
/// background, for the time this Mac was asleep or away as well. Pointing at
/// a moment shows the readings then and the busiest processes of that
/// quarter hour.
struct HistoryCard: View {
    @ObservedObject var connection: ServerConnection
    var unit: TemperatureUnit
    var keepsHistory: Bool
    var isWindows: Bool
    var openSettings: () -> Void

    @AppStorage("historyRange", store: HistoryCard.defaults) private var range: HistoryRange = .hours4

    /// Demo mode keeps its preferences apart from the real ones.
    private static let defaults: UserDefaults? = Demo.isActive ? UserDefaults(suiteName: Demo.defaultsSuite) : nil
    @StateObject private var hover = HistoryHover()

    enum HistoryRange: String, CaseIterable, Identifiable {
        case minutes15, hours4, hours48

        var id: String { rawValue }

        var label: String {
            switch self {
            case .minutes15: return "15 min"
            case .hours4: return "4 hours"
            case .hours48: return "48 hours"
            }
        }

        var seconds: TimeInterval {
            switch self {
            case .minutes15: return HistoryRings.fineSpan
            case .hours4: return HistoryRings.mediumSpan
            case .hours48: return HistoryRings.coarseSpan
            }
        }
    }

    var body: some View {
        let series = HistorySeriesSet(rings: connection.rings, range: range, now: Date())
        Card(accent: Palette.cpu, title: "History", symbol: "clock.arrow.circlepath") {
            Picker("Period", selection: $range) {
                ForEach(HistoryRange.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .controlSize(.small)

            if series.points.count < 2 {
                Text("Nothing recorded for this period yet.")
                    .font(.system(size: 10.5))
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 60)
            } else {
                HistoryCharts(series: series, unit: unit, hover: hover)
                    .equatable()
                HistoryReadout(hover: hover, series: series, connection: connection, unit: unit)
            }
            footer
        }
    }

    @ViewBuilder private var footer: some View {
        switch connection.background {
        case .running(let since):
            Label("The server has kept this since \(Self.moment(since)), including while this Mac was away.",
                  systemImage: "checkmark.circle")
                .font(.system(size: 9.5))
                .foregroundStyle(.tertiary)
        case .absent:
            HStack(alignment: .firstTextBaseline, spacing: 4) {
                Text(keepsHistory
                     ? (isWindows ? "The server's background agent isn't running; on Windows it runs while someone is signed in."
                                  : "The server's background agent isn't running right now.")
                     : "Recorded while this Mac was connected. The server can keep history while it is away, too.")
                    .fixedSize(horizontal: false, vertical: true)
                if !keepsHistory {
                    Button("Settings…", action: openSettings)
                        .buttonStyle(.link)
                }
            }
            .font(.system(size: 9.5))
            .foregroundStyle(.tertiary)
        case .unknown:
            EmptyView()
        }
    }
}

extension HistoryCard {
    /// "10:39 AM" today, "Oct 16, 10:39 AM" before.
    static func moment(_ date: Date) -> String {
        Calendar.current.isDateInToday(date)
            ? date.formatted(date: .omitted, time: .shortened)
            : date.formatted(.dateTime.month(.abbreviated).day().hour().minute())
    }
}

/// The pointer's place in time, shared by the graphs without making them
/// redraw as it moves: only the rule and the readout observe it.
@MainActor
final class HistoryHover: ObservableObject {
    @Published var date: Date?
}

/// The points one period shows, and how to draw them.
struct HistorySeriesSet: Equatable {
    var points: [HistoryPoint]
    var start: Date
    var end: Date
    /// Seconds between points; a longer gap is drawn as a gap.
    var gap: TimeInterval
    var range: HistoryCard.HistoryRange

    init(rings: HistoryRings, range: HistoryCard.HistoryRange, now: Date) {
        let tier: HistoryTier
        switch range {
        case .minutes15: tier = rings.fine
        case .hours4: tier = rings.medium
        case .hours48: tier = rings.coarse
        }
        let start = now.addingTimeInterval(-range.seconds)
        let startMS = Int64(start.timeIntervalSince1970 * 1000)
        points = tier.points.filter { $0.t >= startMS }
        self.start = start
        end = now
        self.range = range
        gap = tier.step > 0 ? tier.step * 2.5 : max(10, rings.interval * 4)
    }

    /// Only a new point, or another period, is worth redrawing for.
    static func == (lhs: HistorySeriesSet, rhs: HistorySeriesSet) -> Bool {
        lhs.range == rhs.range && lhs.points.count == rhs.points.count
            && lhs.points.first?.t == rhs.points.first?.t && lhs.points.last?.t == rhs.points.last?.t
    }

    func has(_ series: HistorySeries) -> Bool { points.contains { $0[series] != nil } }

    /// Runs of points without a gap, so a line never bridges the hours the
    /// server was off.
    var segments: [Int] {
        var segment = 0
        var previous: Int64?
        return points.map { point in
            if let previous, Double(point.t - previous) / 1000 > gap { segment += 1 }
            previous = point.t
            return segment
        }
    }

    func nearest(to date: Date) -> HistoryPoint? {
        let ms = Int64(date.timeIntervalSince1970 * 1000)
        guard let point = points.min(by: { abs($0.t - ms) < abs($1.t - ms) }),
              Double(abs(point.t - ms)) / 1000 <= gap else { return nil }
        return point
    }
}

private struct HistoryCharts: View, Equatable {
    var series: HistorySeriesSet
    var unit: TemperatureUnit
    var hover: HistoryHover

    static func == (lhs: HistoryCharts, rhs: HistoryCharts) -> Bool {
        lhs.series == rhs.series && lhs.unit == rhs.unit
    }

    var body: some View {
        let segments = series.segments
        let rows = rowList
        VStack(alignment: .leading, spacing: 6) {
            ForEach(rows.indices, id: \.self) { index in
                let row = rows[index]
                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 8) {
                        ForEach(row.lines.indices, id: \.self) { line in
                            HStack(spacing: 3) {
                                Capsule()
                                    .fill(row.lines[line].color.opacity(row.lines[line].faint ? 0.45 : 1))
                                    .frame(width: 8, height: 3)
                                Text(row.lines[line].name)
                            }
                        }
                    }
                    .font(.system(size: 9))
                    .foregroundStyle(.secondary)
                    chart(row, segments: segments, showsTime: index == rows.count - 1)
                        .frame(height: index == rows.count - 1 ? 58 : 42)
                }
            }
        }
    }

    static let axisWidth: CGFloat = 40

    struct Line {
        var name: String
        var series: HistorySeries
        var color: Color
        var filled = false
        var faint = false
    }

    struct Row {
        var lines: [Line]
        /// Fixed range for fractions; nil scales to the data.
        var domain: ClosedRange<Double>?
        /// Whether a scale fitted to the data starts at zero. Temperatures
        /// do not: from 0° every reading looks the same.
        var includesZero = true
        var transform: (Double) -> Double = { $0 }
        var label: (Double) -> String
    }

    private var rowList: [Row] {
        var rows: [Row] = []
        var load = [Line(name: "CPU", series: .cpu, color: Palette.cpu, filled: true)]
        if series.has(.cpuPeak) { load.append(Line(name: "CPU peak", series: .cpuPeak, color: Palette.cpu, faint: true)) }
        load.append(Line(name: "Memory", series: .memory, color: Palette.memory))
        if series.has(.gpu) { load.append(Line(name: "GPU", series: .gpu, color: Palette.gpu)) }
        rows.append(Row(lines: load.filter { series.has($0.series) }, domain: 0...1,
                        label: { Format.percent($0) }))

        let temperatures = [Line(name: "CPU °", series: .cpuCelsius, color: Palette.thermal),
                            Line(name: "GPU °", series: .gpuCelsius, color: Palette.gpu)].filter { series.has($0.series) }
        if !temperatures.isEmpty {
            let unit = self.unit
            rows.append(Row(lines: temperatures, domain: nil, includesZero: false,
                            transform: { Format.temperatureValue($0, unit: unit) },
                            label: { String(format: "%.0f°", $0) }))
        }
        if series.has(.watts) {
            rows.append(Row(lines: [Line(name: "Power", series: .watts, color: Palette.power, filled: true)], domain: nil,
                            label: { Format.watts($0) }))
        }
        let network = [Line(name: "Received", series: .rx, color: Palette.network, filled: true),
                       Line(name: "Sent", series: .tx, color: Palette.network.opacity(0.55))].filter { series.has($0.series) }
        if !network.isEmpty {
            rows.append(Row(lines: network, domain: nil, label: { Format.compactRate($0) }))
        }
        let disk = [Line(name: "Read", series: .read, color: Palette.disk, filled: true),
                    Line(name: "Written", series: .write, color: Palette.disk.opacity(0.55))].filter { series.has($0.series) }
        if !disk.isEmpty {
            rows.append(Row(lines: disk, domain: nil, label: { Format.compactRate($0) }))
        }
        return rows.filter { !$0.lines.isEmpty }
    }

    private func chart(_ row: Row, segments: [Int], showsTime: Bool) -> some View {
        let points = series.points
        return Chart {
            ForEach(row.lines.indices, id: \.self) { line in
                let spec = row.lines[line]
                ForEach(points.indices, id: \.self) { index in
                    if let raw = points[index][spec.series] {
                        let value = row.transform(raw)
                        let date = points[index].date
                        let key = "\(spec.name) \(segments[index])"
                        if spec.filled {
                            AreaMark(x: .value("Time", date), y: .value(spec.name, value), series: .value("Series", key))
                                .foregroundStyle(spec.color.opacity(0.22))
                                .interpolationMethod(.monotone)
                        }
                        LineMark(x: .value("Time", date), y: .value(spec.name, value), series: .value("Series", key))
                            .foregroundStyle(spec.faint ? spec.color.opacity(0.45) : spec.color)
                            .lineStyle(StrokeStyle(lineWidth: spec.faint ? 0.8 : 1.3, dash: spec.faint ? [2, 2] : []))
                            .interpolationMethod(.monotone)
                    }
                }
            }
        }
        .chartXScale(domain: series.start...series.end)
        .modifier(YScale(domain: row.domain, includesZero: row.includesZero))
        .chartLegend(.hidden)
        .chartYAxis {
            AxisMarks(position: .trailing, values: .automatic(desiredCount: 2)) { value in
                AxisGridLine().foregroundStyle(Color.primary.opacity(0.06))
                AxisValueLabel {
                    if let number = value.as(Double.self) {
                        // One width for every graph, so their plots, and the
                        // line under the pointer, line up.
                        Text(row.label(number)).font(.system(size: 8.5)).foregroundStyle(.tertiary)
                            .lineLimit(1)
                            .frame(width: HistoryCharts.axisWidth, alignment: .leading)
                    }
                }
            }
        }
        .chartXAxis {
            if showsTime {
                AxisMarks(values: .automatic(desiredCount: 5)) { value in
                    AxisGridLine().foregroundStyle(Color.primary.opacity(0.06))
                    AxisValueLabel(format: series.range == .hours48
                                   ? .dateTime.weekday(.abbreviated).hour()
                                   : .dateTime.hour().minute())
                        .font(.system(size: 8.5))
                }
            } else {
                AxisMarks(values: .automatic(desiredCount: 5)) { _ in
                    AxisGridLine().foregroundStyle(Color.primary.opacity(0.06))
                }
            }
        }
        .chartOverlay { proxy in
            GeometryReader { geometry in
                ZStack(alignment: .topLeading) {
                    HoverRule(hover: hover, proxy: proxy, geometry: geometry)
                    Rectangle().fill(.clear).contentShape(Rectangle())
                        .onContinuousHover { phase in
                            switch phase {
                            case .active(let location):
                                guard let frame = proxy.plotFrame else { return }
                                let plot = geometry[frame]
                                let x = location.x - plot.origin.x
                                // Over the axis labels is not over a moment.
                                hover.date = (0...plot.width).contains(x) ? proxy.value(atX: x, as: Date.self) : nil
                            case .ended:
                                hover.date = nil
                            }
                        }
                }
            }
        }
    }
}

private struct YScale: ViewModifier {
    var domain: ClosedRange<Double>?
    var includesZero: Bool

    func body(content: Content) -> some View {
        if let domain {
            content.chartYScale(domain: domain)
        } else {
            content.chartYScale(domain: .automatic(includesZero: includesZero))
        }
    }
}

/// The vertical line under the pointer, in every graph at once.
private struct HoverRule: View {
    @ObservedObject var hover: HistoryHover
    var proxy: ChartProxy
    var geometry: GeometryProxy

    var body: some View {
        if let date = hover.date, let frame = proxy.plotFrame, let x = proxy.position(forX: date) {
            let plot = geometry[frame]
            Rectangle()
                .fill(Color.primary.opacity(0.35))
                .frame(width: 1, height: plot.height)
                .offset(x: plot.origin.x + x, y: plot.origin.y)
                .allowsHitTesting(false)
        }
    }
}

/// The readings at the pointer and the busiest processes of that quarter
/// hour; with the pointer away, the period's peaks.
private struct HistoryReadout: View {
    @ObservedObject var hover: HistoryHover
    var series: HistorySeriesSet
    var connection: ServerConnection
    var unit: TemperatureUnit

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let date = hover.date, let point = series.nearest(to: date) {
                Text(headline(point))
                    .font(.system(size: 10, weight: .medium))
                    .monospacedDigit()
                processes(at: point.date)
            } else {
                Text(summary)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
        }
        .frame(maxWidth: .infinity, minHeight: 30, alignment: .topLeading)
    }

    private func headline(_ point: HistoryPoint) -> String {
        var parts = [point.date.formatted(date: series.range == .hours48 ? .abbreviated : .omitted, time: .shortened)]
        if let cpu = point[.cpu] {
            var text = "CPU \(Format.percent(cpu))"
            if let peak = point[.cpuPeak], peak > cpu + 0.05 { text += " (peak \(Format.percent(peak)))" }
            parts.append(text)
        }
        if let memory = point[.memory] { parts.append("memory \(Format.percent(memory))") }
        if let celsius = point[.cpuCelsius] { parts.append(Format.temperature(celsius, unit: unit)) }
        if let watts = point[.watts] { parts.append(Format.watts(watts)) }
        return parts.joined(separator: " · ")
    }

    @ViewBuilder
    private func processes(at date: Date) -> some View {
        if let table = table(near: date) {
            let rows = table.rows.prefix(3)
            HStack(spacing: 10) {
                ForEach(Array(rows), id: \.pid) { row in
                    HStack(spacing: 3) {
                        Text(row.name).lineLimit(1).truncationMode(.middle)
                        Text(String(format: "%.0f%%", row.cpuPercent)).foregroundStyle(Palette.cpu)
                    }
                    .help(row.commandLine ?? row.name)
                }
            }
            .font(.system(size: 9.5))
            .monospacedDigit()
            Text(table.live ? "Processes then"
                 : "The busiest moment of that quarter hour, \(table.timestamp.formatted(date: .omitted, time: .shortened))")
                .font(.system(size: 8.5))
                .foregroundStyle(.tertiary)
        } else {
            Text("No process table kept for this moment.")
                .font(.system(size: 9.5))
                .foregroundStyle(.tertiary)
        }
    }

    private struct Table {
        var timestamp: Date
        var live: Bool
        var rows: [ProcessRow]
    }

    /// A table the open dashboard took within seconds of that moment, or
    /// else the background agent's table for its quarter hour.
    private func table(near date: Date) -> Table? {
        if let found = connection.processHistory.nearest(to: date), abs(found.offset) <= 10, !found.sample.rows.isEmpty {
            return Table(timestamp: found.sample.timestamp, live: true,
                         rows: found.sample.rows.sorted { $0.cpuPercent > $1.cpuPercent })
        }
        let quarter = HistoryRings.bucketEnd(Int64(date.timeIntervalSince1970 * 1000), step: HistoryRings.processStep)
        let found = connection.awayProcesses.samples.last {
            HistoryRings.bucketEnd(Int64($0.timestamp.timeIntervalSince1970 * 1000), step: HistoryRings.processStep) == quarter
        }
        guard let found, !found.rows.isEmpty else { return nil }
        return Table(timestamp: found.timestamp, live: false, rows: found.rows.sorted { $0.cpuPercent > $1.cpuPercent })
    }

    private var summary: String {
        let cpu = series.points.compactMap { point in (point[.cpuPeak] ?? point[.cpu]).map { ($0, point.date) } }
        guard let peak = cpu.max(by: { $0.0 < $1.0 }) else { return "Point at the graphs to see a moment." }
        var text = "Busiest: CPU \(Format.percent(peak.0)) at \(peak.1.formatted(date: series.range == .hours48 ? .abbreviated : .omitted, time: .shortened))"
        if let hottest = series.points.compactMap({ $0[.cpuCelsius] }).max() {
            text += " · hottest \(Format.temperature(hottest, unit: unit))"
        }
        return text + ". Point at the graphs for the busiest processes."
    }
}
