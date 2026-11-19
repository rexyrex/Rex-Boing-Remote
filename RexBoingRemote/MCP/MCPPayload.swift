import Foundation
import RexBoingKit

/// Everything the tools read about one server, copied off its connection at
/// the moment of a call. Plain values, so the payloads can be built and
/// checked without a connection behind them.
struct MCPServerView {
    var server: Server
    var state: ServerConnection.State
    var downSince: Date?
    /// Why the last attempt failed, while it is down.
    var lastFailure: String?
    var hello: WireHello?
    var notices: [String: String] = [:]
    /// The last sample as the agent sent it, and the last one with full
    /// detail, carrying the newest sensors, filesystems, interfaces and
    /// process table, with when each came (milliseconds).
    var latest: WireSample?
    var latestFull: WireSample?
    var detailTimes: [String: Int64] = [:]
    var background: ServerConnection.Background = .unknown
    var rings = HistoryRings(interval: 2)
    /// The process tables the app took itself, while something watched in
    /// full detail.
    var appTables: [ProcessSample] = []
}

/// The tools' answers, built from the samples as the agents sent them rather
/// than from the dashboard's `Snapshot`, whose missing readings are zeros:
/// here a reading a server did not report is left out.
enum MCPPayload {
    // MARK: - The server, and whether it is answering

    static func summary(_ view: MCPServerView, now: Date) -> JSONObject {
        var out = JSONObject()
        out.put("id", view.server.id.uuidString)
        out.put("name", view.server.name)
        out.put("address", view.server.destinationLabel)
        out.put("login", view.server.auth == .appKey ? "the app's key, restricted to the agent" : "the user's own SSH setup")
        switch view.state {
        case .live:
            out.put("state", "live")
        case .connecting where view.downSince != nil:
            // Down, with a retry under way right now.
            out.put("state", "down")
            out.put("reason", view.lastFailure)
            out.put("retrying", true)
        case .connecting:
            out.put("state", "connecting")
        case .idle:
            out.put("state", "paused")
            out.put("reason", "Not connected right now: the Mac is asleep or has just woken.")
        case .waiting(let until, let reason):
            out.put("state", "down")
            out.put("reason", reason)
            out.put("nextRetryAt", until)
        case .attention(let issue):
            out.put("state", "down")
            out.put("needsAttention", true)
            out.put("reason", issue.title + ". " + issue.explanation(for: view.server))
        }
        out.put("downSince", view.downSince)
        return out
    }

    /// A plain sentence for a server that is not live, saying what the
    /// readings that follow are.
    static func note(_ view: MCPServerView, now: Date, what: String = "These are its last readings") -> String? {
        let name = view.server.name
        var text: String
        switch view.state {
        case .live:
            return nil
        case .connecting where view.downSince != nil:
            text = "\(name) isn't answering" + (view.lastFailure.map { ": \($0)" } ?? ".") + " A new try is under way."
        case .connecting:
            text = "\(name) is connecting."
        case .idle:
            text = "\(name) isn't connected right now; the Mac is asleep or has just woken."
        case .waiting(let until, let reason):
            text = "\(name) isn't answering: \(reason) The next try is at \(MCPTime.format(until))."
        case .attention(let issue):
            text = "\(name) is stopped until the user acts: \(issue.title). \(issue.explanation(for: view.server))"
        }
        if let t = view.latest?.t {
            text += " \(what), from \(MCPTime.format(ms: t)) (\(age(ms: t, now: now)) seconds ago)."
        } else {
            text += " Nothing has been read from it since Rex Boing Remote started."
        }
        return text
    }

    static func age(ms: Int64, now: Date) -> Int {
        max(0, Int((now.timeIntervalSince1970 - Double(ms) / 1000).rounded()))
    }

    private static func putTime(_ out: inout JSONObject, ms: Int64?, now: Date, key: String = "sampledAt") {
        guard let ms, ms > 0 else { return }
        out.put(key, MCPTime.format(ms: ms))
        if key == "sampledAt" { out.put("ageSeconds", age(ms: ms, now: now)) }
    }

    // MARK: - list_servers

    static func listServers(_ views: [MCPServerView], limit: Int, now: Date) -> JSONValue {
        let shown = views.prefix(limit).map { serverItem($0, now: now).value }
        var out = JSONObject()
        out.put("servers", array: Array(shown))
        out.put("total", views.count)
        out.put("truncated", views.count > shown.count)
        out.put("live", views.filter { $0.state == .live }.count)
        out.put("now", now)
        return out.value
    }

    static func serverItem(_ view: MCPServerView, now: Date) -> JSONObject {
        var out = summary(view, now: now)
        let host = view.hello?.host
        out.put("os", view.hello?.agent?.os ?? view.server.os)
        out.put("arch", view.hello?.agent?.arch ?? view.server.arch)
        out.put("operatingSystem", [host?.osName, host?.osVersion].compactMap { $0 }.joined(separator: " "))
        out.put("hostname", host?.hostname)
        out.put("model", host?.modelName)
        out.put("chip", host?.chipName)
        out.put("agentVersion", view.hello?.agent?.version ?? view.server.agentVersion)
        if let sample = view.latest {
            out.put("vitals", object: vitals(sample, now: now))
        }
        // The system section may come only with some samples; the newest one
        // held is what the dashboard shows.
        if let system = view.latest?.system ?? view.latestFull?.system {
            out.put("system", object: systemAlerts(system))
        }
        if !view.notices.isEmpty { out.put("notices", array: notices(view.notices)) }
        out.put("backgroundHistory", object: background(view))
        return out
    }

    /// The fleet list's figures, and the rest of a vitals sample.
    static func vitals(_ sample: WireSample, now: Date) -> JSONObject {
        var out = JSONObject()
        putTime(&out, ms: sample.t, now: now)
        out.putPercent("cpuPercent", fraction: sample.cpu?.total)
        if let memory = sample.memory {
            if let total = memory.total, total > 0, let used = memory.used {
                out.putPercent("memoryPercent", fraction: Double(used) / Double(total))
            }
            out.put("memoryUsedBytes", memory.used)
            out.put("memoryTotalBytes", memory.total)
            out.put("memoryPressureLevel", memory.pressureLevel)
            if let swap = memory.swap, let total = swap.total, total > 0, let used = swap.used {
                out.putPercent("swapPercent", fraction: Double(used) / Double(total))
            }
        }
        out.putPercent("gpuPercent", fraction: sample.gpus?.first?.utilization)
        out.put("cpuCelsius", sample.thermal?.cpuCelsius ?? sample.thermal?.socCelsius, decimals: 1)
        out.put("gpuCelsius", sample.thermal?.gpuCelsius ?? sample.gpus?.first?.celsius, decimals: 1)
        out.put("peakCelsius", sample.thermal?.peakCelsius, decimals: 1)
        out.put("powerWatts", totalWatts(sample.power), decimals: 2)
        out.put("gpuWatts", sample.power?.gpuWatts ?? sample.gpus?.first?.watts, decimals: 2)
        out.put("networkReceivedBytesPerSecond", sample.network?.rx, decimals: 0)
        out.put("networkSentBytesPerSecond", sample.network?.tx, decimals: 0)
        out.put("diskReadBytesPerSecond", sample.disk?.read, decimals: 0)
        out.put("diskWriteBytesPerSecond", sample.disk?.write, decimals: 0)
        if sample.battery?.present == true {
            out.putPercent("batteryPercent", fraction: sample.battery?.percentage)
        }
        out.put("uptimeSeconds", sample.system?.uptime, decimals: 0)
        out.put("detail", sample.detail)
        return out
    }

    /// Whole-machine power in the order the dashboard prefers it.
    static func totalWatts(_ power: WirePower?) -> Double? {
        power?.systemTotalWatts ?? power?.systemWatts ?? power?.packageWatts
    }

    private static func systemAlerts(_ system: WireSystem) -> JSONObject {
        var out = JSONObject()
        out.put("rebootRequired", system.rebootRequired)
        out.put("rebootReason", system.rebootReason)
        if let failed = system.failedServices { out.put("failedServices", array: failed.prefix(20).map(JSONValue.string)) }
        out.put("updates", system.updates)
        out.put("securityUpdates", system.securityUpdates)
        return out
    }

    private static func notices(_ notices: [String: String]) -> [JSONValue] {
        notices.sorted { $0.key < $1.key }.map { ["code": .string($0.key), "message": .string($0.value)] }
    }

    private static func background(_ view: MCPServerView) -> JSONObject {
        var out = JSONObject()
        var running: Bool?
        switch view.background {
        case .running(let since):
            running = true
            out.put("since", since)
        case .absent:
            running = false
        case .unknown:
            break
        }
        let enabled = view.server.keepHistory ?? running
        out.put("enabled", enabled)
        out.put("running", running)
        if enabled == true {
            out.put("keptOnServerDays", view.server.historyDays ?? HistoryRings.defaultKeepDays)
        }
        return out
    }

    // MARK: - get_server_snapshot

    static func snapshot(_ view: MCPServerView, sections: [MCPSnapshotSection], limit: Int, now: Date, waited: String? = nil) -> JSONValue {
        var out = JSONObject()
        out.put("server", object: summary(view, now: now))
        let latest = view.latest
        let full = view.latestFull
        putTime(&out, ms: latest?.t, now: now)
        out.put("detail", latest?.detail)
        // The lists only full detail has may come with some samples and not
        // others, so each is the newest held and says when it came.
        func detailList<T>(_ fresh: T?, _ older: T?) -> T? { fresh ?? older }
        func listTime(_ name: String, _ object: inout JSONObject) {
            guard object[name] != nil, let t = view.detailTimes[name] ?? full?.t ?? latest?.t else { return }
            object.put(name + "SampledAt", MCPTime.format(ms: t))
        }

        for section in sections {
            switch section {
            case .host:
                if let hello = view.hello { out.put("host", object: host(hello)) }
            case .cpu:
                if let cpu = latest?.cpu ?? full?.cpu { out.put("cpu", object: cpuSection(cpu)) }
            case .gpus:
                if let gpus = latest?.gpus ?? full?.gpus {
                    out.put("gpus", array: gpus.prefix(limit).map { gpu($0).value })
                    out.put("gpusTotal", gpus.count)
                    out.put("gpusTruncated", gpus.count > limit)
                }
            case .memory:
                if let memory = latest?.memory ?? full?.memory { out.put("memory", object: memorySection(memory)) }
            case .thermal:
                let headline = latest?.thermal ?? full?.thermal
                let sensors = detailList(latest?.thermal?.sensors, full?.thermal?.sensors)
                let fans = detailList(latest?.thermal?.fans, full?.thermal?.fans)
                if headline != nil || sensors != nil || fans != nil {
                    var object = thermal(headline, sensors: sensors, fans: fans, limit: limit)
                    listTime("sensors", &object)
                    listTime("fans", &object)
                    out.put("thermal", object: object)
                }
            case .power:
                if let power = latest?.power ?? full?.power { out.put("power", object: powerSection(power)) }
            case .pressure:
                if let pressure = latest?.pressure ?? full?.pressure { out.put("pressure", object: pressureSection(pressure)) }
            case .network:
                let headline = latest?.network ?? full?.network
                let interfaces = detailList(latest?.network?.interfaces, full?.network?.interfaces)
                if headline != nil || interfaces != nil {
                    var object = network(headline, interfaces: interfaces, limit: limit)
                    listTime("interfaces", &object)
                    out.put("network", object: object)
                }
            case .disk:
                let headline = latest?.disk ?? full?.disk
                let volumes = detailList(latest?.disk?.volumes, full?.disk?.volumes)
                if headline != nil || volumes != nil {
                    var object = disk(headline, volumes: volumes, limit: limit)
                    listTime("volumes", &object)
                    out.put("disk", object: object)
                }
            case .battery:
                if let battery = latest?.battery ?? full?.battery, battery.present != false {
                    out.put("battery", object: batterySection(battery))
                }
            case .system:
                let system = latest?.system ?? full?.system
                var object = system.map { systemSection($0, limit: limit) } ?? JSONObject()
                if let boot = view.hello?.host?.bootTime, boot > 0 { object.put("bootedAt", MCPTime.format(ms: boot)) }
                out.put("system", object: object)
            case .notices:
                out.put("notices", array: notices(view.notices))
            }
        }
        var notes = [note(view, now: now)].compactMap { $0 }
        if let waited { notes.append(waited) }
        if !notes.isEmpty { out.put("note", notes.joined(separator: " ")) }
        return out.value
    }

    static func host(_ hello: WireHello) -> JSONObject {
        var out = JSONObject()
        if let host = hello.host {
            out.put("hostname", host.hostname)
            out.put("model", host.modelName)
            out.put("modelIdentifier", host.modelIdentifier)
            out.put("vendor", host.vendor)
            out.put("chip", host.chipName)
            out.put("osName", host.osName)
            out.put("osVersion", host.osVersion)
            out.put("kernel", host.kernel)
            out.put("physicalCores", host.physicalCores)
            out.put("logicalCores", host.logicalCores)
            out.put("performanceCores", host.performanceCores)
            out.put("efficiencyCores", host.efficiencyCores)
            out.put("memoryBytes", host.memoryBytes)
            if let boot = host.bootTime, boot > 0 { out.put("bootedAt", MCPTime.format(ms: boot)) }
            out.put("virtualization", host.virtualization)
            out.put("appleSilicon", host.isAppleSilicon)
        }
        if let agent = hello.agent {
            var object = JSONObject()
            object.put("name", agent.name)
            object.put("version", agent.version)
            object.put("os", agent.os)
            object.put("arch", agent.arch)
            out.put("agent", object: object)
        }
        out.put("protocol", hello.protocol)
        return out
    }

    static func cpuSection(_ cpu: WireCPU) -> JSONObject {
        var out = JSONObject()
        out.putPercent("totalPercent", fraction: cpu.total)
        out.putPercent("userPercent", fraction: cpu.user)
        out.putPercent("systemPercent", fraction: cpu.system)
        out.putPercent("nicePercent", fraction: cpu.nice)
        out.putPercent("iowaitPercent", fraction: cpu.iowait)
        out.putPercent("stealPercent", fraction: cpu.steal)
        out.putPercent("idlePercent", fraction: cpu.idle)
        if let cores = cpu.perCore {
            // One entry per logical core, in order: a core whose reading is
            // not a number is null, so the others keep their places.
            out.put("perCorePercent", array: cores.prefix(1024).map { $0.isFinite ? .double(JSONObject.round($0 * 100, 1)) : .null })
            if let kinds = cpu.kinds, kinds.count == cores.count, kinds.contains(where: { $0 != "?" }) {
                out.put("coreKinds", kinds)
            }
        }
        out.put("clockMHz", cpu.clockMHz, decimals: 0)
        out.put("performanceClockMHz", cpu.performanceClockMHz, decimals: 0)
        out.put("efficiencyClockMHz", cpu.efficiencyClockMHz, decimals: 0)
        if let load = cpu.load, load.count == 3, load.allSatisfy(\.isFinite) {
            out.put("loadAverage", object: {
                var object = JSONObject()
                object.put("oneMinute", load[0], decimals: 2)
                object.put("fiveMinutes", load[1], decimals: 2)
                object.put("fifteenMinutes", load[2], decimals: 2)
                return object
            }())
        }
        out.put("processes", cpu.processes)
        out.put("threads", cpu.threads)
        out.put("zombies", cpu.zombies)
        return out
    }

    static func gpu(_ gpu: WireGPU) -> JSONObject {
        var out = JSONObject()
        out.put("name", gpu.name)
        out.put("vendor", gpu.vendor)
        out.putPercent("utilizationPercent", fraction: gpu.utilization)
        if let engines = gpu.engines, !engines.isEmpty {
            var object = JSONObject()
            for (name, value) in engines { object.putPercent(name, fraction: value) }
            out.put("enginesPercent", object: object)
        }
        out.put("memoryUsedBytes", gpu.memoryUsed)
        out.put("memoryTotalBytes", gpu.memoryTotal)
        out.put("memoryAllocatedBytes", gpu.memoryAllocated)
        out.put("clockMHz", gpu.clockMHz, decimals: 0)
        out.put("maxClockMHz", gpu.maxClockMHz, decimals: 0)
        out.put("temperatureCelsius", gpu.celsius, decimals: 1)
        out.put("powerWatts", gpu.watts, decimals: 2)
        out.put("fanRPM", gpu.fanRPM, decimals: 0)
        // Already a percent on the wire.
        out.put("fanPercent", gpu.fanPercent, decimals: 1)
        out.put("coreCount", gpu.coreCount)
        return out
    }

    static func memorySection(_ memory: WireMemory) -> JSONObject {
        var out = JSONObject()
        out.put("totalBytes", memory.total)
        out.put("usedBytes", memory.used)
        if let total = memory.total, total > 0, let used = memory.used {
            out.putPercent("usedPercent", fraction: Double(used) / Double(total))
        }
        out.put("availableBytes", memory.available)
        out.put("freeBytes", memory.free)
        out.put("appBytes", memory.app)
        out.put("wiredBytes", memory.wired)
        out.put("compressedBytes", memory.compressed)
        out.put("cachedBytes", memory.cached)
        out.put("buffersBytes", memory.buffers)
        out.put("activeBytes", memory.active)
        out.put("inactiveBytes", memory.inactive)
        out.put("purgeableBytes", memory.purgeable)
        out.putPercent("pressurePercent", fraction: memory.pressure)
        out.put("pressureLevel", memory.pressureLevel)
        if let swap = memory.swap {
            var object = JSONObject()
            object.put("totalBytes", swap.total)
            object.put("usedBytes", swap.used)
            object.put("freeBytes", swap.free)
            if let total = swap.total, total > 0, let used = swap.used {
                object.putPercent("usedPercent", fraction: Double(used) / Double(total))
            }
            object.put("inBytesPerSecond", swap.inRate, decimals: 0)
            object.put("outBytesPerSecond", swap.outRate, decimals: 0)
            object.put("encrypted", swap.encrypted)
            out.put("swap", object: object)
        }
        return out
    }

    static func thermal(_ thermal: WireThermal?, sensors: [WireSensor]?, fans: [WireFan]?, limit: Int) -> JSONObject {
        var out = JSONObject()
        out.put("cpuCelsius", thermal?.cpuCelsius, decimals: 1)
        out.put("gpuCelsius", thermal?.gpuCelsius, decimals: 1)
        out.put("socCelsius", thermal?.socCelsius, decimals: 1)
        out.put("batteryCelsius", thermal?.batteryCelsius, decimals: 1)
        out.put("storageCelsius", thermal?.storageCelsius, decimals: 1)
        out.put("peakCelsius", thermal?.peakCelsius, decimals: 1)
        out.put("state", thermal?.state)
        if let sensors {
            // Hottest first, so a cut list keeps the ones that matter.
            let readable = sensors.filter { $0.celsius?.isFinite == true }.sorted { ($0.celsius ?? 0) > ($1.celsius ?? 0) }
            out.put("sensors", array: readable.prefix(limit).map { sensor in
                var object = JSONObject()
                object.put("key", sensor.key)
                object.put("label", sensor.label)
                object.put("category", sensor.category)
                object.put("temperatureCelsius", sensor.celsius, decimals: 1)
                object.put("highCelsius", sensor.high, decimals: 1)
                object.put("criticalCelsius", sensor.critical, decimals: 1)
                return object.value
            })
            out.put("sensorsTotal", readable.count)
            out.put("sensorsTruncated", readable.count > limit)
        }
        if let fans {
            out.put("fans", array: fans.prefix(limit).map { fan in
                var object = JSONObject()
                object.put("index", fan.index)
                object.put("label", fan.label)
                object.put("speedRPM", fan.rpm, decimals: 0)
                object.put("minRPM", fan.minRPM, decimals: 0)
                object.put("maxRPM", fan.maxRPM, decimals: 0)
                return object.value
            })
            out.put("fansTotal", fans.count)
            out.put("fansTruncated", fans.count > limit)
        }
        return out
    }

    static func powerSection(_ power: WirePower) -> JSONObject {
        var out = JSONObject()
        out.put("totalWatts", totalWatts(power), decimals: 2)
        out.put("cpuWatts", power.cpuWatts, decimals: 2)
        out.put("gpuWatts", power.gpuWatts, decimals: 2)
        out.put("neuralEngineWatts", power.aneWatts, decimals: 2)
        out.put("packageWatts", power.packageWatts, decimals: 2)
        out.put("systemWatts", power.systemWatts, decimals: 2)
        out.put("systemTotalWatts", power.systemTotalWatts, decimals: 2)
        out.put("dcInWatts", power.dcInWatts, decimals: 2)
        out.put("adapterWatts", power.adapterWatts, decimals: 2)
        return out
    }

    static func pressureSection(_ pressure: WirePressure) -> JSONObject {
        var out = JSONObject()
        // Percents already on the wire: the share of the last 10 seconds
        // that some tasks (…Full: all of them) waited.
        out.put("cpuSomePercent", pressure.cpu, decimals: 2)
        out.put("memorySomePercent", pressure.memory, decimals: 2)
        out.put("memoryFullPercent", pressure.memoryFull, decimals: 2)
        out.put("ioSomePercent", pressure.io, decimals: 2)
        out.put("ioFullPercent", pressure.ioFull, decimals: 2)
        if !out.isEmpty { out.put("windowSeconds", 10) }
        return out
    }

    static func network(_ network: WireNetwork?, interfaces: [WireInterface]?, limit: Int) -> JSONObject {
        var out = JSONObject()
        out.put("receivedBytesPerSecond", network?.rx, decimals: 0)
        out.put("sentBytesPerSecond", network?.tx, decimals: 0)
        out.put("sessionReceivedBytes", network?.rxTotal)
        out.put("sessionSentBytes", network?.txTotal)
        out.put("primaryInterface", network?.primaryInterface)
        out.put("localAddress", network?.localAddress)
        if let interfaces {
            out.put("interfaces", array: interfaces.prefix(limit).map { interface in
                var object = JSONObject()
                object.put("name", interface.name)
                object.put("receivedBytesPerSecond", interface.rx, decimals: 0)
                object.put("sentBytesPerSecond", interface.tx, decimals: 0)
                object.put("speedMbps", interface.speedMbps, decimals: 0)
                object.put("up", interface.up)
                return object.value
            })
            out.put("interfacesTotal", interfaces.count)
            out.put("interfacesTruncated", interfaces.count > limit)
        }
        return out
    }

    static func disk(_ disk: WireDisk?, volumes: [WireVolume]?, limit: Int) -> JSONObject {
        var out = JSONObject()
        out.put("readBytesPerSecond", disk?.read, decimals: 0)
        out.put("writeBytesPerSecond", disk?.write, decimals: 0)
        out.put("sessionReadBytes", disk?.readTotal)
        out.put("sessionWrittenBytes", disk?.writeTotal)
        if let volumes {
            func full(_ volume: WireVolume) -> Double? {
                guard let total = volume.total, total > 0, volume.available != nil else { return nil }
                return volume.fractionUsed
            }
            // Fullest first, as the Filesystems card lists them.
            let sorted = volumes.sorted { (full($0) ?? -1) > (full($1) ?? -1) }
            out.put("volumes", array: sorted.prefix(limit).map { volume in
                var object = JSONObject()
                object.put("name", volume.name)
                object.put("mount", volume.mount)
                object.put("fs", volume.fs)
                object.put("totalBytes", volume.total)
                object.put("availableBytes", volume.available)
                object.put("usedBytes", volume.used)
                // Full as df counts it, used out of used plus available.
                object.putPercent("usedPercent", fraction: full(volume))
                return object.value
            })
            out.put("volumesTotal", volumes.count)
            out.put("volumesTruncated", volumes.count > limit)
        }
        return out
    }

    static func batterySection(_ battery: WireBattery) -> JSONObject {
        var out = JSONObject()
        out.put("present", battery.present)
        out.putPercent("chargePercent", fraction: battery.percentage)
        out.put("charging", battery.charging)
        out.put("pluggedIn", battery.pluggedIn)
        out.put("timeRemainingSeconds", battery.timeRemainingMinutes.map { $0 * 60 })
        out.put("cycleCount", battery.cycleCount)
        if let design = battery.designCapacity, design > 0, let maximum = battery.maxCapacity {
            out.putPercent("healthPercent", fraction: Double(maximum) / Double(design))
        }
        out.put("condition", battery.condition)
        out.put("temperatureCelsius", battery.celsius, decimals: 1)
        out.put("systemWatts", battery.systemWatts, decimals: 2)
        out.put("chargingWatts", battery.chargingWatts, decimals: 2)
        out.put("adapterWatts", battery.adapterWatts, decimals: 2)
        return out
    }

    static func systemSection(_ system: WireSystem, limit: Int) -> JSONObject {
        var out = JSONObject()
        out.put("uptimeSeconds", system.uptime, decimals: 0)
        out.put("rebootRequired", system.rebootRequired)
        out.put("rebootReason", system.rebootReason)
        out.put("updates", system.updates)
        out.put("securityUpdates", system.securityUpdates)
        if let failed = system.failedServices {
            out.put("failedServices", array: failed.prefix(limit).map(JSONValue.string))
            out.put("failedServicesTotal", failed.count)
            out.put("failedServicesTruncated", failed.count > limit)
        }
        out.put("containers", system.containers)
        return out
    }

    // MARK: - get_server_processes

    static func processes(_ view: MCPServerView, sortBy: MCPProcessSort, limit: Int, now: Date, waited: String? = nil) -> JSONValue {
        var out = JSONObject()
        out.put("server", object: summary(view, now: now))
        out.put("sortBy", sortBy.rawValue)
        var notes = [note(view, now: now, what: "This is its last process table")].compactMap { $0 }
        if let waited { notes.append(waited) }
        guard let table = view.latestFull?.processes ?? view.latest?.processes else {
            notes.append("No process table is held for \(view.server.name) yet.")
            out.put("processes", array: [])
            out.put("total", 0)
            out.put("truncated", false)
            out.put("note", notes.joined(separator: " "))
            return out.value
        }
        putTime(&out, ms: table.sampledAt, now: now)
        out.put("intervalSeconds", table.interval, decimals: 2)
        out.put("processCount", table.count)
        out.put("gpuAttribution", table.gpuAttribution)
        var byPID: [Int32: WireProcessRow] = [:]
        for row in table.rows ?? [] { if let pid = row.pid { byPID[pid] = row } }
        var seen = Set<Int32>()
        let ranked = (table.rank?[sortBy.rawValue] ?? []).filter { seen.insert($0).inserted }.compactMap { byPID[$0] }
        out.put("processes", array: ranked.prefix(limit).map { processRow($0).value })
        out.put("total", ranked.count)
        out.put("truncated", ranked.count > limit)
        if ranked.isEmpty {
            switch sortBy {
            case .gpu: notes.append("This server's agent doesn't attribute GPU use to processes, or nothing used the GPU.")
            case .disk: notes.append("This server's agent ranked no process by disk use: none read or wrote, or it can't tell.")
            default: notes.append("The agent sent no ranking by \(sortBy.rawValue).")
            }
        }
        if !notes.isEmpty { out.put("note", notes.joined(separator: " ")) }
        return out.value
    }

    static func processRow(_ row: WireProcessRow) -> JSONObject {
        var out = JSONObject()
        out.put("pid", row.pid)
        out.put("name", row.name)
        out.put("user", row.user)
        out.put("command", row.cmd.map { cut($0, to: 300) })
        out.put("cpuPercent", row.cpu, decimals: 1)
        out.put("memoryBytes", row.memory)
        out.put("gpuPercent", row.gpu, decimals: 1)
        out.put("diskReadBytesPerSecond", row.diskRead, decimals: 0)
        out.put("diskWriteBytesPerSecond", row.diskWrite, decimals: 0)
        out.put("energyImpact", row.energy, decimals: 1)
        out.put("wakeupsPerSecond", row.wakeups, decimals: 1)
        out.put("threads", row.threads)
        if let start = row.start, start > 0 {
            out.put("startedAt", Date(timeIntervalSince1970: Double(start) / 1_000_000))
        }
        return out
    }

    static func cut(_ text: String, to characters: Int) -> String {
        text.count > characters ? String(text.prefix(characters - 1)) + "…" : text
    }

    // MARK: - get_server_history

    private struct Tier {
        var points: [HistoryPoint]
        var stepSeconds: Double
        var name: String
        var span: TimeInterval
    }

    static func history(_ view: MCPServerView, from: Date, to: Date, points maxPoints: Int,
                        series wanted: [MCPHistorySeries], now: Date) -> JSONValue {
        let rings = view.rings
        let tiers = [
            Tier(points: rings.fine.points, stepSeconds: rings.interval, name: "samples", span: HistoryRings.fineSpan),
            Tier(points: rings.medium.points, stepSeconds: HistoryRings.mediumStep, name: "30-second means", span: HistoryRings.mediumSpan),
            Tier(points: rings.coarse.points, stepSeconds: HistoryRings.coarseStep, name: "5-minute means", span: rings.coarse.span),
        ]
        let fromMS = Int64(from.timeIntervalSince1970 * 1000)
        let toMS = Int64(to.timeIntervalSince1970 * 1000)
        func inWindow(_ tier: Tier) -> [HistoryPoint] { tier.points.filter { $0.t >= fromMS && $0.t <= toMS } }
        // The finest record whose span reaches back to the window's start,
        // or failing that a coarser one that has something in the window.
        let covering = tiers.firstIndex { now.timeIntervalSince(from) <= $0.span + 60 } ?? tiers.count - 1
        var chosen = covering
        var held = inWindow(tiers[covering])
        if held.isEmpty, let coarser = (covering + 1..<tiers.count).first(where: { !inWindow(tiers[$0]).isEmpty }) {
            chosen = coarser
            held = inWindow(tiers[coarser])
        }
        let tier = tiers[chosen]

        var out = JSONObject()
        out.put("server", object: summary(view, now: now))
        out.put("from", from)
        out.put("to", to)
        out.put("record", object: {
            var object = JSONObject()
            object.put("name", tier.name)
            object.put("stepSeconds", tier.stepSeconds, decimals: 1)
            return object
        }())
        out.put("heldSince", rings.oldest)
        out.put("pointsHeld", held.count)

        // Each bucket: the points it holds. Raw points are buckets of one.
        let downsample = held.count > maxPoints
        var buckets: [(end: Int64, points: [HistoryPoint])] = []
        if downsample, let first = held.first?.t, let last = held.last?.t {
            // Over the time the record covers, not the whole window: an app
            // that has watched for a minute of a requested hour still gives
            // `points` buckets of that minute.
            let start = first - 1
            let width = max(1, (last - start + Int64(maxPoints) - 1) / Int64(maxPoints))
            var grouped: [Int: [HistoryPoint]] = [:]
            for point in held { grouped[min(maxPoints - 1, Int((point.t - start - 1) / width)), default: []].append(point) }
            buckets = grouped.keys.sorted().map { (start + Int64($0 + 1) * width, grouped[$0]!) }
            out.put("bucketSeconds", Double(width) / 1000, decimals: 1)
        } else {
            buckets = held.map { ($0.t, [$0]) }
            out.put("bucketSeconds", tier.stepSeconds, decimals: 1)
        }
        out.put("downsampled", downsample)
        out.put("bucketEnds", array: buckets.map { .string(MCPTime.format(ms: min($0.end, toMS))) })

        var seriesOut = JSONObject()
        var summaryOut = JSONObject()
        for name in wanted {
            let series = name.series
            func values(_ point: HistoryPoint) -> (mean: Double?, high: Double?) {
                let value = point[series]
                // The CPU's peak within a window is its own series.
                let high = series == .cpu ? [point[.cpuPeak], value].compactMap { $0 }.max() : value
                return (value, high)
            }
            guard held.contains(where: { values($0).mean != nil }) else { continue }
            func scaled(_ value: Double?) -> JSONValue {
                guard let value, value.isFinite else { return .null }
                return .double(JSONObject.round(value * name.scale, name.decimals))
            }
            var means: [JSONValue] = [], mins: [JSONValue] = [], maxes: [JSONValue] = []
            for bucket in buckets {
                let readings = bucket.points.compactMap { values($0).mean }
                let highs = bucket.points.compactMap { values($0).high }
                means.append(scaled(readings.isEmpty ? nil : readings.reduce(0, +) / Double(readings.count)))
                mins.append(scaled(readings.min()))
                maxes.append(scaled(highs.max()))
            }
            seriesOut[name.rawValue] = ["mean": .array(means), "min": .array(mins), "max": .array(maxes)]

            let readings = held.compactMap { values($0).mean }
            var whole = JSONObject()
            whole["mean"] = scaled(readings.reduce(0, +) / Double(readings.count))
            whole["min"] = scaled(readings.min())
            if let peak = held.compactMap({ point in values(point).high.map { ($0, point.t) } }).max(by: { $0.0 < $1.0 }) {
                whole["max"] = scaled(peak.0)
                whole.put("maxAt", MCPTime.format(ms: peak.1))
            }
            summaryOut.put(name.rawValue, object: whole)
        }
        out.put("series", object: seriesOut)
        out.put("summary", object: summaryOut)

        var notes: [String] = []
        if let note = note(view, now: now, what: "Its history stops at its last reading") { notes.append(note) }
        if now.timeIntervalSince(from) > HistoryRings.coarseSpan + 60 {
            notes.append("The app holds at most 48 hours. Anything older is only on the server, if it keeps "
                         + "history there (backgroundHistory.keptOnServerDays): read it on the server with "
                         + "`~/.local/share/rex-boing-remote/rex-boing-agent history --from \(Int((now.timeIntervalSince(from) / 86400).rounded(.up)))d`.")
        }
        if held.isEmpty {
            notes.append("Nothing is held for this window: the app records while it is connected, and the server "
                         + "fills in the time the Mac was away only when it keeps history in the background.")
        }
        if !notes.isEmpty { out.put("note", notes.joined(separator: " ")) }
        return out.value
    }

    // MARK: - get_server_process_history

    /// One quarter hour's table, from the server's background agent or from
    /// the app's own full samples.
    struct QuarterTable {
        var quarterEnd: Int64
        var sampledAt: Int64
        var source: String
        var interval: Double?
        var count: Int?
        var rows: [WireProcessRow]
        var score: Double { rows.reduce(0) { $0 + HistoryRings.finite($1.cpu) } }
    }

    static func quarterTables(_ view: MCPServerView) -> [Int64: QuarterTable] {
        var byQuarter: [Int64: QuarterTable] = [:]
        // The app's own tables first, the busiest of each quarter hour…
        for sample in view.appTables {
            let at = Int64(sample.timestamp.timeIntervalSince1970 * 1000)
            let rows = sample.rows.map { row -> WireProcessRow in
                var wire = WireProcessRow()
                wire.pid = row.pid
                wire.name = row.name
                wire.user = row.user
                wire.start = row.startTime > 0 ? row.startTime : nil
                wire.cmd = row.commandLine
                wire.cpu = row.cpuPercent
                wire.memory = row.memoryBytes
                wire.threads = row.threadCount > 0 ? row.threadCount : nil
                return wire
            }
            let quarter = HistoryRings.bucketEnd(at, step: HistoryRings.processStep)
            let table = QuarterTable(quarterEnd: quarter, sampledAt: at, source: "app", interval: sample.interval,
                                     count: sample.processCount > 0 ? sample.processCount : nil, rows: rows)
            if table.score > byQuarter[quarter]?.score ?? -1 { byQuarter[quarter] = table }
        }
        // …then the server's, which saw the whole quarter hour.
        for table in view.rings.processTables {
            guard let at = table.sampledAt, at > 0 else { continue }
            let quarter = HistoryRings.bucketEnd(at, step: HistoryRings.processStep)
            byQuarter[quarter] = QuarterTable(quarterEnd: quarter, sampledAt: at, source: "server",
                                              interval: table.interval, count: table.count, rows: table.rows ?? [])
        }
        return byQuarter
    }

    static func processHistory(_ view: MCPServerView, at: Date?, from: Date, to: Date, limit: Int, rows: Int,
                               sortBy: MCPProcessSort, now: Date) -> JSONValue {
        let tables = quarterTables(view)
        let step = Int64(HistoryRings.processStep * 1000)
        var out = JSONObject()
        out.put("server", object: summary(view, now: now))
        var chosen: [QuarterTable]
        var total: Int
        if let at {
            let quarter = HistoryRings.bucketEnd(Int64(at.timeIntervalSince1970 * 1000), step: HistoryRings.processStep)
            out.put("at", at)
            out.put("quarterHourStart", MCPTime.format(ms: quarter - step))
            out.put("quarterHourEnd", MCPTime.format(ms: quarter))
            chosen = tables[quarter].map { [$0] } ?? []
            total = chosen.count
        } else {
            let fromMS = Int64(from.timeIntervalSince1970 * 1000)
            let toMS = Int64(to.timeIntervalSince1970 * 1000)
            out.put("from", from)
            out.put("to", to)
            let inside = tables.values.filter { $0.quarterEnd > fromMS && $0.quarterEnd - step < toMS }
            total = inside.count
            // The busiest quarter hours when there are more, shown in time order.
            chosen = Array(inside.sorted { $0.score > $1.score }.prefix(limit)).sorted { $0.quarterEnd < $1.quarterEnd }
        }
        out.put("tables", array: chosen.map { table in
            var object = JSONObject()
            object.put("quarterHourStart", MCPTime.format(ms: table.quarterEnd - step))
            object.put("quarterHourEnd", MCPTime.format(ms: table.quarterEnd))
            object.put("source", table.source)
            object.put("sampledAt", MCPTime.format(ms: table.sampledAt))
            object.put("intervalSeconds", table.interval, decimals: 2)
            object.put("processCount", table.count)
            let sorted = table.rows.sorted {
                sortBy == .memory ? ($0.memory ?? 0) > ($1.memory ?? 0) : HistoryRings.finite($0.cpu) > HistoryRings.finite($1.cpu)
            }
            object.put("processes", array: sorted.prefix(rows).map { row in
                var process = processRow(row)
                process["command"] = row.cmd.map { .string(cut($0, to: 200)) }
                return process.value
            })
            object.put("processesTotal", table.rows.count)
            object.put("processesTruncated", table.rows.count > rows)
            return object.value
        })
        out.put("total", total)
        out.put("truncated", total > chosen.count)
        out.put("sortBy", sortBy.rawValue)

        var notes: [String] = []
        if let note = note(view, now: now, what: "Its records stop at its last reading") { notes.append(note) }
        if chosen.isEmpty {
            switch view.background {
            case .running:
                notes.append("No process table is held for that time. The server keeps them for its last 24 hours.")
            default:
                notes.append("No process table is held for that time. This server doesn't keep history in the "
                             + "background, so the app has tables only from while it watched in full detail "
                             + "(a dashboard open, or get_server_snapshot or get_server_processes asking).")
            }
        }
        out.put("about", "source server: the busiest moment (most CPU) of the quarter hour, as the server's background "
                + "agent saw it. source app: the busiest table the app took itself in that quarter hour, while it watched.")
        if !notes.isEmpty { out.put("note", notes.joined(separator: " ")) }
        return out.value
    }
}

// MARK: - Naming a server

/// Finds the server an agent named: by id, by name or host, then by a
/// prefix of the name or of one of its words.
enum MCPResolver {
    struct Candidate: Sendable {
        var id: UUID
        var name: String
        /// Other names it answers to exactly: its SSH host, its hostname.
        var aliases: [String] = []
    }

    static func resolve(_ query: String, among candidates: [Candidate]) -> Result<Int, MCPToolError> {
        let wanted = normalize(query)
        let indices = Array(candidates.indices)
        let levels: [(Int) -> Bool] = [
            { candidates[$0].id.uuidString.lowercased() == wanted },
            { normalize(candidates[$0].name) == wanted },
            { candidates[$0].aliases.contains { normalize($0) == wanted } },
            { normalize(candidates[$0].name).hasPrefix(wanted) },
            { wordStarts(normalize(candidates[$0].name)).contains { $0.hasPrefix(wanted) } },
        ]
        for level in levels {
            let matches = indices.filter(level)
            if matches.count == 1 { return .success(matches[0]) }
            if matches.count > 1 {
                return .failure(MCPToolError(
                    .notFound,
                    "\"\(query)\" matches more than one server: \(matches.map { candidates[$0].name }.joined(separator: ", ")). "
                        + "Use more of the name, or the id.",
                    detail: ["candidates": list(matches.map { candidates[$0] })]))
            }
        }
        let names = candidates.map(\.name)
        return .failure(MCPToolError(
            .notFound,
            candidates.isEmpty
                ? "There are no servers in Rex Boing Remote yet. The user adds them in the app (Add Server)."
                : "No server matches \"\(query)\". The servers are: \(names.prefix(12).joined(separator: ", ")).",
            detail: ["candidates": list(Array(candidates.prefix(12)))]))
    }

    private static func list(_ candidates: [Candidate]) -> JSONValue {
        .array(candidates.map { ["id": .string($0.id.uuidString), "name": .string($0.name)] })
    }

    private static func normalize(_ text: String) -> String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
            .folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive], locale: nil)
            .lowercased()
    }

    /// The name from the start of each of its words on: "raspberry pi" gives
    /// "raspberry pi" and "pi".
    private static func wordStarts(_ name: String) -> [Substring] {
        var starts: [Substring] = []
        var previous: Character?
        for index in name.indices {
            let character = name[index]
            if character.isLetter || character.isNumber, previous.map({ !$0.isLetter && !$0.isNumber }) ?? true {
                starts.append(name[index...])
            }
            previous = character
        }
        return starts
    }
}
