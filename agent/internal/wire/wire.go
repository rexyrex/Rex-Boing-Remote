// Package wire defines the JSON messages of the Rex Boing Remote protocol,
// version 1. PROTOCOL.md at the repository root is the specification; these
// types are its Go mirror and must stay in step with it.
//
// Optional numbers whose zero is a real reading (a fan at 0 rpm, 0 W) are
// pointers, so "absent" and "zero" stay distinct on the wire. Values that are
// always present when their section is present are plain.
package wire

// ProtocolVersion is the protocol this agent speaks.
const ProtocolVersion = 1

// AgentInfo identifies the agent build.
type AgentInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// Host describes the machine. Sent once, in Hello.
type Host struct {
	Hostname         string `json:"hostname,omitempty"`
	ModelName        string `json:"modelName,omitempty"`
	ModelIdentifier  string `json:"modelIdentifier,omitempty"`
	Vendor           string `json:"vendor,omitempty"`
	ChipName         string `json:"chipName,omitempty"`
	OSName           string `json:"osName,omitempty"`
	OSVersion        string `json:"osVersion,omitempty"`
	Kernel           string `json:"kernel,omitempty"`
	PhysicalCores    int    `json:"physicalCores,omitempty"`
	LogicalCores     int    `json:"logicalCores,omitempty"`
	PerformanceCores int    `json:"performanceCores,omitempty"`
	EfficiencyCores  int    `json:"efficiencyCores,omitempty"`
	MemoryBytes      uint64 `json:"memoryBytes,omitempty"`
	BootTime         int64  `json:"bootTime,omitempty"` // ms since epoch
	IsAppleSilicon   bool   `json:"isAppleSilicon,omitempty"`
	Virtualization   string `json:"virtualization,omitempty"`
}

// Hello is the first line of every stream.
type Hello struct {
	Type         string    `json:"type"` // "hello"
	Protocol     int       `json:"protocol"`
	Agent        AgentInfo `json:"agent"`
	Host         Host      `json:"host"`
	Capabilities []string  `json:"capabilities"`
	Interval     float64   `json:"interval"`
}

// Detail is the level a sample answers.
type Detail string

const (
	DetailVitals Detail = "vitals"
	DetailFull   Detail = "full"
)

// Sample is one reading.
type Sample struct {
	Type     string  `json:"type"` // "sample"
	Seq      uint64  `json:"seq"`
	T        int64   `json:"t"`        // ms since epoch
	Interval float64 `json:"interval"` // seconds the rates cover
	Detail   Detail  `json:"detail"`
	Resync   bool    `json:"resync"`

	CPU       *CPU       `json:"cpu,omitempty"`
	Memory    *Memory    `json:"memory,omitempty"`
	GPUs      []GPU      `json:"gpus,omitempty"`
	Thermal   *Thermal   `json:"thermal,omitempty"`
	Power     *Power     `json:"power,omitempty"`
	Network   *Network   `json:"network,omitempty"`
	Disk      *Disk      `json:"disk,omitempty"`
	Battery   *Battery   `json:"battery,omitempty"`
	Pressure  *Pressure  `json:"pressure,omitempty"`
	System    *System    `json:"system,omitempty"`
	Processes *Processes `json:"processes,omitempty"`
}

type CPU struct {
	Total               float64     `json:"total"`
	User                float64     `json:"user"`
	System              float64     `json:"system"`
	Idle                float64     `json:"idle"`
	Nice                float64     `json:"nice"`
	IOWait              *float64    `json:"iowait,omitempty"`
	Steal               *float64    `json:"steal,omitempty"`
	PerCore             []float64   `json:"perCore,omitempty"`
	Kinds               string      `json:"kinds,omitempty"`
	ClockMHz            *float64    `json:"clockMHz,omitempty"`
	PerformanceClockMHz *float64    `json:"performanceClockMHz,omitempty"`
	EfficiencyClockMHz  *float64    `json:"efficiencyClockMHz,omitempty"`
	Load                *[3]float64 `json:"load,omitempty"`
	Processes           *int        `json:"processes,omitempty"`
	Threads             *int        `json:"threads,omitempty"`
	Zombies             *int        `json:"zombies,omitempty"`
}

type Swap struct {
	Total     uint64   `json:"total"`
	Used      uint64   `json:"used"`
	Free      uint64   `json:"free"`
	InRate    *float64 `json:"inRate,omitempty"`
	OutRate   *float64 `json:"outRate,omitempty"`
	Encrypted bool     `json:"encrypted,omitempty"`
}

type Memory struct {
	Total         uint64   `json:"total"`
	Used          uint64   `json:"used"`
	Available     *uint64  `json:"available,omitempty"`
	Free          *uint64  `json:"free,omitempty"`
	App           *uint64  `json:"app,omitempty"`
	Wired         *uint64  `json:"wired,omitempty"`
	Compressed    *uint64  `json:"compressed,omitempty"`
	Cached        *uint64  `json:"cached,omitempty"`
	Buffers       *uint64  `json:"buffers,omitempty"`
	Active        *uint64  `json:"active,omitempty"`
	Inactive      *uint64  `json:"inactive,omitempty"`
	Purgeable     *uint64  `json:"purgeable,omitempty"`
	Pressure      *float64 `json:"pressure,omitempty"`
	PressureLevel string   `json:"pressureLevel,omitempty"` // normal | warning | critical
	Swap          *Swap    `json:"swap,omitempty"`
}

type GPU struct {
	Name            string             `json:"name,omitempty"`
	Vendor          string             `json:"vendor,omitempty"`
	Utilization     float64            `json:"utilization"`
	Engines         map[string]float64 `json:"engines,omitempty"`
	MemoryUsed      *uint64            `json:"memoryUsed,omitempty"`
	MemoryTotal     *uint64            `json:"memoryTotal,omitempty"`
	MemoryAllocated *uint64            `json:"memoryAllocated,omitempty"`
	ClockMHz        *float64           `json:"clockMHz,omitempty"`
	MaxClockMHz     *float64           `json:"maxClockMHz,omitempty"`
	Celsius         *float64           `json:"celsius,omitempty"`
	Watts           *float64           `json:"watts,omitempty"`
	FanRPM          *float64           `json:"fanRPM,omitempty"`
	FanPercent      *float64           `json:"fanPercent,omitempty"`
	CoreCount       *int               `json:"coreCount,omitempty"`
}

type Sensor struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Celsius  float64  `json:"celsius"`
	Category string   `json:"category"` // CPU GPU SoC Memory Storage Battery Power Ambient Other
	High     *float64 `json:"high,omitempty"`
	Critical *float64 `json:"critical,omitempty"`
}

type Fan struct {
	Index  int      `json:"index"`
	Label  string   `json:"label,omitempty"`
	RPM    float64  `json:"rpm"`
	MinRPM *float64 `json:"minRPM,omitempty"`
	MaxRPM *float64 `json:"maxRPM,omitempty"`
}

type Thermal struct {
	Sensors        []Sensor `json:"sensors,omitempty"`
	Fans           []Fan    `json:"fans,omitempty"`
	CPUCelsius     *float64 `json:"cpuCelsius,omitempty"`
	GPUCelsius     *float64 `json:"gpuCelsius,omitempty"`
	SoCCelsius     *float64 `json:"socCelsius,omitempty"`
	BatteryCelsius *float64 `json:"batteryCelsius,omitempty"`
	StorageCelsius *float64 `json:"storageCelsius,omitempty"`
	PeakCelsius    *float64 `json:"peakCelsius,omitempty"`
	State          string   `json:"state,omitempty"` // nominal | fair | serious | critical
}

type Power struct {
	CPUWatts         *float64 `json:"cpuWatts,omitempty"`
	GPUWatts         *float64 `json:"gpuWatts,omitempty"`
	ANEWatts         *float64 `json:"aneWatts,omitempty"`
	PackageWatts     *float64 `json:"packageWatts,omitempty"`
	SystemWatts      *float64 `json:"systemWatts,omitempty"`
	SystemTotalWatts *float64 `json:"systemTotalWatts,omitempty"`
	DCInWatts        *float64 `json:"dcInWatts,omitempty"`
	AdapterWatts     *float64 `json:"adapterWatts,omitempty"`
}

type Interface struct {
	Name      string   `json:"name"`
	RX        float64  `json:"rx"`
	TX        float64  `json:"tx"`
	SpeedMbps *float64 `json:"speedMbps,omitempty"`
	Up        bool     `json:"up"`
}

type Network struct {
	RX               float64     `json:"rx"`
	TX               float64     `json:"tx"`
	RXTotal          uint64      `json:"rxTotal,omitempty"`
	TXTotal          uint64      `json:"txTotal,omitempty"`
	PrimaryInterface string      `json:"primaryInterface,omitempty"`
	LocalAddress     string      `json:"localAddress,omitempty"`
	Interfaces       []Interface `json:"interfaces,omitempty"`
}

type Volume struct {
	Name      string `json:"name"`
	Mount     string `json:"mount,omitempty"`
	FS        string `json:"fs,omitempty"`
	Total     uint64 `json:"total"`
	Available uint64 `json:"available"`
}

type Disk struct {
	Read       float64  `json:"read"`
	Write      float64  `json:"write"`
	ReadTotal  uint64   `json:"readTotal,omitempty"`
	WriteTotal uint64   `json:"writeTotal,omitempty"`
	Volumes    []Volume `json:"volumes,omitempty"`
}

type Battery struct {
	Present              bool     `json:"present"`
	Percentage           float64  `json:"percentage"`
	Charging             bool     `json:"charging"`
	PluggedIn            bool     `json:"pluggedIn"`
	TimeRemainingMinutes *int     `json:"timeRemainingMinutes,omitempty"`
	CycleCount           *int     `json:"cycleCount,omitempty"`
	DesignCapacity       *int     `json:"designCapacity,omitempty"`
	MaxCapacity          *int     `json:"maxCapacity,omitempty"`
	Celsius              *float64 `json:"celsius,omitempty"`
	Voltage              *float64 `json:"voltage,omitempty"`
	Amperage             *float64 `json:"amperage,omitempty"`
	Condition            string   `json:"condition,omitempty"`
	SystemWatts          *float64 `json:"systemWatts,omitempty"`
	ChargingWatts        *float64 `json:"chargingWatts,omitempty"`
	AdapterWatts         *float64 `json:"adapterWatts,omitempty"`
}

type Pressure struct {
	CPU        float64  `json:"cpu"`
	Memory     float64  `json:"memory"`
	IO         float64  `json:"io"`
	MemoryFull *float64 `json:"memoryFull,omitempty"`
	IOFull     *float64 `json:"ioFull,omitempty"`
}

type System struct {
	Uptime          float64  `json:"uptime"`
	RebootRequired  *bool    `json:"rebootRequired,omitempty"`
	RebootReason    string   `json:"rebootReason,omitempty"`
	Updates         *int     `json:"updates,omitempty"`
	SecurityUpdates *int     `json:"securityUpdates,omitempty"`
	FailedServices  []string `json:"failedServices,omitempty"`
	Containers      *int     `json:"containers,omitempty"`
}

type ProcessRow struct {
	PID       int32   `json:"pid"`
	Name      string  `json:"name"`
	User      string  `json:"user,omitempty"`
	Start     uint64  `json:"start,omitempty"` // µs since epoch
	Path      string  `json:"path,omitempty"`
	Cmd       string  `json:"cmd,omitempty"`
	CPU       float64 `json:"cpu"`    // percent of one core
	Memory    uint64  `json:"memory"` // resident bytes
	GPU       float64 `json:"gpu,omitempty"`
	Energy    float64 `json:"energy,omitempty"`
	DiskRead  float64 `json:"diskRead,omitempty"`
	DiskWrite float64 `json:"diskWrite,omitempty"`
	Wakeups   float64 `json:"wakeups,omitempty"`
	Threads   int     `json:"threads,omitempty"`
}

type Processes struct {
	Count          int                `json:"count"`
	SampledAt      int64              `json:"sampledAt"` // ms since epoch
	Interval       float64            `json:"interval"`
	GPUAttribution bool               `json:"gpuAttribution"`
	Rows           []ProcessRow       `json:"rows"`
	Rank           map[string][]int32 `json:"rank"`
}

// Notice is an optional, non-fatal message for the user.
type Notice struct {
	Type    string `json:"type"` // "notice"
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Request is what the app sends on stdin. Fields are optional.
type Request struct {
	Want     Detail   `json:"want,omitempty"`
	Interval *float64 `json:"interval,omitempty"`
}

// Result is printed by install, upgrade and uninstall.
type Result struct {
	OK      bool              `json:"ok"`
	Error   string            `json:"error,omitempty"`
	Message string            `json:"message,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

// PairCode is the JSON inside an rbr1: pairing code.
type PairCode struct {
	V         int      `json:"v"`
	Name      string   `json:"n"`
	User      string   `json:"u"`
	Port      int      `json:"p"`
	OS        string   `json:"o"`
	Addresses []string `json:"a"`
	HostKeys  []string `json:"k"`
}

// Helpers for building optional values.
func F(v float64) *float64 { return &v }
func U(v uint64) *uint64   { return &v }
func I(v int) *int         { return &v }
func B(v bool) *bool       { return &v }
