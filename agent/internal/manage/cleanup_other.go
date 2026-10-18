//go:build !windows

package manage

import "strings"

// CleanupOld deletes what earlier runs left behind. Only Windows leaves
// executables (a running .exe can be renamed but not deleted); here it is
// the temporary files of an upgrade, an install or a history save that was
// killed before it could rename its file into place or remove it. The agent
// calls it at the start of every run.
func CleanupOld() {
	if dir := installDir(); dir != "" {
		removeStale(dir, func(n string) bool {
			// upgrade's, unixWriteAtomic's for the agent, and serve's for
			// history.json.
			return strings.HasPrefix(n, ".rex-boing-agent-upgrade-") || strings.HasPrefix(n, ".rex-boing-agent.rbr-") ||
				strings.HasPrefix(n, ".history.json.")
		})
	}
}
