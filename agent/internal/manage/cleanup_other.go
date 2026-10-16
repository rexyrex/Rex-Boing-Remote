//go:build !windows

package manage

// CleanupOld deletes executables left behind by earlier upgrades. Only
// Windows leaves any (a running .exe can be renamed but not deleted), so on
// every other OS it does nothing. The agent calls it at the start of every
// run.
func CleanupOld() {}
