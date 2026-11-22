package buildinfo

const Version = "0.5.6"

// GetVersion returns the application version string.
// In slim builds, it appends the "-slim" suffix.
func GetVersion() string {
	if IsSlim {
		return Version + "-slim"
	}
	return Version
}
