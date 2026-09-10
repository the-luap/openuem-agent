package enrollmentstore

// InstallationBinding contains public installation metadata from authenticated
// native history. It remains readable during renewal quarantine or certificate
// expiry so a service can verify its executable before attempting recovery.
// It grants no authority to use any generation's credentials or contact another
// origin, and never includes an invitation, certificate or private key.
type InstallationBinding struct {
	DeviceID        string
	TenantID        int
	SiteID          int
	Origin          string
	Platform        string
	Architecture    string
	ReleaseDigest   string
	ReleaseSequence uint64
	AgentSize       int64
	AgentSHA256     string
}

// InstallationBinding requires a completed original enrollment and a consistent
// authenticated renewal history. Pending enrollment, missing anchors, partial
// restores and corrupt history fail before returning installation metadata.
// Call Load separately after recovery to obtain a currently usable identity.
func (s *Store) InstallationBinding() (*InstallationBinding, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, state, err := s.renewalState()
	if err != nil {
		return nil, err
	}
	defer p.close()
	defer state.close()
	i := state.identity
	return &InstallationBinding{DeviceID: i.Response.DeviceID, TenantID: i.Response.TenantID, SiteID: i.Response.SiteID, Origin: i.Origin, Platform: i.Platform, Architecture: i.Architecture, ReleaseDigest: i.ReleaseDigest, ReleaseSequence: p.bootstrap.ReleaseSequence, AgentSize: i.AgentSize, AgentSHA256: i.AgentSHA256}, nil
}

// Matches verifies that a subsequently loaded identity belongs to the same
// installation whose executable was checked. It does not replace Load's current
// certificate validation or the service's independent executable verification.
func (b InstallationBinding) Matches(i *Identity) bool {
	return i != nil && b.DeviceID == i.Response.DeviceID && b.TenantID == i.Response.TenantID && b.SiteID == i.Response.SiteID && b.Origin == i.Origin && b.Platform == i.Platform && b.Architecture == i.Architecture && b.ReleaseDigest == i.ReleaseDigest && b.ReleaseSequence == i.ReleaseSequence && b.AgentSize == i.AgentSize && b.AgentSHA256 == i.AgentSHA256
}
