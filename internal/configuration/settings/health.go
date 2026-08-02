package settings

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

// Health contains settings for the healthcheck and health server.
type Health struct {
	// ServerAddress is the listening address
	// for the health check server.
	// It cannot be the empty string in the internal state.
	ServerAddress string
	// TargetAddresses are the addresses (host or host:port)
	// to TCP TLS dial to periodically for the health check.
	// Addresses after the first one are used as fallbacks for retries.
	// It cannot be empty in the internal state.
	TargetAddresses []string
	// ICMPTargetIPs are the IP addresses to use for ICMP echo requests
	// in the health checker. The slice can be set to a single
	// unspecified address (0.0.0.0) such that the VPN server IP is used,
	// although this can be less reliable. It defaults to [1.1.1.1,8.8.8.8],
	// and cannot be left empty in the internal state.
	ICMPTargetIPs []netip.Addr
	// SmallCheckType is the type of small health check to perform.
	// It can be "icmp" or "dns", and defaults to "icmp".
	// Note it changes automatically to dns if icmp is not supported.
	SmallCheckType string
	// RestartVPN indicates whether to restart the VPN connection
	// when the healthcheck fails.
	RestartVPN *bool
	// StartupTimeout is the maximum duration of the initial TCP+TLS
	// healthcheck performed right after the VPN tunnel comes up.
	// Defaults to 15s (increased from the historical 6s to reduce
	// false-positive restart loops on slower providers; see #2154).
	// Set via HEALTH_STARTUP_TIMEOUT.
	StartupTimeout time.Duration
}

func (h Health) Validate() (err error) {
	err = validate.ListeningAddress(h.ServerAddress, os.Getuid())
	if err != nil {
		return fmt.Errorf("server listening address is not valid: %w", err)
	}

	for _, ip := range h.ICMPTargetIPs {
		switch {
		case !ip.IsValid():
			return fmt.Errorf("ICMP target IP address is not valid: %s", ip)
		case ip.IsUnspecified() && len(h.ICMPTargetIPs) > 1:
			return errors.New("ICMP target IP addresses are not compatible: " +
				"only a single IP address must be set if it is to be unspecified")
		}
	}

	err = validate.IsOneOf(h.SmallCheckType, "icmp", "dns")
	if err != nil {
		return fmt.Errorf("small check type is not valid: %w", err)
	}

	if h.StartupTimeout <= 0 {
		return errors.New("startup timeout must be greater than 0")
	}

	return nil
}

func (h *Health) copy() (copied Health) {
	return Health{
		ServerAddress:   h.ServerAddress,
		TargetAddresses: h.TargetAddresses,
		ICMPTargetIPs:   gosettings.CopySlice(h.ICMPTargetIPs),
		SmallCheckType:  h.SmallCheckType,
		RestartVPN:      gosettings.CopyPointer(h.RestartVPN),
		StartupTimeout:  h.StartupTimeout,
	}
}

// OverrideWith overrides fields of the receiver
// settings object with any field set in the other
// settings.
func (h *Health) OverrideWith(other Health) {
	h.ServerAddress = gosettings.OverrideWithComparable(h.ServerAddress, other.ServerAddress)
	h.TargetAddresses = gosettings.OverrideWithSlice(h.TargetAddresses, other.TargetAddresses)
	h.ICMPTargetIPs = gosettings.OverrideWithSlice(h.ICMPTargetIPs, other.ICMPTargetIPs)
	h.SmallCheckType = gosettings.OverrideWithComparable(h.SmallCheckType, other.SmallCheckType)
	h.RestartVPN = gosettings.OverrideWithPointer(h.RestartVPN, other.RestartVPN)
	h.StartupTimeout = gosettings.OverrideWithComparable(h.StartupTimeout, other.StartupTimeout)
}

func (h *Health) SetDefaults() {
	h.ServerAddress = gosettings.DefaultComparable(h.ServerAddress, "127.0.0.1:9999")
	h.TargetAddresses = gosettings.DefaultSlice(h.TargetAddresses, []string{"cloudflare.com:443", "github.com:443"})
	h.ICMPTargetIPs = gosettings.DefaultSlice(h.ICMPTargetIPs, []netip.Addr{
		netip.AddrFrom4([4]byte{1, 1, 1, 1}),
		netip.AddrFrom4([4]byte{8, 8, 8, 8}),
	})
	h.SmallCheckType = gosettings.DefaultComparable(h.SmallCheckType, "icmp")
	h.RestartVPN = gosettings.DefaultPointer(h.RestartVPN, true)
	// Default raised from historical 6s to 15s to reduce false restart loops
	// on slower VPN providers (see https://github.com/passteque/gluetun/issues/2154).
	h.StartupTimeout = gosettings.DefaultComparable(h.StartupTimeout, 15*time.Second)
}

func (h Health) String() string {
	return h.toLinesNode().String()
}

func (h Health) toLinesNode() (node *gotree.Node) {
	node = gotree.New("Health settings:")
	node.Appendf("Server listening address: %s", h.ServerAddress)
	targetAddrs := node.Appendf("Target addresses:")
	for _, targetAddr := range h.TargetAddresses {
		targetAddrs.Append(targetAddr)
	}
	switch h.SmallCheckType {
	case "icmp":
		icmpNode := node.Appendf("Small health check type: ICMP echo request")
		if len(h.ICMPTargetIPs) == 1 && h.ICMPTargetIPs[0].IsUnspecified() {
			icmpNode.Appendf("ICMP target IP: VPN server IP address")
		} else {
			icmpIPs := icmpNode.Appendf("ICMP target IPs:")
			for _, ip := range h.ICMPTargetIPs {
				icmpIPs.Append(ip.String())
			}
		}
	case "dns":
		node.Appendf("Small health check type: Plain DNS lookup over UDP")
	}
	node.Appendf("Restart VPN on healthcheck failure: %s", gosettings.BoolToYesNo(h.RestartVPN))
	node.Appendf("Startup healthcheck timeout: %s", h.StartupTimeout)
	return node
}

func (h *Health) Read(r *reader.Reader) (err error) {
	h.ServerAddress = r.String("HEALTH_SERVER_ADDRESS")
	h.TargetAddresses = r.CSV("HEALTH_TARGET_ADDRESSES",
		reader.RetroKeys("HEALTH_ADDRESS_TO_PING", "HEALTH_TARGET_ADDRESS"))
	h.ICMPTargetIPs, err = r.CSVNetipAddresses("HEALTH_ICMP_TARGET_IPS", reader.RetroKeys("HEALTH_ICMP_TARGET_IP"))
	if err != nil {
		return err
	}
	h.SmallCheckType = r.String("HEALTH_SMALL_CHECK_TYPE")
	h.RestartVPN, err = r.BoolPtr("HEALTH_RESTART_VPN")
	if err != nil {
		return err
	}
	startupTimeout, err := r.DurationPtr("HEALTH_STARTUP_TIMEOUT")
	if err != nil {
		return err
	}
	if startupTimeout != nil {
		h.StartupTimeout = *startupTimeout
	}
	return nil
}
