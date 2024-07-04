// Copyright (c) 2024 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addrmgr

import (
	"encoding/base32"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/wire"
)

// NetAddress defines information about a peer on the network.
type NetAddress struct {
	// Type represents the type of an address (IPv4, IPv6, Tor, etc.).
	Type NetAddressType

	// IP address of the peer. It is defined as a byte array to support various
	// address types that are not standard to the net module and therefore not
	// entirely appropriate to store as a net.IP.
	IP []byte

	// Port is the port of the remote peer.
	Port uint16

	// Timestamp is the last time the address was seen.
	Timestamp time.Time

	// Services represents the service flags supported by this network address.
	Services wire.ServiceFlag
}

// IsRoutable returns a boolean indicating whether the network address is
// routable.
func (netAddr *NetAddress) IsRoutable() bool {
	return IsRoutable(netAddr.IP)
}

// ipString returns a string representation of the network address' IP field.
// If the ip is in the range used for Tor addresses then it will be transformed
// into the respective .onion address. It does not include the port.
func (netAddr *NetAddress) ipString() string {
	netIP := netAddr.IP
	switch netAddr.Type {
	case TorV3Address:
		// A TorV3 onion address is 35 bytes total:
		// A 32 byte pubkey, then a 2 byte checksum, then a 1 byte version.

		// By default, the address manager parses and stores TorV3 address as
		// the 32 byte pubkey only. Therefore, it is safe to assume that the
		// input netIP is not the full 35 byte onion address and will need to
		// be constructed from the pubkey.
		if len(netIP) == 32 {
			var pubkey [32]byte
			copy(pubkey[:], netIP)                // Already had the pubkey
			checksum := calcTorV3Checksum(pubkey) // Generate the checksum
			var fullAddress [35]byte
			copy(fullAddress[:32], pubkey[:])
			copy(fullAddress[32:], checksum[:])
			fullAddress[34] = 3 // Set the version byte for TorV3

			base32 := base32.StdEncoding.EncodeToString(fullAddress[:])
			return strings.ToLower(base32) + ".onion"
		}
	case IPv6Address:
		return net.IP(netIP).String()
	case IPv4Address:
		return net.IP(netIP).String()
	}

	// If the netAddr.Type is not recognized in the switch:
	return fmt.Sprintf(
		"unsupported IP type %d, %s, %x", netAddr.Type, netIP, netIP)
}

// Key returns a string that can be used to uniquely represent the network
// address and includes the port.
func (netAddr *NetAddress) Key() string {
	portString := strconv.FormatUint(uint64(netAddr.Port), 10)
	return net.JoinHostPort(netAddr.ipString(), portString)
}

// String returns a human-readable string for the network address.  This is
// equivalent to calling Key, but is provided so the type can be used as a
// fmt.Stringer.
func (netAddr *NetAddress) String() string {
	return netAddr.Key()
}

// Clone creates a shallow copy of the NetAddress instance. The IP reference
// is shared since it is not mutated.
func (netAddr *NetAddress) Clone() *NetAddress {
	netAddrCopy := *netAddr
	return &netAddrCopy
}

// AddService adds the provided service to the set of services that the
// network address supports.
func (netAddr *NetAddress) AddService(service wire.ServiceFlag) {
	netAddr.Services |= service
}

// canonicalizeIP converts the provided address' bytes into a standard structure
// based on the type of the network address, if applicable.
func canonicalizeIP(addrType NetAddressType, addrBytes []byte) []byte {
	if addrBytes == nil {
		return nil
	}
	switch {
	case len(addrBytes) == 16 && addrType == IPv4Address:
		return net.IP(addrBytes).To4()
	case addrType == IPv6Address:
		return net.IP(addrBytes).To16()
	}
	// Given a Tor address (or other), the bytes are returned unchanged.
	return addrBytes
}

// deriveNetAddressType attempts to determine the network address type from the
// address' raw bytes. If the type cannot be determined, an error is returned.
func deriveNetAddressType(claimedType NetAddressType, addrBytes []byte) (NetAddressType, error) {
	len := len(addrBytes)
	switch {
	case isIPv4(addrBytes):
		return IPv4Address, nil
	case len == 16:
		return IPv6Address, nil
	case len == 32 && claimedType == TorV3Address:
		return TorV3Address, nil
	}
	str := fmt.Sprintf("unable to determine address type from raw network "+
		"address bytes: %v", addrBytes)
	return UnknownAddressType, makeError(ErrUnknownAddressType, str)
}

// checkNetAddressType returns an error if the suggested address type does not
// appear to match the provided address.
func checkNetAddressType(addrType NetAddressType, addrBytes []byte) error {
	derivedAddressType, err := deriveNetAddressType(addrType, addrBytes)
	if err != nil {
		return err
	}
	if addrType != derivedAddressType {
		str := fmt.Sprintf("derived address type does not match expected value"+
			" (got %v, expected %v, address bytes %v).", derivedAddressType,
			addrType, addrBytes)
		return makeError(ErrMismatchedAddressType, str)
	}
	return nil
}

// NewNetAddressFromParams creates a new network address from the given
// parameters. If the provided address type does not appear to match the
// address, an error is returned.
func NewNetAddressFromParams(netAddressType NetAddressType, addrBytes []byte, port uint16, timestamp time.Time, services wire.ServiceFlag) (*NetAddress, error) {
	canonicalizedIP := canonicalizeIP(netAddressType, addrBytes)
	err := checkNetAddressType(netAddressType, canonicalizedIP)
	if err != nil {
		return nil, err
	}
	return &NetAddress{
		Type:      netAddressType,
		IP:        canonicalizedIP,
		Port:      port,
		Services:  services,
		Timestamp: timestamp,
	}, nil
}

// newNetAddressFromString creates a new network address from the given string.
// The address string is expected to be provided in the format "host:port".
func (a *AddrManager) newNetAddressFromString(addr string) (*NetAddress, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	addrType, addrBytes, err := ParseHost(host)
	if err != nil {
		return nil, err
	}
	if addrType == UnknownAddressType {
		str := fmt.Sprintf("failed to deserialize address %s", addr)
		return nil, makeError(ErrUnknownAddressType, str)
	}
	timestamp := time.Unix(time.Now().Unix(), 0)
	return NewNetAddressFromParams(addrType, addrBytes, uint16(port), timestamp,
		wire.SFNodeNetwork)
}

// NewNetAddressFromIPPort creates a new network address given an ip, port, and
// the supported service flags for the address. The provided ip MUST be a valid
// IPv4 or IPv6 address, since this method does not perform error checking on
// the derived network address type. Furthermore, other types of network
// addresses (like TorV3 or I2P) will not be recognized.
func NewNetAddressFromIPPort(ip net.IP, port uint16, services wire.ServiceFlag) *NetAddress {
	netAddressType, _ := deriveNetAddressType(UnknownAddressType, ip)
	timestamp := time.Unix(time.Now().Unix(), 0)
	canonicalizedIP := canonicalizeIP(netAddressType, ip)
	return &NetAddress{
		Type:      netAddressType,
		IP:        canonicalizedIP,
		Port:      port,
		Services:  services,
		Timestamp: timestamp,
	}
}
