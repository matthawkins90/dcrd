// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2024 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addrmgr

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/decred/dcrd/wire"
)

// TestIPTypes ensures the various functions which determine the type of an IP
// address based on RFCs work as intended.
func TestIPTypes(t *testing.T) {
	type ipTest struct {
		ip       net.IP
		rfc1918  bool
		rfc2544  bool
		rfc3849  bool
		rfc3927  bool
		rfc3964  bool
		rfc4193  bool
		rfc4380  bool
		rfc4843  bool
		rfc4862  bool
		rfc5737  bool
		rfc6052  bool
		rfc6145  bool
		rfc6598  bool
		local    bool
		valid    bool
		routable bool
	}

	newIPTest := func(ip string, rfc1918, rfc2544, rfc3849, rfc3927, rfc3964,
		rfc4193, rfc4380, rfc4843, rfc4862, rfc5737, rfc6052, rfc6145, rfc6598,
		local, valid, routable bool) ipTest {
		nip := net.ParseIP(ip)
		test := ipTest{nip, rfc1918, rfc2544, rfc3849, rfc3927, rfc3964, rfc4193, rfc4380,
			rfc4843, rfc4862, rfc5737, rfc6052, rfc6145, rfc6598, local, valid, routable}
		return test
	}

	tests := []ipTest{
		newIPTest("10.255.255.255", true, false, false, false, false, false,
			false, false, false, false, false, false, false, false, true, false),
		newIPTest("192.168.0.1", true, false, false, false, false, false,
			false, false, false, false, false, false, false, false, true, false),
		newIPTest("172.31.255.1", true, false, false, false, false, false,
			false, false, false, false, false, false, false, false, true, false),
		newIPTest("172.32.1.1", false, false, false, false, false, false, false, false,
			false, false, false, false, false, false, true, true),
		newIPTest("169.254.250.120", false, false, false, true, false, false,
			false, false, false, false, false, false, false, false, true, false),
		newIPTest("0.0.0.0", false, false, false, false, false, false, false,
			false, false, false, false, false, false, true, false, false),
		newIPTest("255.255.255.255", false, false, false, false, false, false,
			false, false, false, false, false, false, false, false, false, false),
		newIPTest("127.0.0.1", false, false, false, false, false, false,
			false, false, false, false, false, false, false, true, true, false),
		newIPTest("fd00:dead::1", false, false, false, false, false, true,
			false, false, false, false, false, false, false, false, true, false),
		newIPTest("2001::1", false, false, false, false, false, false,
			true, false, false, false, false, false, false, false, true, true),
		newIPTest("2001:10:abcd::1:1", false, false, false, false, false, false,
			false, true, false, false, false, false, false, false, true, false),
		newIPTest("fe80::1", false, false, false, false, false, false,
			false, false, true, false, false, false, false, false, true, false),
		newIPTest("fe80:1::1", false, false, false, false, false, false,
			false, false, false, false, false, false, false, false, true, true),
		newIPTest("64:ff9b::1", false, false, false, false, false, false,
			false, false, false, false, true, false, false, false, true, true),
		newIPTest("::ffff:abcd:ef12:1", false, false, false, false, false, false,
			false, false, false, false, false, false, false, false, true, true),
		newIPTest("::1", false, false, false, false, false, false, false, false,
			false, false, false, false, false, true, true, false),
		newIPTest("198.18.0.1", false, true, false, false, false, false, false,
			false, false, false, false, false, false, false, true, false),
		newIPTest("100.127.255.1", false, false, false, false, false, false, false,
			false, false, false, false, false, true, false, true, false),
		newIPTest("203.0.113.1", false, false, false, false, false, false, false,
			false, false, false, false, false, false, false, true, false),
	}

	t.Logf("Running %d tests", len(tests))
	for _, test := range tests {
		if rv := isRFC1918(test.ip); rv != test.rfc1918 {
			t.Errorf("isRFC1918 %s\n got: %v want: %v", test.ip, rv, test.rfc1918)
		}

		if rv := isRFC3849(test.ip); rv != test.rfc3849 {
			t.Errorf("isRFC3849 %s\n got: %v want: %v", test.ip, rv, test.rfc3849)
		}

		if rv := isRFC3927(test.ip); rv != test.rfc3927 {
			t.Errorf("isRFC3927 %s\n got: %v want: %v", test.ip, rv, test.rfc3927)
		}

		if rv := isRFC3964(test.ip); rv != test.rfc3964 {
			t.Errorf("isRFC3964 %s\n got: %v want: %v", test.ip, rv, test.rfc3964)
		}

		if rv := isRFC4193(test.ip); rv != test.rfc4193 {
			t.Errorf("isRFC4193 %s\n got: %v want: %v", test.ip, rv, test.rfc4193)
		}

		if rv := isRFC4380(test.ip); rv != test.rfc4380 {
			t.Errorf("isRFC4380 %s\n got: %v want: %v", test.ip, rv, test.rfc4380)
		}

		if rv := isRFC4843(test.ip); rv != test.rfc4843 {
			t.Errorf("isRFC4843 %s\n got: %v want: %v", test.ip, rv, test.rfc4843)
		}

		if rv := isRFC4862(test.ip); rv != test.rfc4862 {
			t.Errorf("isRFC4862 %s\n got: %v want: %v", test.ip, rv, test.rfc4862)
		}

		if rv := isRFC6052(test.ip); rv != test.rfc6052 {
			t.Errorf("isRFC6052 %s\n got: %v want: %v", test.ip, rv, test.rfc6052)
		}

		if rv := isRFC6145(test.ip); rv != test.rfc6145 {
			t.Errorf("isRFC1918 %s\n got: %v want: %v", test.ip, rv, test.rfc6145)
		}

		if rv := isLocal(test.ip); rv != test.local {
			t.Errorf("isLocal %s\n got: %v want: %v", test.ip, rv, test.local)
		}

		if rv := isValid(test.ip); rv != test.valid {
			t.Errorf("IsValid %s\n got: %v want: %v", test.ip, rv, test.valid)
		}

		if rv := IsRoutable(test.ip); rv != test.routable {
			t.Errorf("IsRoutable %s\n got: %v want: %v", test.ip, rv, test.routable)
		}
	}
}

// TestIsTorV3 tests the isTorV3 function to ensure it can properly identify
// whether or not various addresses match the TorV3 spec.
func TestIsTorV3(t *testing.T) {
	tests := []struct {
		name            string
		input_bytes     []byte
		expected_pubkey []byte
		expected_bool   bool
	}{
		{
			name:            "Valid TorV3 address",
			input_bytes:     append(torV3PubkeyBytes, 0xEE, 0x27, torV3VersionByte),
			expected_pubkey: torV3PubkeyBytes,
			expected_bool:   true,
		},
		{
			name: "Empty pubkey, but still valid",
			input_bytes: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0xCD, 0x0E, torV3VersionByte,
			},
			expected_pubkey: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			expected_bool: true,
		},
		{
			name:            "Incorrect length",
			input_bytes:     []byte{0x01, 0x02, 0x03},
			expected_pubkey: nil,
			expected_bool:   false,
		},
		{
			name:            "Wrong version byte",
			input_bytes:     append(torV3PubkeyBytes, 0xEE, 0x27, 0x01),
			expected_pubkey: nil,
			expected_bool:   false,
		},
		{
			name:            "Computed checksum doesn't match input checksum",
			input_bytes:     append(torV3PubkeyBytes, 0x00, 0x00, torV3VersionByte),
			expected_pubkey: nil,
			expected_bool:   false,
		},
	}

	for _, test := range tests {
		pubkey, valid := isTorV3(test.input_bytes)
		if !bytes.Equal(pubkey, test.expected_pubkey) || valid != test.expected_bool {
			t.Errorf("%q: unexpected result: got pubkey: %v, valid: %v;"+
				"expected pubkey: %v, expected_bool: %v", test.name, pubkey,
				valid, test.expected_pubkey, test.expected_bool)
		}
	}
}

// TestGroupKey tests the GroupKey function to ensure it properly groups various
// IP addresses.
func TestGroupKey(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		// Local addresses.
		{name: "ipv4 localhost", ip: "127.0.0.1", expected: "local"},
		{name: "ipv6 localhost", ip: "::1", expected: "local"},
		{name: "ipv4 zero", ip: "0.0.0.0", expected: "local"},
		{name: "ipv4 first octet zero", ip: "0.1.2.3", expected: "local"},

		// Unroutable addresses.
		{name: "ipv4 invalid bcast", ip: "255.255.255.255", expected: "unroutable"},
		{name: "ipv4 rfc1918 10/8", ip: "10.1.2.3", expected: "unroutable"},
		{name: "ipv4 rfc1918 172.16/12", ip: "172.16.1.2", expected: "unroutable"},
		{name: "ipv4 rfc1918 192.168/16", ip: "192.168.1.2", expected: "unroutable"},
		{name: "ipv6 rfc3849 2001:db8::/32", ip: "2001:db8::1234", expected: "unroutable"},
		{name: "ipv4 rfc3927 169.254/16", ip: "169.254.1.2", expected: "unroutable"},
		{name: "ipv6 rfc4193 fc00::/7", ip: "fc00::1234", expected: "unroutable"},
		{name: "ipv6 rfc4843 2001:10::/28", ip: "2001:10::1234", expected: "unroutable"},
		{name: "ipv6 rfc4862 fe80::/64", ip: "fe80::1234", expected: "unroutable"},

		// IPv4 normal.
		{name: "ipv4 normal class a", ip: "12.1.2.3", expected: "12.1.0.0"},
		{name: "ipv4 normal class b", ip: "173.1.2.3", expected: "173.1.0.0"},
		{name: "ipv4 normal class c", ip: "196.1.2.3", expected: "196.1.0.0"},

		// IPv6/IPv4 translations.
		{name: "ipv6 rfc3964 with ipv4 encap", ip: "2002:0c01:0203::", expected: "12.1.0.0"},
		{name: "ipv6 rfc4380 toredo ipv4", ip: "2001:0:1234::f3fe:fdfc", expected: "12.1.0.0"},
		{name: "ipv6 rfc6052 well-known prefix with ipv4", ip: "64:ff9b::0c01:0203", expected: "12.1.0.0"},
		{name: "ipv6 rfc6145 translated ipv4", ip: "::ffff:0:0c01:0203", expected: "12.1.0.0"},

		// IPv6 normal.
		{name: "ipv6 normal", ip: "2602:100::1", expected: "2602:100::"},
		{name: "ipv6 normal 2", ip: "2602:0100::1234", expected: "2602:100::"},
		{name: "ipv6 hurricane electric", ip: "2001:470:1f10:a1::2", expected: "2001:470:1000::"},
		{name: "ipv6 hurricane electric 2", ip: "2001:0470:1f10:a1::2", expected: "2001:470:1000::"},

		// TorV3
		{name: "TorV3", ip: "xa4r2iadxm55fbnqgwwi5mymqdcofiu3w6rpbtqn7b2dyn7mgwj64jyd.onion", expected: "torv3:8"},
	}

	for _, test := range tests {
		addrType, addrBytes, err := ParseHost(test.ip)
		if err != nil {
			t.Fatalf("failed to decode host %q: %v", test.ip, err)
		}
		netAddress, _ := NewNetAddressFromParams(addrType, addrBytes, 8333, time.Now(), wire.SFNodeNetwork)
		actualkey := netAddress.GroupKey()
		if actualkey != test.expected {
			t.Errorf("%q: unexpected group key - got %q, expected: %q", test.name, actualkey, test.expected)
		}
	}
}
