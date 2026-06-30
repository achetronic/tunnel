// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package ipam

import (
	"testing"
)

func TestIPAM(t *testing.T) {
	tests := []struct {
		name        string
		network     string
		expectErr   bool
		relayIP     string
		replicaIPs  map[int32]string
		replicaErrs map[int32]bool
	}{
		{
			name:      "valid /24 network",
			network:   "10.200.0.0/24",
			expectErr: false,
			relayIP:   "10.200.0.1",
			replicaIPs: map[int32]string{
				0:   "10.200.0.2",
				1:   "10.200.0.3",
				252: "10.200.0.254",
			},
			replicaErrs: map[int32]bool{
				-1:  true,
				253: true, // .255 is broadcast
			},
		},
		{
			// Non-.0-aligned base (TODO #18): offsets are computed over the
			// whole prefix, so base+1 is .129, not a hardcoded .1 outside
			// the network.
			name:      "non-aligned /25 base",
			network:   "10.200.0.128/25",
			expectErr: false,
			relayIP:   "10.200.0.129",
			replicaIPs: map[int32]string{
				0: "10.200.0.130",
			},
			replicaErrs: map[int32]bool{
				// base+2+125 = .255, the /25 broadcast.
				125: true,
			},
		},
		{
			// Wider-than-/24 network (TODO #18): the host offset crosses the
			// third-octet boundary instead of erroring at 254.
			name:      "/23 crosses octet boundary",
			network:   "10.200.0.0/23",
			expectErr: false,
			relayIP:   "10.200.0.1",
			replicaIPs: map[int32]string{
				0:   "10.200.0.2",
				254: "10.200.1.0",
				255: "10.200.1.1",
			},
			replicaErrs: map[int32]bool{
				// base+2+509 = 10.200.1.255, the /23 broadcast.
				509: true,
			},
		},
		{
			name:      "invalid CIDR",
			network:   "not-a-cidr",
			expectErr: true,
		},
		{
			// Hallazgo #17: IPv6 must be rejected by New itself.
			name:      "ipv6 rejected",
			network:   "::1/128",
			expectErr: true,
		},
		{
			// Hallazgo #17: small /28 network (10.0.0.0/28 spans .0 to .15).
			// ordinal 0 (.2) is valid inside the prefix.
			// ordinal 14 maps to lastOctet=16 (.16) which is outside the /28 prefix.
			name:      "small /28 ordinal in range",
			network:   "10.0.0.0/28",
			expectErr: false,
			relayIP:   "10.0.0.1",
			replicaIPs: map[int32]string{
				0: "10.0.0.2",
			},
			replicaErrs: map[int32]bool{
				// ordinal 14 -> lastOctet=16 -> .16 is outside the /28 prefix
				14: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i, err := New(tt.network)
			if (err != nil) != tt.expectErr {
				t.Fatalf("New() error = %v, expectErr %v", err, tt.expectErr)
			}
			if err != nil {
				return
			}

			relay, err := i.RelayIP()
			if tt.relayIP == "" {
				if err == nil {
					t.Errorf("RelayIP() expected error, got %s", relay)
				}
			} else {
				if err != nil {
					t.Errorf("RelayIP() unexpected error: %v", err)
				}
				if relay != tt.relayIP {
					t.Errorf("RelayIP() = %v, want %v", relay, tt.relayIP)
				}
			}

			for ord, wantIP := range tt.replicaIPs {
				ip, err := i.ReplicaIP(ord)
				if err != nil {
					t.Errorf("ReplicaIP(%d) unexpected error: %v", ord, err)
				}
				if ip != wantIP {
					t.Errorf("ReplicaIP(%d) = %v, want %v", ord, ip, wantIP)
				}
			}

			for ord, wantErr := range tt.replicaErrs {
				if wantErr {
					_, err := i.ReplicaIP(ord)
					if err == nil {
						t.Errorf("ReplicaIP(%d) expected error, got nil", ord)
					}
				}
			}
		})
	}
}

// TestMaskBits verifies that MaskBits returns the correct prefix length,
// eliminating the need for callers to re-parse the CIDR string.
func TestMaskBits(t *testing.T) {
	cases := []struct {
		cidr string
		want int
	}{
		{"10.0.0.0/24", 24},
		{"192.168.0.0/16", 16},
		{"10.0.0.0/28", 28},
	}
	for _, c := range cases {
		i, err := New(c.cidr)
		if err != nil {
			t.Fatalf("New(%q) unexpected error: %v", c.cidr, err)
		}
		if got := i.MaskBits(); got != c.want {
			t.Errorf("MaskBits() for %q = %d, want %d", c.cidr, got, c.want)
		}
	}
}
