// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

package nftables

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestProtoNumber(t *testing.T) {
	cases := map[string]struct {
		want    int
		wantErr bool
	}{
		"TCP":  {want: unix.IPPROTO_TCP},
		"UDP":  {want: unix.IPPROTO_UDP},
		"ICMP": {wantErr: true},
		"":     {wantErr: true},
	}
	for in, tc := range cases {
		t.Run(in, func(t *testing.T) {
			got, err := protoNumber(in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("protoNumber(%q) = %d, want %d", in, got, tc.want)
			}
		})
	}
}

func TestIfnamePadding(t *testing.T) {
	b := ifname("wg-uplink")
	if len(b) != ifnameSize {
		t.Fatalf("ifname length = %d, want %d", len(b), ifnameSize)
	}
	if string(b[:9]) != "wg-uplink" {
		t.Fatalf("ifname prefix = %q", string(b[:9]))
	}
	for i := 9; i < ifnameSize; i++ {
		if b[i] != 0 {
			t.Fatalf("ifname byte %d not zero-padded: %d", i, b[i])
		}
	}
}
