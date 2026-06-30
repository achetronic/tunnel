// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package agentconfig

import (
	"reflect"
	"strings"
	"testing"
)

// validRelayJSON is a minimal valid relay document with no nftables config and
// a single uplink peer (no endpoint set since uplinks dial in).
const validRelayJSON = `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-relay",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "listenPort": 51821,
      "address": "10.200.0.1/24"
    },
    "peers": [
      {
        "publicKey": "d29ybGR3b3JsZHdvcmxkd29ybGR3b3JsZHdvcmxk",
        "allowedIPs": ["10.200.0.2/32"]
      }
    ]
  }
}`

// validUplinkJSON is a valid uplink document with nftables config, MTU, an
// endpoint pointing at the relay, and a non-zero PersistentKeepalive.
const validUplinkJSON = `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-uplink",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "10.200.0.2/32",
      "mtu": 1420
    },
    "peers": [
      {
        "publicKey": "d29ybGR3b3JsZHdvcmxkd29ybGR3b3JsZHdvcmxk",
        "allowedIPs": ["0.0.0.0/0"],
        "endpoint": "203.0.113.1:51821",
        "persistentKeepalive": 25
      }
    ]
  },
  "nftables": {
    "interface": "wg-uplink",
    "tunnelNetwork": "10.200.0.0/24",
    "rules": [
      {
        "protocol": "TCP",
        "listenPort": 8080,
        "targetIP": "10.96.0.1",
        "targetPort": 80
      },
      {
        "protocol": "UDP",
        "listenPort": 9090,
        "targetIP": "10.96.0.2",
        "targetPort": 53
      }
    ]
  }
}`

// TestParse runs table-driven parse and validation tests covering both valid
// and invalid documents. Each invalid case checks that the returned error
// message contains the expected substring.
func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErr     bool
		errContains string
	}{
		// --- valid documents ---
		{
			name:    "valid relay document",
			input:   validRelayJSON,
			wantErr: false,
		},
		{
			name:    "valid uplink document with nftables",
			input:   validUplinkJSON,
			wantErr: false,
		},
		{
			name: "valid relay with zero peers",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-relay",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "listenPort": 51821,
      "address": "10.200.0.1/24"
    },
    "peers": []
  }
}`,
			wantErr: false,
		},
		{
			name: "valid interface with MTU only",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-relay",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "10.200.0.1/24",
      "mtu": 1280
    },
    "peers": []
  }
}`,
			wantErr: false,
		},
		// --- bad version ---
		{
			name: "version zero",
			input: `{
  "version": 0,
  "wireguard": {
    "interface": {
      "name": "wg-relay",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "10.200.0.1/24"
    },
    "peers": []
  }
}`,
			wantErr:     true,
			errContains: "version",
		},
		{
			name: "version too high",
			input: `{
  "version": 2,
  "wireguard": {
    "interface": {
      "name": "wg-relay",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "10.200.0.1/24"
    },
    "peers": []
  }
}`,
			wantErr:     true,
			errContains: "version",
		},
		// --- missing interface fields ---
		{
			name: "missing interface name",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "10.200.0.1/24"
    },
    "peers": []
  }
}`,
			wantErr:     true,
			errContains: "wireguard.interface.name",
		},
		{
			name: "missing private key",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-relay",
      "address": "10.200.0.1/24"
    },
    "peers": []
  }
}`,
			wantErr:     true,
			errContains: "wireguard.interface.privateKey",
		},
		{
			name: "missing address",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-relay",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv"
    },
    "peers": []
  }
}`,
			wantErr:     true,
			errContains: "wireguard.interface.address",
		},
		// --- bad CIDR ---
		{
			name: "bad interface address CIDR",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-relay",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "not-a-cidr"
    },
    "peers": []
  }
}`,
			wantErr:     true,
			errContains: "wireguard.interface.address",
		},
		{
			name: "bad AllowedIP CIDR in peer",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-relay",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "10.200.0.1/24"
    },
    "peers": [
      {
        "publicKey": "d29ybGR3b3JsZHdvcmxkd29ybGR3b3JsZHdvcmxk",
        "allowedIPs": ["not-a-cidr"]
      }
    ]
  }
}`,
			wantErr:     true,
			errContains: "allowedIPs[0]",
		},
		// --- unknown field rejected ---
		{
			name: "unknown top-level field",
			input: `{
  "version": 1,
  "unknown": "value",
  "wireguard": {
    "interface": {
      "name": "wg-relay",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "10.200.0.1/24"
    },
    "peers": []
  }
}`,
			wantErr:     true,
			errContains: "unknown",
		},
		{
			name: "unknown field inside wireguard interface",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-relay",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "10.200.0.1/24",
      "unexpected": true
    },
    "peers": []
  }
}`,
			wantErr:     true,
			errContains: "unexpected",
		},
		// --- bad nftables protocol ---
		{
			name: "bad protocol in nftables rule",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-uplink",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "10.200.0.2/32"
    },
    "peers": []
  },
  "nftables": {
    "interface": "wg-uplink",
    "tunnelNetwork": "10.200.0.0/24",
    "rules": [
      {
        "protocol": "ICMP",
        "listenPort": 8080,
        "targetIP": "10.96.0.1",
        "targetPort": 80
      }
    ]
  }
}`,
			wantErr:     true,
			errContains: "protocol",
		},
		// --- out-of-range ports ---
		{
			name: "nftables listenPort zero",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-uplink",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "10.200.0.2/32"
    },
    "peers": []
  },
  "nftables": {
    "interface": "wg-uplink",
    "tunnelNetwork": "10.200.0.0/24",
    "rules": [
      {
        "protocol": "TCP",
        "listenPort": 0,
        "targetIP": "10.96.0.1",
        "targetPort": 80
      }
    ]
  }
}`,
			wantErr:     true,
			errContains: "listenPort",
		},
		{
			name: "nftables targetPort out of range",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-uplink",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "10.200.0.2/32"
    },
    "peers": []
  },
  "nftables": {
    "interface": "wg-uplink",
    "tunnelNetwork": "10.200.0.0/24",
    "rules": [
      {
        "protocol": "UDP",
        "listenPort": 9090,
        "targetIP": "10.96.0.2",
        "targetPort": 65536
      }
    ]
  }
}`,
			wantErr:     true,
			errContains: "targetPort",
		},
		{
			name: "interface listenPort too large",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-relay",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "listenPort": 70000,
      "address": "10.200.0.1/24"
    },
    "peers": []
  }
}`,
			wantErr:     true,
			errContains: "listenPort",
		},
		// --- other peer errors ---
		{
			name: "peer with missing public key",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-relay",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "10.200.0.1/24"
    },
    "peers": [
      {
        "allowedIPs": ["10.200.0.2/32"]
      }
    ]
  }
}`,
			wantErr:     true,
			errContains: "publicKey",
		},
		{
			name: "peer with empty allowedIPs",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-relay",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "10.200.0.1/24"
    },
    "peers": [
      {
        "publicKey": "d29ybGR3b3JsZHdvcmxkd29ybGR3b3JsZHdvcmxk",
        "allowedIPs": []
      }
    ]
  }
}`,
			wantErr:     true,
			errContains: "allowedIPs",
		},
		{
			name: "peer with invalid endpoint",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-uplink",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "10.200.0.2/32"
    },
    "peers": [
      {
        "publicKey": "d29ybGR3b3JsZHdvcmxkd29ybGR3b3JsZHdvcmxk",
        "allowedIPs": ["0.0.0.0/0"],
        "endpoint": "no-port-here"
      }
    ]
  }
}`,
			wantErr:     true,
			errContains: "endpoint",
		},
		{
			name: "peer with negative persistentKeepalive",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-uplink",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "10.200.0.2/32"
    },
    "peers": [
      {
        "publicKey": "d29ybGR3b3JsZHdvcmxkd29ybGR3b3JsZHdvcmxk",
        "allowedIPs": ["0.0.0.0/0"],
        "persistentKeepalive": -1
      }
    ]
  }
}`,
			wantErr:     true,
			errContains: "persistentKeepalive",
		},
		{
			name: "invalid targetIP in nftables rule",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-uplink",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "10.200.0.2/32"
    },
    "peers": []
  },
  "nftables": {
    "interface": "wg-uplink",
    "tunnelNetwork": "10.200.0.0/24",
    "rules": [
      {
        "protocol": "TCP",
        "listenPort": 8080,
        "targetIP": "not-an-ip",
        "targetPort": 80
      }
    ]
  }
}`,
			wantErr:     true,
			errContains: "targetIP",
		},
		{
			name: "negative MTU",
			input: `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-relay",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "address": "10.200.0.1/24",
      "mtu": -1
    },
    "peers": []
  }
}`,
			wantErr:     true,
			errContains: "mtu",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := Parse([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}
			if doc == nil {
				t.Fatal("Parse() returned nil document without error")
			}
		})
	}
}

// TestRoundTrip verifies that Parse -> Marshal -> Parse produces a Document
// that is field-for-field equal to the first one. The test uses the uplink
// document because it exercises every optional section (MTU, endpoint,
// keepalive, nftables).
func TestRoundTrip(t *testing.T) {
	doc1, err := Parse([]byte(validUplinkJSON))
	if err != nil {
		t.Fatalf("first Parse failed: %v", err)
	}

	marshaled, err := doc1.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	doc2, err := Parse(marshaled)
	if err != nil {
		t.Fatalf("second Parse of marshaled output failed: %v", err)
	}

	if !reflect.DeepEqual(doc1, doc2) {
		t.Errorf("round-trip mismatch\nwant: %+v\ngot:  %+v", doc1, doc2)
	}
}

// TestMarshalValidJSON verifies that Marshal produces output that is itself
// valid JSON and can be decoded without error.
func TestMarshalValidJSON(t *testing.T) {
	doc, err := Parse([]byte(validRelayJSON))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	b, err := doc.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("Marshal returned empty bytes")
	}

	// Re-parse to confirm the output is well-formed JSON accepted by Parse.
	if _, err := Parse(b); err != nil {
		t.Errorf("Parse of Marshal output failed: %v", err)
	}
}

// TestValidateNilDocument confirms that calling Validate on a nil pointer
// returns an error rather than panicking.
func TestValidateNilDocument(t *testing.T) {
	var d *Document
	err := d.Validate()
	if err == nil {
		t.Fatal("Validate on nil document should return an error")
	}
}

// netdevRelayJSON returns a valid relay document carrying a netdev section with
// the given DisableOffloads value, so the netdev field is exercised end to end.
func netdevRelayJSON(disable bool) string {
	return `{
  "version": 1,
  "wireguard": {
    "interface": {
      "name": "wg-relay",
      "privateKey": "aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv",
      "listenPort": 51821,
      "address": "10.200.0.1/24"
    },
    "peers": []
  },
  "netdev": {
    "disableOffloads": ` + map[bool]string{true: "true", false: "false"}[disable] + `
  }
}`
}

// TestNetdevSection covers the optional netdev section in all three shapes:
// present with DisableOffloads true, present with false, and absent (nil), plus
// a marshal/parse round-trip that must preserve the section field-for-field.
func TestNetdevSection(t *testing.T) {
	// Present, true.
	docTrue, err := Parse([]byte(netdevRelayJSON(true)))
	if err != nil {
		t.Fatalf("parse netdev (true) failed: %v", err)
	}
	if docTrue.Netdev == nil {
		t.Fatal("netdev section should be present")
	}
	if !docTrue.Netdev.DisableOffloads {
		t.Fatal("netdev.disableOffloads should be true")
	}

	// Present, false.
	docFalse, err := Parse([]byte(netdevRelayJSON(false)))
	if err != nil {
		t.Fatalf("parse netdev (false) failed: %v", err)
	}
	if docFalse.Netdev == nil {
		t.Fatal("netdev section should be present even when disableOffloads is false")
	}
	if docFalse.Netdev.DisableOffloads {
		t.Fatal("netdev.disableOffloads should be false")
	}

	// Absent (nil).
	docAbsent, err := Parse([]byte(validRelayJSON))
	if err != nil {
		t.Fatalf("parse relay without netdev failed: %v", err)
	}
	if docAbsent.Netdev != nil {
		t.Fatal("netdev section should be nil when omitted")
	}

	// Round-trip: Parse -> Marshal -> Parse must preserve the section.
	marshaled, err := docTrue.Marshal()
	if err != nil {
		t.Fatalf("marshal netdev document failed: %v", err)
	}
	round, err := Parse(marshaled)
	if err != nil {
		t.Fatalf("re-parse of marshaled netdev document failed: %v", err)
	}
	if !reflect.DeepEqual(docTrue, round) {
		t.Errorf("netdev round-trip mismatch\nwant: %+v\ngot:  %+v", docTrue, round)
	}
}
