package probe

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestMatchTraceICMP(t *testing.T) {
	destination := net.ParseIP("203.0.113.25").To4()
	packet := make([]byte, 8+20+8)
	packet[0] = 11 // time exceeded
	quoted := packet[8:]
	quoted[0] = 0x45
	quoted[9] = 17 // UDP
	copy(quoted[16:20], destination)
	binary.BigEndian.PutUint16(quoted[20:20+2], 49152)
	binary.BigEndian.PutUint16(quoted[20+2:20+4], 33435)
	if _, _, ok := matchTraceICMP(packet, destination, 49152, 33435); !ok {
		t.Fatal("expected matching TTL-exceeded response")
	}
	if _, _, ok := matchTraceICMP(packet, destination, 49152, 33436); ok {
		t.Fatal("response for a different probe port must not match")
	}
	if _, _, ok := matchTraceICMP(packet, destination, 49153, 33435); ok {
		t.Fatal("response for a different source port must not match")
	}
}

func TestTracerouteSkipsIPv6Destinations(t *testing.T) {
	target, err := ParseTarget("https://example.test")
	if err != nil {
		t.Fatal(err)
	}
	result := Traceroute(context.Background(), target, []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}}, 500*time.Millisecond)
	if result.Status != "skipped" {
		t.Fatalf("IPv6 target trace status = %q, want skipped", result.Status)
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		input, wantURL, wantPort string
	}{
		{"example.test", "https://example.test", "443"},
		{"http://example.test:8080/health", "http://example.test:8080/health", "8080"},
	}
	for _, test := range tests {
		target, err := ParseTarget(test.input)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", test.input, err)
		}
		if target.Value != test.wantURL || target.Port != test.wantPort {
			t.Fatalf("ParseTarget(%q) = %q port %q", test.input, target.Value, target.Port)
		}
	}
	if _, err := ParseTarget("ftp://example.test"); err == nil {
		t.Fatal("non-HTTP scheme should be rejected")
	}
}
