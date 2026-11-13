package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/iamtonmoy0/wirecase/internal/casefile"
)

const maxTraceHops = 16

type traceHop struct {
	TTL     int    `json:"ttl"`
	Address string `json:"address,omitempty"`
	RTTMS   int64  `json:"rtt_ms,omitempty"`
	Timeout bool   `json:"timeout,omitempty"`
	Reached bool   `json:"reached,omitempty"`
}

// Traceroute sends opt-in UDP probes with increasing IPv4 TTLs and listens for
// the corresponding ICMP responses. Raw ICMP socket access may require admin
// privileges. Callers should record a skipped result instead of failing a
// normal capture when that permission is unavailable.
func Traceroute(ctx context.Context, target Target, addresses []net.IPAddr, timeout time.Duration) casefile.ProbeResult {
	result := casefile.ProbeResult{Name: "trace", Status: "skipped"}
	var destination net.IP
	for _, address := range addresses {
		if v4 := address.IP.To4(); v4 != nil {
			destination = append(net.IP(nil), v4...)
			break
		}
	}
	if destination == nil {
		result.Details = map[string]any{"reason": "traceroute currently supports IPv4 targets"}
		return result
	}
	listener, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		result.Details = map[string]any{"reason": "raw ICMP socket unavailable; elevated privileges may be required"}
		return result
	}
	defer listener.Close()
	perHop := timeout / maxTraceHops
	if perHop < 50*time.Millisecond {
		perHop = 50 * time.Millisecond
	}
	start := time.Now()
	hops := make([]traceHop, 0, maxTraceHops)
	for ttl := 1; ttl <= maxTraceHops; ttl++ {
		if err := ctx.Err(); err != nil {
			result.Status, result.Error = "failed", err.Error()
			break
		}
		probePort := 33434 + ttl
		udp, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: destination, Port: probePort})
		if err != nil {
			result.Status, result.Error = "failed", err.Error()
			break
		}
		if err := setIPv4TTL(udp, ttl); err != nil {
			_ = udp.Close()
			result.Status, result.Error = "failed", fmt.Sprintf("set TTL %d: %v", ttl, err)
			break
		}
		sourcePort := udp.LocalAddr().(*net.UDPAddr).Port
		_ = listener.SetReadDeadline(time.Now().Add(perHop))
		hopStart := time.Now()
		_, writeErr := udp.Write([]byte("wirecase-trace"))
		_ = udp.Close()
		if writeErr != nil {
			result.Status, result.Error = "failed", writeErr.Error()
			break
		}
		hop := traceHop{TTL: ttl, Timeout: true}
		buffer := make([]byte, 1500)
		for {
			n, peer, readErr := listener.ReadFrom(buffer)
			if readErr != nil {
				if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
					break
				}
				result.Status, result.Error = "failed", readErr.Error()
				break
			}
			typ, code, matched := matchTraceICMP(buffer[:n], destination, sourcePort, probePort)
			if !matched {
				continue
			}
			ip, ok := peer.(*net.IPAddr)
			if !ok {
				continue
			}
			hop.Address = ip.IP.String()
			hop.RTTMS = time.Since(hopStart).Milliseconds()
			hop.Timeout = false
			hop.Reached = ip.IP.Equal(destination) && typ == 3 && code == 3
			break
		}
		hops = append(hops, hop)
		if result.Status == "failed" || hop.Reached {
			break
		}
	}
	result.DurationMS = time.Since(start).Milliseconds()
	if result.Status != "failed" {
		result.Status = "ok"
	}
	if len(hops) > 0 {
		result.Details = map[string]any{"destination": destination.String(), "hops": hops, "reached": traceReached(hops)}
	}
	if len(hops) == 0 && result.Status == "ok" {
		result.Status, result.Error = "failed", "no route probes were sent"
	}
	return result
}

func matchTraceICMP(packet []byte, destination net.IP, sourcePort, destinationPort int) (uint8, uint8, bool) {
	if len(packet) < 8+20 || (packet[0] != 3 && packet[0] != 11) {
		return 0, 0, false
	}
	quoted := packet[8:]
	if quoted[0]>>4 != 4 || quoted[9] != 17 {
		return 0, 0, false
	}
	headerLen := int(quoted[0]&0x0f) * 4
	if headerLen < 20 || len(quoted) < headerLen+8 {
		return 0, 0, false
	}
	if !net.IP(quoted[16:20]).Equal(destination) ||
		binary.BigEndian.Uint16(quoted[headerLen:headerLen+2]) != uint16(sourcePort) ||
		binary.BigEndian.Uint16(quoted[headerLen+2:headerLen+4]) != uint16(destinationPort) {
		return 0, 0, false
	}
	return packet[0], packet[1], true
}

func traceReached(hops []traceHop) bool {
	for _, hop := range hops {
		if hop.Reached {
			return true
		}
	}
	return false
}
