//go:build !windows

package probe

import (
	"net"
	"syscall"
)

func setIPv4TTL(conn *net.UDPConn, ttl int) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		socketErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	}); err != nil {
		return err
	}
	return socketErr
}
