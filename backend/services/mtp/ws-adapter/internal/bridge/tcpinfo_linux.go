//go:build linux

package bridge

import (
	"net"

	"golang.org/x/sys/unix"
)

func getRTTMicros(conn *net.TCPConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var rtt uint32
	ctrlErr := raw.Control(func(fd uintptr) {
		info, e := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if e != nil {
			err = e
			return
		}
		rtt = info.Rtt
	})
	if ctrlErr != nil {
		return 0, ctrlErr
	}
	return rtt, err
}
