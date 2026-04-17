//go:build !linux

package bridge

import (
	"errors"
	"net"
)

func getRTTMicros(_ *net.TCPConn) (uint32, error) {
	return 0, errors.New("RTT measurement not supported on this platform")
}
