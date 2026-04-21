package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-stomp/stomp/v3/server"
	"github.com/joho/godotenv"
)

type Credentials struct {
	Login  string
	Passwd string
}

type trackedListener struct {
	net.Listener
	mu    sync.Mutex
	conns map[*trackedConn]struct{}
}

type trackedConn struct {
	net.Conn
	owner *trackedListener
	once  sync.Once
}

func (c *Credentials) Authenticate(login, passwd string) bool {

	if c.Login == "" && c.Passwd == "" {
		return true
	}

	if login != c.Login || passwd != c.Passwd {
		log.Println("CLIENT AUTH: Invalid Credentials")
		return false
	}
	return true
}

func newTrackedListener(inner net.Listener) *trackedListener {
	return &trackedListener{
		Listener: inner,
		conns:    make(map[*trackedConn]struct{}),
	}
}

func (l *trackedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	tc := &trackedConn{Conn: conn, owner: l}
	l.mu.Lock()
	l.conns[tc] = struct{}{}
	l.mu.Unlock()

	return tc, nil
}

func (l *trackedListener) shutdown() {
	_ = l.Close()

	l.mu.Lock()
	conns := make([]*trackedConn, 0, len(l.conns))
	for conn := range l.conns {
		conns = append(conns, conn)
	}
	l.mu.Unlock()

	for _, conn := range conns {
		_ = conn.SetDeadline(time.Now().Add(250 * time.Millisecond))
		_ = conn.Close()
	}
}

func (c *trackedConn) Close() error {
	var err error
	c.once.Do(func() {
		c.owner.mu.Lock()
		delete(c.owner.conns, c)
		c.owner.mu.Unlock()
		err = c.Conn.Close()
	})
	return err
}

func main() {
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading godotenv file")
	}
	localEnv := ".env.local"
	if _, err = os.Stat(localEnv); err == nil {
		_ = godotenv.Overload(localEnv)
		log.Println("Loaded variables from '.env.local'")
	} else {
		log.Println("Loaded variables from '.env'")
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	creds := Credentials{
		Login:  os.Getenv("STOMP_USERNAME"),
		Passwd: os.Getenv("STOMP_PASSWORD"),
	}

	l, err := net.Listen("tcp", server.DefaultAddr)
	if err != nil {
		log.Println("Error to open tcp port: ", err)
	}
	tracked := newTrackedListener(l)

	s := server.Server{
		Addr:          server.DefaultAddr,
		HeartBeat:     server.DefaultHeartBeat,
		Authenticator: &creds,
	}

	log.Println("Started STOMP server at port", s.Addr)
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- s.Serve(tracked)
	}()

	select {
	case sig := <-done:
		log.Printf("received shutdown signal: %v", sig)
		tracked.shutdown()
		select {
		case err = <-serveDone:
			if err != nil {
				log.Println("Error to stop stomp server: ", err)
			}
		case <-time.After(500 * time.Millisecond):
		}
	case err = <-serveDone:
		if err != nil {
			log.Println("Error to start stomp server: ", err)
		}
	}
}
