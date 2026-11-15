package udp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	luaHooks "github.com/mazdakn/fabricate/pkg/lua"
)

const (
	maxUDPDatagramSize    = 64 * 1024
	defaultSessionTimeout = 60 * time.Second
)

type udpSession struct {
	key          string
	clientAddr   *net.UDPAddr
	upstreamConn *net.UDPConn
	connCtx      luaHooks.ConnectContext
	lastActive   atomic.Int64
	closeOnce    sync.Once
}

func (s *udpSession) touch() {
	s.lastActive.Store(time.Now().UnixNano())
}

func (s *udpSession) close() {
	s.closeOnce.Do(func() {
		_ = s.upstreamConn.Close()
	})
}

func resolveTargetAddr(host string, port int, fallback *net.UDPAddr) (*net.UDPAddr, error) {
	if host != "" && port > 0 {
		if ip := net.ParseIP(host); ip != nil {
			return &net.UDPAddr{IP: ip, Port: port}, nil
		}
		return net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, errors.New("no UDP destination address configured or provided by Lua hook")
}

// Serve runs the UDP proxy loop on an existing UDP listener until ctx is canceled.
func Serve(
	ctx context.Context,
	listener *net.UDPConn,
	remoteAddress string,
	hookRunner *luaHooks.HookRunner,
	sessionTimeout time.Duration,
) error {
	if sessionTimeout <= 0 {
		sessionTimeout = defaultSessionTimeout
	}

	var defaultRemote *net.UDPAddr
	if remoteAddress != "" {
		var err error
		defaultRemote, err = net.ResolveUDPAddr("udp", remoteAddress)
		if err != nil {
			return fmt.Errorf("invalid remote UDP address %q: %w", remoteAddress, err)
		}
	}

	var (
		sessionsMu sync.Mutex
		sessions   = make(map[string]*udpSession)
		wg         sync.WaitGroup
	)

	removeSession := func(key string) {
		sessionsMu.Lock()
		sess, ok := sessions[key]
		if ok {
			delete(sessions, key)
		}
		sessionsMu.Unlock()
		if ok {
			sess.close()
		}
	}

	// Reaper goroutine to clean up idle sessions and close all sessions on context cancellation.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(sessionTimeout / 2)
		if sessionTimeout/2 < 10*time.Millisecond {
			ticker.Reset(10 * time.Millisecond)
		}
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				sessionsMu.Lock()
				for k, sess := range sessions {
					sess.close()
					delete(sessions, k)
				}
				sessionsMu.Unlock()
				return
			case now := <-ticker.C:
				cutoff := now.Add(-sessionTimeout).UnixNano()
				sessionsMu.Lock()
				for k, sess := range sessions {
					if sess.lastActive.Load() < cutoff {
						sess.close()
						delete(sessions, k)
					}
				}
				sessionsMu.Unlock()
			}
		}
	}()

	buf := make([]byte, maxUDPDatagramSize)
	for {
		if ctx.Err() != nil {
			wg.Wait()
			return nil
		}

		_ = listener.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, clientAddr, err := listener.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				wg.Wait()
				return nil
			}
			return fmt.Errorf("udp read error: %w", err)
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])

		key := clientAddr.String()
		sessionsMu.Lock()
		sess, exists := sessions[key]
		sessionsMu.Unlock()

		if !exists {
			connCtx := luaHooks.ConnectContext{
				Protocol:   "udp",
				SourceIP:   clientAddr.IP.String(),
				SourcePort: clientAddr.Port,
			}
			if defaultRemote != nil {
				connCtx.DestinationIP = defaultRemote.IP.String()
				connCtx.DestinationPort = defaultRemote.Port
			}

			if hookRunner != nil && hookRunner.HasOnConnect() {
				verdict, err := hookRunner.CallOnConnect(connCtx)
				if err != nil {
					slog.Error("UDP on_connect hook error", "err", err)
					continue
				}
				if verdict == "DROP" {
					slog.Info("UDP session dropped by on_connect", "client", key)
					continue
				}
			}

			upstreamConn, err := net.ListenUDP("udp", nil)
			if err != nil {
				slog.Error("Failed to open upstream UDP socket", "client", key, "err", err)
				continue
			}

			sess = &udpSession{
				key:          key,
				clientAddr:   clientAddr,
				upstreamConn: upstreamConn,
				connCtx:      connCtx,
			}
			sess.touch()

			sessionsMu.Lock()
			sessions[key] = sess
			sessionsMu.Unlock()

			wg.Add(1)
			go func(s *udpSession) {
				defer wg.Done()
				defer removeSession(s.key)
				readUpstreamLoop(ctx, listener, s, hookRunner)
			}(sess)
		} else {
			sess.touch()
		}

		targetAddr := defaultRemote
		if hookRunner != nil && hookRunner.HasOnPacketWrite() {
			res, err := hookRunner.CallOnPacketWrite(sess.connCtx, "client_to_remote", payload)
			if err != nil {
				slog.Error("UDP on_packet_write (client_to_remote) error", "err", err)
				continue
			}
			if res.Drop {
				continue
			}
			payload = res.Data
			targetAddr, err = resolveTargetAddr(res.DestinationIP, res.DestinationPort, defaultRemote)
			if err != nil {
				slog.Error("UDP target resolution failed", "err", err)
				continue
			}
		}

		if targetAddr == nil {
			slog.Warn("Dropping UDP packet: no destination address", "client", key)
			continue
		}

		if _, err := sess.upstreamConn.WriteToUDP(payload, targetAddr); err != nil {
			slog.Error("Failed to forward UDP datagram", "target", targetAddr, "err", err)
		}
	}
}

func readUpstreamLoop(
	ctx context.Context,
	listener *net.UDPConn,
	sess *udpSession,
	hookRunner *luaHooks.HookRunner,
) {
	buf := make([]byte, maxUDPDatagramSize)
	for {
		if ctx.Err() != nil {
			return
		}

		_ = sess.upstreamConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, remoteAddr, err := sess.upstreamConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		sess.touch()
		payload := make([]byte, n)
		copy(payload, buf[:n])

		replyCtx := sess.connCtx
		replyCtx.DestinationIP = remoteAddr.IP.String()
		replyCtx.DestinationPort = remoteAddr.Port

		clientTarget := sess.clientAddr
		if hookRunner != nil && hookRunner.HasOnPacketWrite() {
			res, err := hookRunner.CallOnPacketWrite(replyCtx, "remote_to_client", payload)
			if err != nil {
				slog.Error("UDP on_packet_write (remote_to_client) error", "err", err)
				continue
			}
			if res.Drop {
				continue
			}
			payload = res.Data
			if (res.DestinationIP != "" && res.DestinationIP != replyCtx.DestinationIP) ||
				(res.DestinationPort > 0 && res.DestinationPort != replyCtx.DestinationPort) {
				if overridden, err := resolveTargetAddr(res.DestinationIP, res.DestinationPort, sess.clientAddr); err == nil {
					clientTarget = overridden
				}
			}
		}

		if _, err := listener.WriteToUDP(payload, clientTarget); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Error("Failed to write UDP reply to client", "client", clientTarget, "err", err)
		}
	}
}

// Run starts the standalone UDP proxy server on localAddress and forwards to remoteAddress.
func Run(ctx context.Context, wg *sync.WaitGroup, localAddress, remoteAddress, scriptFile string, sessionTimeout time.Duration) {
	defer wg.Done()

	var hookRunner *luaHooks.HookRunner
	if scriptFile != "" {
		var err error
		hookRunner, err = luaHooks.NewHookRunner(scriptFile)
		if err != nil {
			slog.Error("Failed to initialize lua script for UDP proxy", "err", err)
			os.Exit(1)
		}
		defer hookRunner.Close()
	}

	localAddr, err := net.ResolveUDPAddr("udp", localAddress)
	if err != nil {
		slog.Error("Invalid UDP local address", "address", localAddress, "err", err)
		os.Exit(1)
	}

	listener, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		slog.Error("Failed to listen on UDP", "address", localAddress, "err", err)
		os.Exit(1)
	}
	defer listener.Close() //nolint: errcheck

	slog.Info("Fabricate UDP proxy listening", "address", listener.LocalAddr(), "remote", remoteAddress)
	if err := Serve(ctx, listener, remoteAddress, hookRunner, sessionTimeout); err != nil {
		slog.Error("UDP server failed", "err", err)
		os.Exit(1)
	}
}
