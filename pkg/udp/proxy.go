package udp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
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
	readPollInterval      = 200 * time.Millisecond
)

type udpSession struct {
	clientAddr   netip.AddrPort
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

type proxyServer struct {
	listener       *net.UDPConn
	defaultRemote  netip.AddrPort
	hookRunner     *luaHooks.HookRunner
	sessionTimeout time.Duration

	sessionsMu sync.Mutex
	sessions   map[netip.AddrPort]*udpSession
	wg         sync.WaitGroup
}

func newProxyServer(
	listener *net.UDPConn,
	remoteAddress string,
	hookRunner *luaHooks.HookRunner,
	sessionTimeout time.Duration,
) (*proxyServer, error) {
	if sessionTimeout <= 0 {
		sessionTimeout = defaultSessionTimeout
	}

	var defaultRemote netip.AddrPort
	if remoteAddress != "" {
		addr, err := net.ResolveUDPAddr("udp", remoteAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid remote UDP address %q: %w", remoteAddress, err)
		}
		defaultRemote = addr.AddrPort()
	}

	return &proxyServer{
		listener:       listener,
		defaultRemote:  defaultRemote,
		hookRunner:     hookRunner,
		sessionTimeout: sessionTimeout,
		sessions:       make(map[netip.AddrPort]*udpSession),
	}, nil
}

// Serve runs the UDP proxy loop on an existing UDP listener until ctx is canceled.
func Serve(
	ctx context.Context,
	listener *net.UDPConn,
	remoteAddress string,
	hookRunner *luaHooks.HookRunner,
	sessionTimeout time.Duration,
) error {
	srv, err := newProxyServer(listener, remoteAddress, hookRunner, sessionTimeout)
	if err != nil {
		return err
	}
	return srv.serve(ctx)
}

func (p *proxyServer) serve(ctx context.Context) error {
	p.wg.Go(func() {
		p.reapIdleSessions(ctx)
	})

	buf := make([]byte, maxUDPDatagramSize)
	for {
		if ctx.Err() != nil {
			p.wg.Wait()
			return nil
		}

		_ = p.listener.SetReadDeadline(time.Now().Add(readPollInterval))
		n, clientAddr, err := p.listener.ReadFromUDPAddrPort(buf)
		if err != nil {
			if isTimeoutError(err) {
				continue
			}
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				p.wg.Wait()
				return nil
			}
			return fmt.Errorf("udp read error: %w", err)
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])
		p.handleClientDatagram(ctx, clientAddr, payload)
	}
}

func (p *proxyServer) handleClientDatagram(ctx context.Context, clientAddr netip.AddrPort, payload []byte) {
	sess, ok := p.getOrCreateSession(ctx, clientAddr)
	if !ok {
		return
	}

	payload, targetAddr, ok := p.prepareClientForward(sess, payload)
	if !ok {
		return
	}

	if _, err := sess.upstreamConn.WriteToUDPAddrPort(payload, targetAddr); err != nil {
		slog.Error("Failed to forward UDP datagram", "target", targetAddr, "err", err)
	}
}

func (p *proxyServer) getOrCreateSession(ctx context.Context, clientAddr netip.AddrPort) (*udpSession, bool) {
	p.sessionsMu.Lock()
	sess, exists := p.sessions[clientAddr]
	p.sessionsMu.Unlock()

	if exists {
		sess.touch()
		return sess, true
	}

	connCtx := p.newConnectContext(clientAddr)
	if !p.authorizeSession(clientAddr, connCtx) {
		return nil, false
	}

	upstreamConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		slog.Error("Failed to open upstream UDP socket", "client", clientAddr, "err", err)
		return nil, false
	}

	sess = &udpSession{
		clientAddr:   clientAddr,
		upstreamConn: upstreamConn,
		connCtx:      connCtx,
	}
	sess.touch()

	p.sessionsMu.Lock()
	p.sessions[clientAddr] = sess
	p.sessionsMu.Unlock()

	p.wg.Go(func() {
		defer p.removeSession(sess.clientAddr)
		p.readUpstreamLoop(ctx, sess)
	})

	return sess, true
}

func (p *proxyServer) newConnectContext(clientAddr netip.AddrPort) luaHooks.ConnectContext {
	connCtx := luaHooks.ConnectContext{
		Protocol:   "udp",
		SourceIP:   clientAddr.Addr().Unmap().String(),
		SourcePort: int(clientAddr.Port()),
	}
	if p.defaultRemote.IsValid() {
		connCtx.DestinationIP = p.defaultRemote.Addr().Unmap().String()
		connCtx.DestinationPort = int(p.defaultRemote.Port())
	}
	return connCtx
}

func (p *proxyServer) authorizeSession(clientAddr netip.AddrPort, connCtx luaHooks.ConnectContext) bool {
	if p.hookRunner == nil || !p.hookRunner.HasOnConnect() {
		return true
	}
	verdict, err := p.hookRunner.CallOnConnect(connCtx)
	if err != nil {
		slog.Error("UDP on_connect hook error", "err", err)
		return false
	}
	if verdict == "DROP" {
		slog.Info("UDP session dropped by on_connect", "client", clientAddr)
		return false
	}
	return true
}

func (p *proxyServer) prepareClientForward(sess *udpSession, payload []byte) ([]byte, netip.AddrPort, bool) {
	targetAddr := p.defaultRemote
	if p.hookRunner != nil && p.hookRunner.HasOnPacketWrite() {
		res, err := p.hookRunner.CallOnPacketWrite(sess.connCtx, "client_to_remote", payload)
		if err != nil {
			slog.Error("UDP on_packet_write (client_to_remote) error", "err", err)
			return nil, netip.AddrPort{}, false
		}
		if res.Drop {
			return nil, netip.AddrPort{}, false
		}
		payload = res.Data
		targetAddr, err = resolveTargetAddr(res.DestinationIP, res.DestinationPort, p.defaultRemote)
		if err != nil {
			slog.Error("UDP target resolution failed", "err", err)
			return nil, netip.AddrPort{}, false
		}
	}

	if !targetAddr.IsValid() {
		slog.Warn("Dropping UDP packet: no destination address", "client", sess.clientAddr)
		return nil, netip.AddrPort{}, false
	}
	return payload, targetAddr, true
}

func (p *proxyServer) readUpstreamLoop(ctx context.Context, sess *udpSession) {
	buf := make([]byte, maxUDPDatagramSize)
	for {
		if ctx.Err() != nil {
			return
		}

		_ = sess.upstreamConn.SetReadDeadline(time.Now().Add(readPollInterval))
		n, remoteAddr, err := sess.upstreamConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if isTimeoutError(err) {
				continue
			}
			return
		}

		sess.touch()
		payload := make([]byte, n)
		copy(payload, buf[:n])

		if !p.forwardUpstreamDatagram(sess, remoteAddr, payload) {
			return
		}
	}
}

func (p *proxyServer) forwardUpstreamDatagram(sess *udpSession, remoteAddr netip.AddrPort, payload []byte) bool {
	payload, clientTarget, ok := p.prepareUpstreamReply(sess, remoteAddr, payload)
	if !ok {
		return true
	}

	if _, err := p.listener.WriteToUDPAddrPort(payload, clientTarget); err != nil {
		if errors.Is(err, net.ErrClosed) {
			return false
		}
		slog.Error("Failed to write UDP reply to client", "client", clientTarget, "err", err)
	}
	return true
}

func (p *proxyServer) prepareUpstreamReply(sess *udpSession, remoteAddr netip.AddrPort, payload []byte) ([]byte, netip.AddrPort, bool) {
	clientTarget := sess.clientAddr
	if p.hookRunner == nil || !p.hookRunner.HasOnPacketWrite() {
		return payload, clientTarget, true
	}

	replyCtx := sess.connCtx
	replyCtx.DestinationIP = remoteAddr.Addr().Unmap().String()
	replyCtx.DestinationPort = int(remoteAddr.Port())

	res, err := p.hookRunner.CallOnPacketWrite(replyCtx, "remote_to_client", payload)
	if err != nil {
		slog.Error("UDP on_packet_write (remote_to_client) error", "err", err)
		return nil, netip.AddrPort{}, false
	}
	if res.Drop {
		return nil, netip.AddrPort{}, false
	}
	if (res.DestinationIP != "" && res.DestinationIP != replyCtx.DestinationIP) ||
		(res.DestinationPort > 0 && res.DestinationPort != replyCtx.DestinationPort) {
		if overridden, err := resolveTargetAddr(res.DestinationIP, res.DestinationPort, sess.clientAddr); err == nil {
			clientTarget = overridden
		}
	}
	return res.Data, clientTarget, true
}

func (p *proxyServer) reapIdleSessions(ctx context.Context) {
	interval := p.sessionTimeout / 2
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.closeAllSessions()
			return
		case now := <-ticker.C:
			p.closeExpiredSessions(now.Add(-p.sessionTimeout).UnixNano())
		}
	}
}

func (p *proxyServer) removeSession(clientAddr netip.AddrPort) {
	p.sessionsMu.Lock()
	sess, ok := p.sessions[clientAddr]
	if ok {
		delete(p.sessions, clientAddr)
	}
	p.sessionsMu.Unlock()
	if ok {
		sess.close()
	}
}

func (p *proxyServer) closeAllSessions() {
	p.sessionsMu.Lock()
	defer p.sessionsMu.Unlock()
	for k, sess := range p.sessions {
		sess.close()
		delete(p.sessions, k)
	}
}

func (p *proxyServer) closeExpiredSessions(cutoff int64) {
	p.sessionsMu.Lock()
	defer p.sessionsMu.Unlock()
	for k, sess := range p.sessions {
		if sess.lastActive.Load() < cutoff {
			sess.close()
			delete(p.sessions, k)
		}
	}
}

func resolveTargetAddr(host string, port int, fallback netip.AddrPort) (netip.AddrPort, error) {
	if host != "" && port > 0 {
		if addr, err := netip.ParseAddr(host); err == nil && port <= 65535 {
			return netip.AddrPortFrom(addr, uint16(port)), nil
		}
		udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return netip.AddrPort{}, err
		}
		return udpAddr.AddrPort(), nil
	}
	if fallback.IsValid() {
		return fallback, nil
	}
	return netip.AddrPort{}, errors.New("no UDP destination address configured or provided by Lua hook")
}

func isTimeoutError(err error) bool {
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

// Run starts the standalone UDP proxy server on localAddress and forwards to remoteAddress.
func Run(ctx context.Context, localAddress, remoteAddress, scriptFile string, sessionTimeout time.Duration) {
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
