package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/ingest"
)

const maxTCPLineBytes = 1 << 20
const maxTCPClients = 128

func ListenNetwork(ctx context.Context, out io.Writer, addr, protocol, format string, errOut io.Writer) error {
	return ListenNetworkWithAllowlist(ctx, out, addr, protocol, format, nil, errOut)
}

func ListenNetworkWithAllowlist(ctx context.Context, out io.Writer, addr, protocol, format string, allow []string, errOut io.Writer) error {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	format = strings.ToLower(strings.TrimSpace(format))
	if protocol != "udp" && protocol != "tcp" { return fmt.Errorf("unsupported listener protocol %q (use udp or tcp)", protocol) }
	if format != "syslog" && format != "cef" && format != "leef" { return fmt.Errorf("unsupported listener format %q (use syslog, cef, or leef)", format) }
	if errOut == nil { errOut = io.Discard }

	var mu sync.Mutex
	var errMu sync.Mutex
	write := func(payload string) {
		events, err := ingest.Read(strings.NewReader(payload), format)
		if err != nil { errMu.Lock(); fmt.Fprintf(errOut, "ignored malformed %s message: %v\n", format, err); errMu.Unlock(); return }
		enc := json.NewEncoder(out)
		mu.Lock()
		defer mu.Unlock()
		for _, event := range events {
			if err := enc.Encode(event); err != nil { errMu.Lock(); fmt.Fprintf(errOut, "write event: %v\n", err); errMu.Unlock(); return }
		}
	}

	if protocol == "udp" {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil { return fmt.Errorf("listen UDP %s: %w", addr, err) }
		defer pc.Close()
		buf := make([]byte, 65535)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(time.Second))
			n, sender, err := pc.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil { return nil }
				if ne, ok := err.(net.Error); ok && ne.Timeout() { continue }
				return fmt.Errorf("receive UDP message: %w", err)
			}
			if senderAllowed(sender, allow) { write(string(buf[:n])) }
		}
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil { return fmt.Errorf("listen TCP %s: %w", addr, err) }
	defer ln.Close()
	tcpListener, ok := ln.(*net.TCPListener)
	if !ok { return fmt.Errorf("unexpected TCP listener type") }
	var clients sync.WaitGroup
	slots := make(chan struct{}, maxTCPClients)
	defer clients.Wait()
	for {
		_ = tcpListener.SetDeadline(time.Now().Add(time.Second))
		conn, err := tcpListener.Accept()
		if err != nil {
			if ctx.Err() != nil { return nil }
			if ne, ok := err.(net.Error); ok && ne.Timeout() { continue }
			return fmt.Errorf("accept TCP connection: %w", err)
		}
		if !senderAllowed(conn.RemoteAddr(), allow) { _ = conn.Close(); continue }
		select { case slots <- struct{}{}: default: _ = conn.Close(); continue }
		clients.Add(1)
		go func(c net.Conn) {
			defer clients.Done()
			defer func(){ <-slots }()
			defer c.Close()
			reader := bufio.NewReaderSize(c, 64*1024)
			line := make([]byte, 0, 4096)
			dropping := false
			for {
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				part, readErr := reader.ReadSlice('\n')
				if dropping {
					if readErr == nil { dropping = false }
					if readErr == bufio.ErrBufferFull { continue }
					if ne, ok := readErr.(net.Error); ok && ne.Timeout() { if ctx.Err() != nil { return }; continue }
					if readErr == io.EOF || readErr != nil { return }
					continue
				}
				if len(line)+len(part) > maxTCPLineBytes {
					errMu.Lock(); fmt.Fprintf(errOut, "dropped TCP line exceeding %d bytes from %s\n", maxTCPLineBytes, c.RemoteAddr()); errMu.Unlock()
					line = line[:0]
					dropping = readErr != nil
					if readErr == nil { continue }
					if readErr == bufio.ErrBufferFull { continue }
					if ne, ok := readErr.(net.Error); ok && ne.Timeout() { if ctx.Err() != nil { return }; continue }
					return
				}
				line = append(line, part...)
				if readErr == nil {
					if len(strings.TrimSpace(string(line))) > 0 { write(string(line)) }
					line = line[:0]
					continue
				}
				if readErr == bufio.ErrBufferFull { continue }
				if ne, ok := readErr.(net.Error); ok && ne.Timeout() { if ctx.Err() != nil { return }; continue }
				if readErr == io.EOF { if len(strings.TrimSpace(string(line))) > 0 { write(string(line)) }; return }
				return
			}
		}(conn)
	}
}

func senderAllowed(addr net.Addr, allow []string) bool {
	if len(allow) == 0 { return true }
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil { host = addr.String() }
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil { return false }
	for _, entry := range allow {
		entry = strings.TrimSpace(entry)
		if entry == "" { continue }
		if candidate := net.ParseIP(entry); candidate != nil && candidate.Equal(ip) { return true }
		_, network, err := net.ParseCIDR(entry)
		if err == nil && network.Contains(ip) { return true }
	}
	return false
}
