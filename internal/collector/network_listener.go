package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"strconv"
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
			framer := newTCPFramer(reader)
			for {
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				message, ok, readErr := framer.Next()
				if ne, isNetErr := readErr.(net.Error); isNetErr && ne.Timeout() {
					if ctx.Err() != nil { return }
					continue
				}
				if readErr == io.EOF { return }
				if readErr != nil {
					errMu.Lock(); fmt.Fprintf(errOut, "dropped invalid TCP frame from %s: %v\n", c.RemoteAddr(), readErr); errMu.Unlock()
					return
				}
				if ok && strings.TrimSpace(message) != "" { write(message) }
			}
		}(conn)
	}
}


// tcpFramer accepts both newline-delimited messages and RFC 6587 octet-counted
// messages. Its state survives read timeouts, and every frame is size-bounded.
type tcpFramer struct {
 reader *bufio.Reader
 mode byte // 0=start, 1=line, 2=octet-count prefix, 3=octet payload
 line []byte
 prefix []byte
 frame []byte
 remaining int
}

func newTCPFramer(reader *bufio.Reader) *tcpFramer {
 return &tcpFramer{reader: reader, line: make([]byte, 0, 4096), prefix: make([]byte, 0, 12)}
}

func (f *tcpFramer) reset() {
 f.mode = 0
 f.line = f.line[:0]
 f.prefix = f.prefix[:0]
 f.frame = f.frame[:0]
 f.remaining = 0
}

func (f *tcpFramer) Next() (string, bool, error) {
 for {
  b, err := f.reader.ReadByte()
  if err != nil {
   if err == io.EOF && (f.mode == 1 || f.mode == 2) {
    if f.mode == 2 { f.line = append(f.line, f.prefix...) }
    msg := strings.TrimSpace(string(f.line)); f.reset()
    if msg != "" { return msg, true, nil }
   }
   if err == io.EOF && f.mode == 3 { return "", false, io.ErrUnexpectedEOF }
   return "", false, err
  }
  switch f.mode {
  case 0:
   if b >= '0' && b <= '9' { f.mode = 2; f.prefix = append(f.prefix, b) } else { f.mode = 1; f.line = append(f.line, b) }
  case 1:
   f.line = append(f.line, b)
   if len(f.line) > maxTCPLineBytes { return "", false, fmt.Errorf("TCP line exceeds %d bytes", maxTCPLineBytes) }
   if b == '\n' { msg := strings.TrimSpace(string(f.line)); f.reset(); return msg, msg != "", nil }
  case 2:
   if b >= '0' && b <= '9' && len(f.prefix) < 10 { f.prefix = append(f.prefix, b); continue }
   if b == ' ' {
    n, parseErr := strconv.Atoi(string(f.prefix))
    if parseErr != nil || n < 1 || n > maxTCPLineBytes { return "", false, fmt.Errorf("invalid RFC 6587 frame length %q", f.prefix) }
    f.mode, f.remaining = 3, n
    f.frame = f.frame[:0]
    continue
   }
   f.mode = 1
   f.line = append(f.line, f.prefix...)
   f.line = append(f.line, b)
   if len(f.line) > maxTCPLineBytes { return "", false, fmt.Errorf("TCP line exceeds %d bytes", maxTCPLineBytes) }
   if b == '\n' { msg := strings.TrimSpace(string(f.line)); f.reset(); return msg, msg != "", nil }
  case 3:
   f.frame = append(f.frame, b)
   f.remaining--
   if f.remaining == 0 { msg := string(f.frame); f.reset(); return msg, true, nil }
  }
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
