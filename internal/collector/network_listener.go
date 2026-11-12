package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/ingest"
)

// ListenNetwork receives line-oriented Syslog, CEF, or LEEF messages over UDP or TCP
// and writes normalized events as JSONL. It is intended for trusted LAN log forwarders.
func ListenNetwork(ctx context.Context, out io.Writer, addr, protocol, format string, errOut io.Writer) error {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	format = strings.ToLower(strings.TrimSpace(format))
	if protocol != "udp" && protocol != "tcp" {
		return fmt.Errorf("unsupported listener protocol %q (use udp or tcp)", protocol)
	}
	if format != "syslog" && format != "cef" && format != "leef" {
		return fmt.Errorf("unsupported listener format %q (use syslog, cef, or leef)", format)
	}
	if errOut == nil {
		errOut = io.Discard
	}
	var mu sync.Mutex
	write := func(payload string) {
		events, err := ingest.Read(strings.NewReader(payload), format)
		if err != nil {
			fmt.Fprintf(errOut, "ignored malformed %s message: %v\n", format, err)
			return
		}
		enc := json.NewEncoder(out)
		mu.Lock()
		defer mu.Unlock()
		for _, event := range events {
			if err := enc.Encode(event); err != nil {
				fmt.Fprintf(errOut, "write event: %v\n", err)
				return
			}
		}
	}

	if protocol == "udp" {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return fmt.Errorf("listen UDP %s: %w", addr, err)
		}
		defer pc.Close()
		buf := make([]byte, 65535)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(time.Second))
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return fmt.Errorf("receive UDP message: %w", err)
			}
			write(string(buf[:n]))
		}
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen TCP %s: %w", addr, err)
	}
	defer ln.Close()
	tcpListener, ok := ln.(*net.TCPListener)
	if !ok {
		return fmt.Errorf("unexpected TCP listener type")
	}
	var clients sync.WaitGroup
	defer clients.Wait()
	for {
		_ = tcpListener.SetDeadline(time.Now().Add(time.Second))
		conn, err := tcpListener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return fmt.Errorf("accept TCP connection: %w", err)
		}
		clients.Add(1)
		go func(c net.Conn) {
			defer clients.Done()
			defer c.Close()
			go func() {
				<-ctx.Done()
				_ = c.Close()
			}()
			reader := bufio.NewReaderSize(c, 64*1024)
			for {
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				line, readErr := reader.ReadString('\n')
				if strings.TrimSpace(line) != "" {
					write(line)
				}
				if readErr != nil {
					if ctx.Err() != nil || readErr == io.EOF {
						return
					}
					if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
						continue
					}
					fmt.Fprintf(errOut, "TCP client read: %v\n", readErr)
					return
				}
			}
		}(conn)
	}
}

// Keep os imported in this file only for a convenient explicit default in examples.
var _ = os.Stderr
