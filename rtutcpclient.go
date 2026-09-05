// Copyright 2014 Quoc-Viet Nguyen. All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license. See the LICENSE file for details.

package modbus

import (
	"io"
	"time"
)

// RTUTCPClientHandler implements Packager and Transporter interface.
// It transports raw RTU frames (slave id + PDU + CRC) transparently over TCP,
// i.e. the wire format is identical to serial RTU but carried on a TCP socket
// without the Modbus TCP MBAP header.
//
// The Packager side is fully reused from rtuPackager (CRC encode/decode/verify).
// The Transporter side reuses tcpTransporter for connection management and
// overrides Send to read RTU-framed responses.
type RTUTCPClientHandler struct {
	rtuPackager
	rtuTCPTransporter
}

// NewRTUTCPClientHandler allocates and initializes a RTUTCPClientHandler.
func NewRTUTCPClientHandler(address string) *RTUTCPClientHandler {
	handler := &RTUTCPClientHandler{}
	handler.Address = address
	handler.Timeout = tcpTimeout
	handler.IdleTimeout = tcpIdleTimeout
	return handler
}

// RTUTCPClient creates an RTU-over-TCP client with the default handler and the
// given connect string.
func RTUTCPClient(address string) Client {
	handler := NewRTUTCPClientHandler(address)
	return NewClient(handler)
}

// rtuTCPTransporter implements the Transporter interface for raw RTU frames
// over TCP. It embeds tcpTransporter to reuse connection management
// (connect/close/idle timer/flush/logging) and overrides Send to read
// RTU-framed responses, which have no MBAP length field to parse.
type rtuTCPTransporter struct {
	tcpTransporter
}

// RTUTCPTransporter is the exported form of rtuTCPTransporter, mirroring the
// TcpTransporter / RtuSerialTransporter exported wrappers.
type RTUTCPTransporter struct {
	rtuTCPTransporter
}

// Send sends a raw RTU frame over TCP and reads the RTU-framed response.
//
// Unlike tcpTransporter.Send (which parses the MBAP length field to decide how
// many bytes to read), this reads the minimum RTU frame first and then reads
// the remainder based on the function code via calculateResponseLength. This
// mirrors rtuSerialTransporter.Send but drops the serial inter-frame timing
// (calculateDelay/time.Sleep), which is not required over TCP.
func (mb *rtuTCPTransporter) Send(aduRequest []byte) (aduResponse []byte, err error) {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	// Establish a new connection if not connected (reused from tcpTransporter).
	if err = mb.connect(); err != nil {
		return
	}
	// Start the timer to close when idle (reused).
	mb.lastActivity = time.Now()
	mb.startCloseTimer()
	// Set write and read timeout (reused logic).
	var timeout time.Time
	if mb.Timeout > 0 {
		timeout = mb.lastActivity.Add(mb.Timeout)
	}
	if err = mb.conn.SetDeadline(timeout); err != nil {
		return
	}
	// Send data.
	mb.logf("modbus: sending % x", aduRequest)
	if _, err = mb.conn.Write(aduRequest); err != nil {
		return
	}

	// --- RTU read logic (adapted from rtuSerialTransporter.Send, no inter-frame delay) ---
	function := aduRequest[1]
	functionFail := aduRequest[1] & 0x80
	bytesToRead := calculateResponseLength(aduRequest)

	var n int
	var data [rtuMaxSize]byte
	// Read the minimum frame first.
	n, err = io.ReadAtLeast(mb.conn, data[:], rtuMinSize)
	if err != nil {
		return
	}
	// If the function code matches, read the rest of the expected response.
	if data[1] == function {
		if n < bytesToRead {
			if bytesToRead > rtuMinSize && bytesToRead <= rtuMaxSize {
				if bytesToRead > n {
					var n1 int
					n1, err = io.ReadFull(mb.conn, data[n:bytesToRead])
					n += n1
				}
			}
		}
	} else if data[1] == functionFail {
		// Exception response is 5 bytes.
		if n < rtuExceptionSize {
			var n1 int
			n1, err = io.ReadFull(mb.conn, data[n:rtuExceptionSize])
			n += n1
		}
	}
	if err != nil {
		return
	}
	aduResponse = data[:n]
	mb.logf("modbus: received % x\n", aduResponse)
	return
}

// Compile-time interface conformance checks.
var (
	_ ClientHandler = (*RTUTCPClientHandler)(nil)
	_ Transporter   = (*rtuTCPTransporter)(nil)
)
