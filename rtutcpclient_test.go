// Copyright 2014 Quoc-Viet Nguyen. All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license. See the LICENSE file for details.

package modbus

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// TestRTUTCPClientHandlerEncoding verifies the handler forwards the reused
// rtuPackager Encode/Decode/Verify methods through embedding. The expected
// CRC (0x54 0xC0) is the well-known reference vector for slave 1, func 3,
// data 50 00 00 18.
func TestRTUTCPClientHandlerEncoding(t *testing.T) {
	handler := NewRTUTCPClientHandler("127.0.0.1:0")
	handler.SlaveId = 0x01

	pdu := &ProtocolDataUnit{
		FunctionCode: FuncCodeReadHoldingRegisters,
		Data:         []byte{0x50, 0x00, 0x00, 0x18},
	}
	adu, err := handler.Encode(pdu)
	if err != nil {
		t.Fatal(err)
	}
	expected := []byte{0x01, 0x03, 0x50, 0x00, 0x00, 0x18, 0x54, 0xC0}
	if !bytes.Equal(expected, adu) {
		t.Fatalf("adu: expected %v, actual %v", expected, adu)
	}

	// Verify + Decode round-trip on the same frame.
	if err = handler.Verify(adu, adu); err != nil {
		t.Fatalf("verify: %v", err)
	}
	got, err := handler.Decode(adu)
	if err != nil {
		t.Fatal(err)
	}
	if got.FunctionCode != pdu.FunctionCode || !bytes.Equal(got.Data, pdu.Data) {
		t.Fatalf("decode mismatch: got %+v", got)
	}
}

// TestRTUTCPTransporter exercises Send against a loopback TCP echo server.
// A WriteSingleRegister RTU request has equal request/response length (8
// bytes), so an echo server returns exactly the bytes calculateResponseLength
// predicts. Also asserts the connection is closed after IdleTimeout.
func TestRTUTCPTransporter(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	client := &rtuTCPTransporter{
		tcpTransporter: tcpTransporter{
			Address:     ln.Addr().String(),
			Timeout:     1 * time.Second,
			IdleTimeout: 100 * time.Millisecond,
		},
	}

	// Build an RTU frame whose response length equals its request length.
	packager := rtuPackager{SlaveId: 0x01}
	pdu := &ProtocolDataUnit{
		FunctionCode: FuncCodeWriteSingleRegister,
		Data:         dataBlock(0x0001, 0x0003),
	}
	req, err := packager.Encode(pdu)
	if err != nil {
		t.Fatal(err)
	}

	rsp, err := client.Send(req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(req, rsp) {
		t.Fatalf("unexpected response: % x", rsp)
	}

	// Idle timeout should have closed the connection.
	time.Sleep(150 * time.Millisecond)
	if client.conn != nil {
		t.Fatalf("connection is not closed: %+v", client.conn)
	}
}

// TestRTUTCPClient guards the convenience constructor and its wiring into the
// Client interface.
func TestRTUTCPClient(t *testing.T) {
	cl := RTUTCPClient("127.0.0.1:0")
	if cl == nil {
		t.Fatal("expected non-nil client")
	}
}

// BenchmarkRTUTCPEncoder reuses rtuPackager via the handler.
func BenchmarkRTUTCPEncoder(b *testing.B) {
	handler := NewRTUTCPClientHandler("127.0.0.1:0")
	handler.SlaveId = 10
	pdu := ProtocolDataUnit{
		FunctionCode: 1,
		Data:         []byte{2, 3, 4, 5, 6, 7, 8, 9},
	}
	for i := 0; i < b.N; i++ {
		if _, err := handler.Encode(&pdu); err != nil {
			b.Fatal(err)
		}
	}
}
