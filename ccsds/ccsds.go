// Package ccsds provides functionality for decoding CCSDS (Consultative Committee for Space Data Systems) packets.
// It supports reading and parsing CCSDS packet headers and data from an io.Reader.
package ccsds

import (
	"encoding/binary"
	"errors"
	"io"
)

// Packet represents a CCSDS packet with its header and data.
type Packet struct {
	// Primary header
	Version       uint8  // Version number (3 bits)
	Type          uint8  // Packet type (1 bit): 0=Telemetry, 1=Telecommand
	SecondaryHdr  bool   // Secondary header flag
	APID          uint16 // Application Process ID (11 bits)
	SequenceFlags uint8  // Sequence flags (2 bits)
	SequenceCount uint16 // Packet sequence count (14 bits)
	DataLen       uint16 // Data length (16 bits)

	// Packet data
	Data []byte
}

// Decoder reads and decodes CCSDS packets from an input stream.
type Decoder struct {
	r io.Reader
}

// NewDecoder creates a new decoder that reads from r.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: r}
}

// ReadPacket reads and decodes a single CCSDS packet from the input stream.
func (d *Decoder) ReadPacket() (*Packet, error) {
	header := make([]byte, 6) // CCSDS primary header is 6 bytes
	_, err := io.ReadFull(d.r, header)
	if err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, err
	}

	pkt := &Packet{}

	// Parse primary header
	pkt.Version = (header[0] & 0xE0) >> 5
	pkt.Type = (header[0] & 0x10) >> 4
	pkt.SecondaryHdr = (header[0] & 0x08) != 0

	// Combine two bytes for APID (11 bits)
	pkt.APID = uint16(header[0]&0x07)<<8 | uint16(header[1])

	// Sequence control
	pkt.SequenceFlags = (header[2] & 0xC0) >> 6
	pkt.SequenceCount = binary.BigEndian.Uint16([]byte{header[2] & 0x3F, header[3]})

	// Data length (CCSDS counts data length - 1)
	// The data length field indicates the length of the data field - 1
	// So we add 1 to get the actual data length
	pkt.DataLen = binary.BigEndian.Uint16([]byte{header[4], header[5]}) + 1

	// Read packet data
	if pkt.DataLen > 0 {
		pkt.Data = make([]byte, pkt.DataLen)
		if _, err := io.ReadFull(d.r, pkt.Data); err != nil {
			return nil, err
		}
	} else {
		pkt.Data = []byte{}
	}

	return pkt, nil
}

// ReadAllPackets reads all packets from the input stream until EOF.
// It returns a slice of packets and any error encountered.
func (d *Decoder) ReadAllPackets() ([]*Packet, error) {
	var packets []*Packet

	for {
		pkt, err := d.ReadPacket()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return packets, err
		}
		packets = append(packets, pkt)
	}

	return packets, nil
}
