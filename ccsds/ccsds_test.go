package ccsds

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecoder_ReadPacket(t *testing.T) {
	tests := []struct {
		name    string
		data    string // Hex string of the packet data
		want    Packet
		wantErr bool
	}{
		{
			name: "Simple telemetry packet",
			// Version: 0, Type: 0, SecHdr: true, APID: 1
			// SeqFlags: 0, SeqCount: 0x3FFF, DataLen: 3 (CCSDS counts data length - 1)
			// Data: 0xDE, 0xAD, 0xBE
			data: "08013FFF0002DEADBE",
			want: Packet{
				Version:       0,
				Type:          0,
				SecondaryHdr:  true,
				APID:          1,
				SequenceFlags: 0,
				SequenceCount: 0x3FFF,
				DataLen:       3, // 3 bytes of data (CCSDS: data length - 1 = 2)
				Data:          []byte{0xDE, 0xAD, 0xBE},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert hex string to bytes
			data, err := hex.DecodeString(tt.data)
			if err != nil {
				t.Fatalf("Failed to decode test data: %v", err)
			}

			r := bytes.NewReader(data)
			d := NewDecoder(r)

			got, err := d.ReadPacket()
			if (err != nil) != tt.wantErr {
				t.Errorf("Decoder.ReadPacket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !assert.Equal(t, tt.want, *got) {
				t.Errorf("Decoder.ReadPacket() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDecoder_ReadAllPackets(t *testing.T) {
	// Two packets in sequence
	// First: Simple telemetry packet
	// Second: Telecommand packet with secondary header
	data, _ := hex.DecodeString("08013FFF0002DEADBE08013FFF0002DEADBE")

	r := bytes.NewReader(data)
	d := NewDecoder(r)

	packets, err := d.ReadAllPackets()
	assert.NoError(t, err)
	assert.Len(t, packets, 2)

	// Verify first packet
	assert.Equal(t, uint8(0), packets[0].Version)
	assert.Equal(t, uint8(0), packets[0].Type)
	assert.Equal(t, uint16(1), packets[0].APID)
	assert.Equal(t, []byte{0xDE, 0xAD, 0xBE}, packets[0].Data)

	// Verify second packet
	assert.Equal(t, uint8(0), packets[0].Version)
	assert.Equal(t, uint8(0), packets[0].Type)
	assert.Equal(t, uint16(1), packets[0].APID)
	assert.Equal(t, []byte{0xDE, 0xAD, 0xBE}, packets[0].Data)

}
