// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestH264Payloader_Payload(t *testing.T) {
	pck := H264Payloader{}
	smallpayload := []byte{0x90, 0x90, 0x90}
	multiplepayload := []byte{0x00, 0x00, 0x01, 0x90, 0x00, 0x00, 0x01, 0x90}
	mixednalupayload := []byte{
		0x00, 0x00, 0x01, 0x90,
		0x00, 0x00, 0x00, 0x01, 0x90,
		0x00, 0x00, 0x01, 0x90,
		0x00, 0x00, 0x00, 0x01, 0x90,
	}

	largepayload := []byte{
		0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	}
	largePayloadPacketized := [][]byte{
		{0x1c, 0x80, 0x01, 0x02, 0x03},
		{0x1c, 0x00, 0x04, 0x05, 0x06},
		{0x1c, 0x00, 0x07, 0x08, 0x09},
		{0x1c, 0x00, 0x10, 0x11, 0x12},
		{0x1c, 0x40, 0x13, 0x14, 0x15},
	}

	// Positive MTU, nil payload
	res := pck.Payload(1, nil)
	assert.Len(t, res, 0, "Generated payload should be empty")

	// Positive MTU, empty payload
	res = pck.Payload(1, []byte{})
	assert.Len(t, res, 0, "Generated payload should be empty")

	// Positive MTU, empty NAL
	res = pck.Payload(1, []byte{0x00, 0x00, 0x01})
	assert.Len(t, res, 0, "Generated payload should be empty")

	// Negative MTU, small payload
	res = pck.Payload(0, smallpayload)
	assert.Len(t, res, 0, "Generated payload should be empty")

	// 0 MTU, small payload
	res = pck.Payload(0, smallpayload)
	assert.Len(t, res, 0, "Generated payload should be empty")

	// Positive MTU, small payload
	res = pck.Payload(1, smallpayload)
	assert.Len(t, res, 0, "Generated payload should be empty")

	// Positive MTU, small payload
	res = pck.Payload(5, smallpayload)
	assert.Len(t, res, 1, "Generated payload should be the 1")
	assert.Len(t, smallpayload, len(res[0]), "Generated payload should be the same size as original payload size")

	// Multiple NALU in a single payload
	res = pck.Payload(5, multiplepayload)
	assert.Len(t, res, 2, "2 nal units should be broken out")
	for i := range 2 {
		assert.Lenf(t, res[i], 1, "Payload %d of 2 is packed incorrectly", i+1)
	}

	// Multiple NALU in a single payload with 3-byte and 4-byte start sequences
	res = pck.Payload(5, mixednalupayload)
	assert.Len(t, res, 4, "4 nal units should be broken out")
	for i := range 4 {
		assert.Lenf(t, res[i], 1, "Payload %d of 4 is packed incorrectly", i+1)
	}

	// Large Payload split across multiple RTP Packets
	res = pck.Payload(5, largepayload)
	assert.Equal(t, largePayloadPacketized, res, "FU-A packetization failed")

	// Nalu type 9 or 12
	res = pck.Payload(5, []byte{0x09, 0x00, 0x00})
	assert.Len(t, res, 0, "Generated payload should be empty")
}

func TestH264Packet_Unmarshal(t *testing.T) {
	singlePayload := []byte{0x90, 0x90, 0x90}
	singlePayloadUnmarshaled := []byte{0x00, 0x00, 0x00, 0x01, 0x90, 0x90, 0x90}
	singlePayloadUnmarshaledAVC := []byte{0x00, 0x00, 0x00, 0x03, 0x90, 0x90, 0x90}

	largepayload := []byte{
		0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	}
	largepayloadAVC := []byte{
		0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	}
	largePayloadPacketized := [][]byte{
		{0x1c, 0x80, 0x01, 0x02, 0x03},
		{0x1c, 0x00, 0x04, 0x05, 0x06},
		{0x1c, 0x00, 0x07, 0x08, 0x09},
		{0x1c, 0x00, 0x10, 0x11, 0x12},
		{0x1c, 0x40, 0x13, 0x14, 0x15},
	}

	singlePayloadMultiNALU := []byte{
		0x78, 0x00, 0x0f, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a, 0x40,
		0x3c, 0x22, 0x11, 0xa8, 0x00, 0x05, 0x68, 0x1a, 0x34, 0xe3, 0xc8,
	}
	singlePayloadMultiNALUUnmarshaled := []byte{
		0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a,
		0x40, 0x3c, 0x22, 0x11, 0xa8, 0x00, 0x00, 0x00, 0x01, 0x68, 0x1a, 0x34, 0xe3, 0xc8,
	}
	singlePayloadMultiNALUUnmarshaledAVC := []byte{
		0x00, 0x00, 0x00, 0x0f, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a,
		0x40, 0x3c, 0x22, 0x11, 0xa8, 0x00, 0x00, 0x00, 0x05, 0x68, 0x1a, 0x34, 0xe3, 0xc8,
	}
	singlePayloadWithBrokenSecondNALU := []byte{
		0x78, 0x00, 0x0f, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a, 0x40,
		0x3c, 0x22, 0x11, 0xa8, 0x00,
	}
	singlePayloadWithBrokenSecondNALUUnmarshaled := []byte{
		0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a,
		0x40, 0x3c, 0x22, 0x11, 0xa8,
	}
	singlePayloadWithBrokenSecondUnmarshaledAVC := []byte{
		0x00, 0x00, 0x00, 0x0f, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a,
		0x40, 0x3c, 0x22, 0x11, 0xa8,
	}

	incompleteSinglePayloadMultiNALU := []byte{
		0x78, 0x00, 0x0f, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a, 0x40,
		0x3c, 0x22, 0x11,
	}

	pkt := H264Packet{}
	avcPkt := H264Packet{IsAVC: true}
	_, err := pkt.Unmarshal(nil)
	assert.Error(t, err, "Unmarshal did not fail on nil payload")

	_, err = pkt.Unmarshal([]byte{})
	assert.Error(t, err, "Unmarshal did not fail on []byte{}")

	_, err = pkt.Unmarshal([]byte{0xFC})
	assert.Error(t, err, "Unmarshal accepted a FU-A packet that is too small for a payload and header")

	_, err = pkt.Unmarshal([]byte{0x0A})
	assert.NoError(t, err, "Unmarshaling end of sequence(NALU Type : 10) should succeed")

	_, err = pkt.Unmarshal([]byte{0xFF, 0x00, 0x00})
	assert.Error(t, err, "Unmarshal accepted a packet with a NALU Type we don't handle")

	_, err = pkt.Unmarshal(incompleteSinglePayloadMultiNALU)
	assert.Error(t, err, "Unmarshal accepted a STAP-A packet with insufficient data")

	res, err := pkt.Unmarshal(singlePayload)
	assert.NoError(t, err)
	assert.Equal(t, singlePayloadUnmarshaled, res)

	res, err = avcPkt.Unmarshal(singlePayload)
	assert.NoError(t, err)
	assert.Equal(t, singlePayloadUnmarshaledAVC, res)

	largePayloadResult := []byte{}
	for i := range largePayloadPacketized {
		res, err = pkt.Unmarshal(largePayloadPacketized[i])
		assert.NoError(t, err)
		largePayloadResult = append(largePayloadResult, res...)
	}
	assert.Equal(t, largepayload, largePayloadResult)

	largePayloadResultAVC := []byte{}
	for i := range largePayloadPacketized {
		res, err = avcPkt.Unmarshal(largePayloadPacketized[i])
		assert.NoError(t, err)
		largePayloadResultAVC = append(largePayloadResultAVC, res...)
	}
	assert.Equal(t, largepayloadAVC, largePayloadResultAVC)

	res, err = pkt.Unmarshal(singlePayloadMultiNALU)
	assert.NoError(t, err)
	assert.Equal(t, singlePayloadMultiNALUUnmarshaled, res)

	res, err = avcPkt.Unmarshal(singlePayloadMultiNALU)
	assert.NoError(t, err)
	assert.Equal(t, singlePayloadMultiNALUUnmarshaledAVC, res)

	res, err = pkt.Unmarshal(singlePayloadWithBrokenSecondNALU)
	assert.NoError(t, err)
	assert.Equal(t, singlePayloadWithBrokenSecondNALUUnmarshaled, res)

	res, err = avcPkt.Unmarshal(singlePayloadWithBrokenSecondNALU)
	assert.NoError(t, err)
	assert.Equal(t, singlePayloadWithBrokenSecondUnmarshaledAVC, res)
}

func TestH264IsPartitionHead(t *testing.T) {
	h264 := H264Packet{}

	assert.False(t, h264.IsPartitionHead(nil), "nil must not be a partition head")
	assert.False(t, h264.IsPartitionHead([]byte{}), "empty nalu must not be a partition head")

	singleNalu := []byte{1, 0}
	assert.True(t, h264.IsPartitionHead(singleNalu), "single nalu must be a partition head")

	stapaNalu := []byte{stapaNALUType, 0}
	assert.True(t, h264.IsPartitionHead(stapaNalu), "stapa nalu must be a partition head")

	fuaStartNalu := []byte{fuaNALUType, fuStartBitmask}
	assert.True(t, h264.IsPartitionHead(fuaStartNalu), "fua start nalu must be a partition head")

	fuaEndNalu := []byte{fuaNALUType, fuEndBitmask}
	assert.False(t, h264.IsPartitionHead(fuaEndNalu), "fua end nalu must not be a partition head")

	fubStartNalu := []byte{fubNALUType, fuStartBitmask}
	assert.True(t, h264.IsPartitionHead(fubStartNalu), "fub start nalu must be a partition head")

	fubEndNalu := []byte{fubNALUType, fuEndBitmask}
	assert.False(t, h264.IsPartitionHead(fubEndNalu), "fub end nalu must not be a partition head")
}

func TestH264IsPartitionTail(t *testing.T) {
	h264 := H264Packet{}

	assert.False(t, h264.IsPartitionTail(true, nil), "nil must not be a partition tail")
	assert.False(t, h264.IsPartitionTail(true, []byte{}), "empty nalu must not be a partition tail")

	singleNalu := []byte{1, 0}
	assert.False(t, h264.IsPartitionTail(false, singleNalu), "single nalu without marker must not be a partition tail")
	assert.True(t, h264.IsPartitionTail(true, singleNalu), "single nalu with marker must be a partition tail")

	fuaStartNalu := []byte{fuaNALUType, fuStartBitmask}
	assert.False(t, h264.IsPartitionTail(false, fuaStartNalu), "fua start nalu must not be a partition tail")
	assert.False(t, h264.IsPartitionTail(true, fuaStartNalu), "fua start nalu must not be a partition tail even with marker")

	fuaEndNalu := []byte{fuaNALUType, fuEndBitmask}
	assert.True(t, h264.IsPartitionTail(false, fuaEndNalu), "fua end nalu must be a partition tail without marker")
	assert.True(t, h264.IsPartitionTail(true, fuaEndNalu), "fua end nalu must be a partition tail with marker")

	fubEndNalu := []byte{fubNALUType, fuEndBitmask}
	assert.True(t, h264.IsPartitionTail(false, fubEndNalu), "fub end nalu must be a partition tail without marker")
}

// h264FUFragments is a fixed FU-A fragment sequence for a single NAL unit.
// The reassembled NAL unit is {0x65, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}.
func h264FUFragments() [][]byte {
	return [][]byte{
		{fuaNALUType | naluRefIdcBitmask, fuStartBitmask | 0x05, 0x01, 0x02, 0x03},
		{fuaNALUType | naluRefIdcBitmask, 0x05, 0x04, 0x05, 0x06},
		{fuaNALUType | naluRefIdcBitmask, fuEndBitmask | 0x05, 0x07},
	}
}

func TestH264Packet_Unmarshal_IncompleteFUA(t *testing.T) {
	fragments := h264FUFragments()

	// Annex B output of the whole NAL unit.
	wholeNalu := []byte{0x00, 0x00, 0x00, 0x01, 0x65, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	// AVC output of the whole NAL unit.
	wholeNaluAVC := []byte{0x00, 0x00, 0x00, 0x08, 0x65, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}

	t.Run("losing the start fragment yields no media", func(t *testing.T) {
		pkt := H264Packet{}

		for _, fragment := range fragments[1:] {
			res, err := pkt.Unmarshal(fragment)
			assert.NoError(t, err)
			assert.Empty(t, res, "a fragment without its start must not produce media")
		}
	})

	t.Run("losing the start fragment does not corrupt the next NAL", func(t *testing.T) {
		pkt := H264Packet{}

		for _, fragment := range fragments[1:] {
			_, err := pkt.Unmarshal(fragment)
			assert.NoError(t, err)
		}

		// A complete NAL unit follows the lost fragments.
		res, err := pkt.Unmarshal([]byte{stapaNALUType, 0x00, 0x02, 0x65, 0xAA})
		assert.NoError(t, err)
		assert.Equal(t, []byte("\x00\x00\x00\x01\x65\xAA"), res,
			"stale fragments must not be prepended to the next NAL unit")
	})

	t.Run("a non-FU packet terminates an unfinished fragment", func(t *testing.T) {
		pkt := H264Packet{}

		_, err := pkt.Unmarshal(fragments[0])
		assert.NoError(t, err)

		// The remaining fragments are lost and the next NAL arrives whole.
		res, err := pkt.Unmarshal([]byte{0x65, 0xAA})
		assert.NoError(t, err)
		assert.Equal(t, []byte("\x00\x00\x00\x01\x65\xAA"), res)

		// A late end fragment belongs to the abandoned NAL and must not be
		// emitted, nor must it carry the abandoned bytes.
		for _, fragment := range fragments[1:] {
			res, err = pkt.Unmarshal(fragment)
			assert.NoError(t, err)
			assert.Empty(t, res, "a fragment of an abandoned NAL must not produce media")
		}
	})

	t.Run("the start of a new fragment discards the old fragments", func(t *testing.T) {
		pkt := H264Packet{}

		_, err := pkt.Unmarshal(fragments[0])
		assert.NoError(t, err)

		// A new fragmented NAL unit starts before the previous one ended.
		res, err := pkt.Unmarshal(fragments[0])
		assert.NoError(t, err)
		assert.Empty(t, res)

		res, err = pkt.Unmarshal(fragments[1])
		assert.NoError(t, err)
		assert.Empty(t, res)

		res, err = pkt.Unmarshal(fragments[2])
		assert.NoError(t, err)
		assert.Equal(t, wholeNalu, res,
			"only the fragments of the restarted NAL unit must be emitted")
	})

	t.Run("a complete FU-A sequence reassembles", func(t *testing.T) {
		pkt := H264Packet{}

		var res []byte
		for i, fragment := range fragments {
			out, err := pkt.Unmarshal(fragment)
			assert.NoError(t, err)
			if i < len(fragments)-1 {
				assert.Empty(t, out)
			}
			res = append(res, out...)
		}
		assert.Equal(t, wholeNalu, res)
	})

	t.Run("a complete FU-A sequence reassembles as AVC", func(t *testing.T) {
		pkt := H264Packet{IsAVC: true}

		var res []byte
		for _, fragment := range fragments {
			out, err := pkt.Unmarshal(fragment)
			assert.NoError(t, err)
			res = append(res, out...)
		}
		assert.Equal(t, wholeNaluAVC, res)
	})
}

func TestH264Packet_Unmarshal_STAPA(t *testing.T) {
	pkt := H264Packet{}

	res, err := pkt.Unmarshal([]byte{
		stapaNALUType, 0x00, 0x02, 0x65, 0xAA, 0x00, 0x03, 0x41, 0xBB, 0xCC,
	})
	assert.NoError(t, err)
	assert.Equal(t, []byte{
		0x00, 0x00, 0x00, 0x01, 0x65, 0xAA,
		0x00, 0x00, 0x00, 0x01, 0x41, 0xBB, 0xCC,
	}, res)
}

func TestH264Payloader_Payload_SPS_and_PPS_handling(t *testing.T) {
	pck := H264Payloader{}
	expected := [][]byte{
		{0x78, 0x00, 0x03, 0x07, 0x00, 0x01, 0x00, 0x03, 0x08, 0x02, 0x03},
		{0x05, 0x04, 0x05},
	}

	// When packetizing SPS and PPS are emitted with following NALU
	res := pck.Payload(1500, []byte{0x07, 0x00, 0x01})
	assert.Len(t, res, 0, "Generated payload should be empty")

	res = pck.Payload(1500, []byte{0x08, 0x02, 0x03})
	assert.Len(t, res, 0, "Generated payload should be empty")
	assert.Equal(t, expected, pck.Payload(1500, []byte{0x05, 0x04, 0x05}), "SPS and PPS aren't packed together")
}

func TestH264Payloader_Payload_SPS_and_PPS_handling_no_stapA(t *testing.T) {
	pck := H264Payloader{}
	pck.DisableStapA = true

	expectedSps := []byte{0x07, 0x00, 0x01}
	// The SPS is packed as a single NALU
	res := pck.Payload(1500, expectedSps)
	assert.Len(t, res, 1, "Generated payload should not be empty")
	assert.Equal(t, expectedSps, res[0], "SPS has not been packed correctly")
	// The PPS is packed as a single NALU
	expectedPps := []byte{0x08, 0x02, 0x03}
	res = pck.Payload(1500, expectedPps)
	assert.Len(t, res, 1, "Generated payload should not be empty")
	assert.Equal(t, expectedPps, res[0], "PPS has not been packed correctly")
}
