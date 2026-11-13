// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"github.com/pion/randutil"
	"github.com/pion/rtp/codecs/vp9"
)

// Use global random generator to properly seed by crypto grade random.
var globalMathRandomGenerator = randutil.NewMathRandomGenerator() // nolint:gochecknoglobals

// VP9Payloader payloads VP9 packets.
type VP9Payloader struct {
	// whether to use flexible mode or non-flexible mode.
	FlexibleMode bool

	// InitialPictureIDFn is a function that returns random initial picture ID.
	InitialPictureIDFn func() uint16

	pictureID   uint16
	initialized bool
}

const (
	maxSpatialLayers = 5
	maxVP9RefPics    = 3
)

// Payload fragments an VP9 packet across one or more byte arrays.
func (p *VP9Payloader) Payload(mtu uint16, payload []byte) [][]byte {
	if !p.initialized {
		if p.InitialPictureIDFn == nil {
			p.InitialPictureIDFn = func() uint16 {
				return uint16(globalMathRandomGenerator.Intn(0x7FFF)) // nolint: gosec
			}
		}
		p.pictureID = p.InitialPictureIDFn() & 0x7FFF
		p.initialized = true
	}

	var payloads [][]byte
	if p.FlexibleMode {
		payloads = p.payloadFlexible(mtu, payload)
	} else {
		payloads = p.payloadNonFlexible(mtu, payload)
	}

	// A call that produced no packets does not represent a picture on the
	// wire, so it must not consume a Picture ID: receivers track gaps by the
	// IDs they actually observe, and burning an ID here makes them request a
	// refresh for a frame that was never sent.
	if len(payloads) == 0 {
		return payloads
	}

	p.pictureID++
	if p.pictureID >= 0x8000 {
		p.pictureID = 0
	}

	return payloads
}

func (p *VP9Payloader) payloadFlexible(mtu uint16, payload []byte) [][]byte {
	/*
	 * Flexible mode (F=1)
	 *        0 1 2 3 4 5 6 7
	 *       +-+-+-+-+-+-+-+-+
	 *       |I|P|L|F|B|E|V|Z| (REQUIRED)
	 *       +-+-+-+-+-+-+-+-+
	 *  I:   |M| PICTURE ID  | (REQUIRED)
	 *       +-+-+-+-+-+-+-+-+
	 *  M:   | EXTENDED PID  | (RECOMMENDED)
	 *       +-+-+-+-+-+-+-+-+
	 *  L:   | TID |U| SID |D| (CONDITIONALLY RECOMMENDED)
	 *       +-+-+-+-+-+-+-+-+                             -\
	 *  P,F: | P_DIFF      |N| (CONDITIONALLY REQUIRED)    - up to 3 times
	 *       +-+-+-+-+-+-+-+-+                             -/
	 *  V:   | SS            |
	 *       | ..            |
	 *       +-+-+-+-+-+-+-+-+
	 */

	headerSize := 3
	maxFragmentSize := int(mtu) - headerSize
	payloadDataRemaining := len(payload)
	payloadDataIndex := 0
	var payloads [][]byte

	if minInt(maxFragmentSize, payloadDataRemaining) <= 0 {
		return [][]byte{}
	}

	for payloadDataRemaining > 0 {
		currentFragmentSize := minInt(maxFragmentSize, payloadDataRemaining)
		out := make([]byte, headerSize+currentFragmentSize)

		out[0] = 0x90 // F=1, I=1
		if payloadDataIndex == 0 {
			out[0] |= 0x08 // B=1
		}
		if payloadDataRemaining == currentFragmentSize {
			out[0] |= 0x04 // E=1
		}

		out[1] = byte(p.pictureID>>8) | 0x80
		out[2] = byte(p.pictureID) //nolint:gosec

		copy(out[headerSize:], payload[payloadDataIndex:payloadDataIndex+currentFragmentSize])
		payloads = append(payloads, out)

		payloadDataRemaining -= currentFragmentSize
		payloadDataIndex += currentFragmentSize
	}

	return payloads
}

func (p *VP9Payloader) payloadNonFlexible(mtu uint16, payload []byte) [][]byte { //nolint:cyclop
	/*
	 * Non-flexible mode (F=0)
	 *        0 1 2 3 4 5 6 7
	 *       +-+-+-+-+-+-+-+-+
	 *       |I|P|L|F|B|E|V|Z| (REQUIRED)
	 *       +-+-+-+-+-+-+-+-+
	 *  I:   |M| PICTURE ID  | (RECOMMENDED)
	 *       +-+-+-+-+-+-+-+-+
	 *  M:   | EXTENDED PID  | (RECOMMENDED)
	 *       +-+-+-+-+-+-+-+-+
	 *  L:   | TID |U| SID |D| (CONDITIONALLY RECOMMENDED)
	 *       +-+-+-+-+-+-+-+-+
	 *       |   TL0PICIDX   | (CONDITIONALLY REQUIRED)
	 *       +-+-+-+-+-+-+-+-+
	 *  V:   | SS            |
	 *       | ..            |
	 *       +-+-+-+-+-+-+-+-+
	 */

	var header vp9.Header
	err := header.Unmarshal(payload)
	if err != nil {
		return [][]byte{}
	}

	// A show_existing_frame does not decode a new picture: it merely displays a
	// reference frame already held by the decoder. It therefore cannot carry a
	// scalability structure (which describes a stream's spatial layers) and is
	// treated as an inter-picture predicted frame, matching RFC 9628's rule
	// that the SS only travels in the first packet of a key picture.
	isKeyFrame := !header.NonKeyFrame && !header.ShowExistingFrame

	payloadDataRemaining := len(payload)
	payloadDataIndex := 0
	var payloads [][]byte

	for payloadDataRemaining > 0 {
		var headerSize int
		if isKeyFrame && payloadDataIndex == 0 {
			headerSize = 3 + 8
		} else {
			headerSize = 3
		}

		maxFragmentSize := int(mtu) - headerSize
		currentFragmentSize := minInt(maxFragmentSize, payloadDataRemaining)
		if currentFragmentSize <= 0 {
			return [][]byte{}
		}

		out := make([]byte, headerSize+currentFragmentSize)

		out[0] = 0x80 | 0x01 // I=1, Z=1

		if !isKeyFrame {
			out[0] |= 0x40 // P=1
		}
		if payloadDataIndex == 0 {
			out[0] |= 0x08 // B=1
		}
		if payloadDataRemaining == currentFragmentSize {
			out[0] |= 0x04 // E=1
		}

		out[1] = byte(p.pictureID>>8) | 0x80
		out[2] = byte(p.pictureID) //nolint:gosec
		off := 3

		if isKeyFrame && payloadDataIndex == 0 {
			out[0] |= 0x02         // V=1
			out[off] = 0x10 | 0x08 // N_S=0, Y=1, G=1
			off++

			width := header.Width()
			out[off] = byte(width >> 8)
			off++
			out[off] = byte(width & 0xFF)
			off++

			height := header.Height()
			out[off] = byte(height >> 8)
			off++
			out[off] = byte(height & 0xFF)
			off++

			out[off] = 0x01 // N_G=1
			off++

			out[off] = 1<<4 | 1<<2 // TID=0, U=1, R=1
			off++

			out[off] = 0x01 // P_DIFF=1
		}

		copy(out[headerSize:], payload[payloadDataIndex:payloadDataIndex+currentFragmentSize])
		payloads = append(payloads, out)

		payloadDataRemaining -= currentFragmentSize
		payloadDataIndex += currentFragmentSize
	}

	return payloads
}

// VP9Packet represents the VP9 header that is stored in the payload of an RTP Packet.
type VP9Packet struct {
	// Required header
	I bool // PictureID is present
	P bool // Inter-picture predicted frame
	L bool // Layer indices is present
	F bool // Flexible mode
	B bool // Start of a frame
	E bool // End of a frame
	V bool // Scalability structure (SS) data present
	Z bool // Not a reference frame for upper spatial layers

	// Recommended headers
	PictureID uint16 // 7 or 16 bits, picture ID

	// Conditionally recommended headers
	TID uint8 // Temporal layer ID
	U   bool  // Switching up point
	SID uint8 // Spatial layer ID
	D   bool  // Inter-layer dependency used

	// Conditionally required headers
	PDiff     []uint8 // Reference index (F=1)
	TL0PICIDX uint8   // Temporal layer zero index (F=0)

	// Scalability structure headers
	NS      uint8 // N_S + 1 indicates the number of spatial layers present in the VP9 stream
	Y       bool  // Each spatial layer's frame resolution present
	G       bool  // PG description present flag.
	NG      uint8 // N_G indicates the number of pictures in a Picture Group (PG)
	Width   []uint16
	Height  []uint16
	PGTID   []uint8   // Temporal layer ID of pictures in a Picture Group
	PGU     []bool    // Switching up point of pictures in a Picture Group
	PGPDiff [][]uint8 // Reference indecies of pictures in a Picture Group

	Payload []byte

	videoDepacketizer
}

// Unmarshal parses the passed byte slice and stores the result in the VP9Packet this method is called upon.
func (p *VP9Packet) Unmarshal(packet []byte) ([]byte, error) { // nolint:cyclop
	if packet == nil {
		return nil, errNilPacket
	}
	if len(packet) < 1 {
		return nil, errShortPacket
	}

	// Reset every parsed field before parsing so a reused packet yields exactly
	// what a fresh, zero-value packet would. Optional slices are truncated to
	// length zero while keeping their backing arrays (a nil slice stays nil),
	// and the parse helpers keep them nil until they actually hold an element.
	// Together this gives identical results to a fresh parse with no steady
	// state allocations once the largest descriptor has been seen.
	p.I = false
	p.P = false
	p.L = false
	p.F = false
	p.B = false
	p.E = false
	p.V = false
	p.Z = false
	p.PictureID = 0
	p.TID = 0
	p.U = false
	p.SID = 0
	p.D = false
	p.PDiff = p.PDiff[:0]
	p.TL0PICIDX = 0
	p.NS = 0
	p.Y = false
	p.G = false
	p.NG = 0
	p.Width = p.Width[:0]
	p.Height = p.Height[:0]
	p.PGTID = p.PGTID[:0]
	p.PGU = p.PGU[:0]
	p.PGPDiff = p.PGPDiff[:0]
	p.Payload = nil

	p.I = packet[0]&0x80 != 0
	p.P = packet[0]&0x40 != 0
	p.L = packet[0]&0x20 != 0
	p.F = packet[0]&0x10 != 0
	p.B = packet[0]&0x08 != 0
	p.E = packet[0]&0x04 != 0
	p.V = packet[0]&0x02 != 0
	p.Z = packet[0]&0x01 != 0

	pos := 1
	var err error

	if p.I {
		pos, err = p.parsePictureID(packet, pos)
		if err != nil {
			return nil, err
		}
	}

	if p.L {
		pos, err = p.parseLayerInfo(packet, pos)
		if err != nil {
			return nil, err
		}
	}

	if p.F && p.P {
		pos, err = p.parseRefIndices(packet, pos)
		if err != nil {
			return nil, err
		}
	}

	if p.V {
		pos, err = p.parseSSData(packet, pos)
		if err != nil {
			return nil, err
		}
	}

	// Normalize every empty optional slice to nil. The reset above truncates
	// previously allocated slices to length zero to retain their capacity, but
	// a zero-value packet keeps absent fields nil; folding empty slices back to
	// nil makes a reused packet identical to a fresh one without dropping the
	// backing arrays of fields that do hold elements.
	if len(p.PDiff) == 0 {
		p.PDiff = nil
	}
	if len(p.Width) == 0 {
		p.Width = nil
	}
	if len(p.Height) == 0 {
		p.Height = nil
	}
	if len(p.PGTID) == 0 {
		p.PGTID = nil
	}
	if len(p.PGU) == 0 {
		p.PGU = nil
	}
	if len(p.PGPDiff) == 0 {
		p.PGPDiff = nil
	}

	p.Payload = packet[pos:]

	return p.Payload, nil
}

// Picture ID:
/*
*      +-+-+-+-+-+-+-+-+
* I:   |M| PICTURE ID  |   M:0 => picture id is 7 bits.
*      +-+-+-+-+-+-+-+-+   M:1 => picture id is 15 bits.
* M:   | EXTENDED PID  |
*      +-+-+-+-+-+-+-+-+
**/
// .
func (p *VP9Packet) parsePictureID(packet []byte, pos int) (int, error) {
	if len(packet) <= pos {
		return pos, errShortPacket
	}

	p.PictureID = uint16(packet[pos] & 0x7F)
	if packet[pos]&0x80 != 0 {
		pos++
		if len(packet) <= pos {
			return pos, errShortPacket
		}
		p.PictureID = p.PictureID<<8 | uint16(packet[pos])
	}
	pos++

	return pos, nil
}

func (p *VP9Packet) parseLayerInfo(packet []byte, pos int) (int, error) {
	pos, err := p.parseLayerInfoCommon(packet, pos)
	if err != nil {
		return pos, err
	}

	if p.F {
		return pos, nil
	}

	return p.parseLayerInfoNonFlexibleMode(packet, pos)
}

// Layer indices (flexible mode):
/*
*      +-+-+-+-+-+-+-+-+
* L:   |  T  |U|  S  |D|
*      +-+-+-+-+-+-+-+-+
**/
// .
func (p *VP9Packet) parseLayerInfoCommon(packet []byte, pos int) (int, error) {
	if len(packet) <= pos {
		return pos, errShortPacket
	}

	p.TID = packet[pos] >> 5
	p.U = packet[pos]&0x10 != 0
	p.SID = (packet[pos] >> 1) & 0x7
	p.D = packet[pos]&0x01 != 0

	if p.SID >= maxSpatialLayers {
		return pos, errTooManySpatialLayers
	}

	pos++

	return pos, nil
}

// Layer indices (non-flexible mode):
/*
*      +-+-+-+-+-+-+-+-+
* L:   |  T  |U|  S  |D|
*      +-+-+-+-+-+-+-+-+
*      |   TL0PICIDX   |
*      +-+-+-+-+-+-+-+-+
**/
// .
func (p *VP9Packet) parseLayerInfoNonFlexibleMode(packet []byte, pos int) (int, error) {
	if len(packet) <= pos {
		return pos, errShortPacket
	}

	p.TL0PICIDX = packet[pos]
	pos++

	return pos, nil
}

// Reference indices: .
/*
*      +-+-+-+-+-+-+-+-+                P=1,F=1: At least one reference index
* P,F: | P_DIFF      |N|  up to 3 times          has to be specified.
*      +-+-+-+-+-+-+-+-+                    N=1: An additional P_DIFF follows
*                                              current P_DIFF.
*
**/
// .
func (p *VP9Packet) parseRefIndices(packet []byte, pos int) (int, error) {
	for {
		if len(packet) <= pos {
			return pos, errShortPacket
		}
		if len(p.PDiff) >= maxVP9RefPics {
			return pos, errTooManyPDiff
		}

		more := packet[pos]&0x01 != 0
		p.PDiff = appendPreserveNil(p.PDiff, packet[pos]>>1)
		pos++

		if !more {
			return pos, nil
		}
	}
}

// Scalability structure (SS):
/*
*      +-+-+-+-+-+-+-+-+
* V:   | N_S |Y|G|-|-|-|
*      +-+-+-+-+-+-+-+-+              -|
* Y:   |     WIDTH     | (OPTIONAL)    .
*      +               .
*      |               | (OPTIONAL)    .
*      +-+-+-+-+-+-+-+-+               . N_S + 1 times
*      |     HEIGHT    | (OPTIONAL)    .
*      +               .
*      |               | (OPTIONAL)    .
*      +-+-+-+-+-+-+-+-+              -|
* G:   |      N_G      | (OPTIONAL)
*      +-+-+-+-+-+-+-+-+                           -|
* N_G: |  T  |U| R |-|-| (OPTIONAL)                 .
*      +-+-+-+-+-+-+-+-+              -|            . N_G times
*      |    P_DIFF     | (OPTIONAL)    . R times    .
*      +-+-+-+-+-+-+-+-+              -|           -|
**/
// .
func (p *VP9Packet) parseSSData(packet []byte, pos int) (int, error) { // nolint: cyclop
	if len(packet) <= pos {
		return pos, errShortPacket
	}

	p.NS = packet[pos] >> 5
	p.Y = packet[pos]&0x10 != 0
	p.G = packet[pos]&0x8 != 0
	pos++

	// N_S + 1 is the number of spatial layers declared by the stream. VP9
	// implementations cannot express more than maxSpatialLayers, so a larger
	// value makes the descriptor invalid rather than silently inflating the
	// parsed layer count.
	if p.NS >= maxSpatialLayers {
		return pos, errTooManySpatialLayers
	}

	NS := p.NS + 1
	p.NG = 0

	if p.Y {
		p.Width = resizeUint16Slice(p.Width, int(NS))
		p.Height = resizeUint16Slice(p.Height, int(NS))
		for i := 0; i < int(NS); i++ {
			if len(packet) <= (pos + 3) {
				return pos, errShortPacket
			}

			p.Width[i] = uint16(packet[pos])<<8 | uint16(packet[pos+1])
			pos += 2
			p.Height[i] = uint16(packet[pos])<<8 | uint16(packet[pos+1])
			pos += 2
		}
	}

	if p.G {
		if len(packet) <= pos {
			return pos, errShortPacket
		}

		p.NG = packet[pos]
		pos++
	}

	for i := 0; i < int(p.NG); i++ {
		if len(packet) <= pos {
			return pos, errShortPacket
		}

		p.PGTID = appendPreserveNil(p.PGTID, packet[pos]>>5)
		p.PGU = appendPreserveNil(p.PGU, packet[pos]&0x10 != 0)
		reference := int((packet[pos] >> 2) & 0x3)
		pos++

		if i >= cap(p.PGPDiff) {
			p.PGPDiff = appendPreserveNil(p.PGPDiff, []uint8(nil))
		} else {
			p.PGPDiff = p.PGPDiff[:i+1]
			p.PGPDiff[i] = p.PGPDiff[i][:0]
		}

		if len(packet) <= (pos + reference - 1) {
			return pos, errShortPacket
		}

		for range reference {
			p.PGPDiff[i] = appendPreserveNil(p.PGPDiff[i], packet[pos])
			pos++
		}
	}

	return pos, nil
}

// VP9PartitionHeadChecker checks VP9 partition head.
//
// Deprecated: replaced by VP9Packet.IsPartitionHead().
type VP9PartitionHeadChecker struct{}

// IsPartitionHead checks whether if this is a head of the VP9 partition.
//
// Deprecated: replaced by VP9Packet.IsPartitionHead().
func (*VP9PartitionHeadChecker) IsPartitionHead(packet []byte) bool {
	return (&VP9Packet{}).IsPartitionHead(packet)
}

// IsPartitionHead checks whether if this is a head of the VP9 partition.
func (*VP9Packet) IsPartitionHead(payload []byte) bool {
	if len(payload) < 1 {
		return false
	}

	return (payload[0] & 0x08) != 0
}
