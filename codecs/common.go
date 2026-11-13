// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

func minInt(a, b int) int {
	if a < b {
		return a
	}

	return b
}

// audioDepacketizer is a mixin for audio codec depacketizers.
type audioDepacketizer struct{}

func (d *audioDepacketizer) IsPartitionTail(_ bool, _ []byte) bool {
	return true
}

func (d *audioDepacketizer) IsPartitionHead(_ []byte) bool {
	return true
}

// videoDepacketizer is a mixin for video codec depacketizers.
type videoDepacketizer struct {
	zeroAllocation bool
}

func (d *videoDepacketizer) IsPartitionTail(marker bool, _ []byte) bool {
	return marker
}

// SetZeroAllocation enables Zero Allocation mode for the depacketizer
// By default the Depacketizers will allocate as they parse. These allocations
// are needed for Metadata and other optional values. If you don't need this information
// enabling SetZeroAllocation gives you higher performance at a reduced feature set.
func (d *videoDepacketizer) SetZeroAllocation(zeroAllocation bool) {
	d.zeroAllocation = zeroAllocation
}

// resizeUint16Slice resizes the provided slice to the desired size, or
// allocates a new slice if needed. The contents are unspecified; the
// caller must overwrite every element. A desired size of zero always yields
// nil so a parser resetting its optional slices matches a zero-value struct.
func resizeUint16Slice(s []uint16, desiredSize int) []uint16 {
	if desiredSize == 0 {
		return nil
	}
	if cap(s) >= desiredSize {
		return s[:desiredSize]
	}

	return make([]uint16, desiredSize)
}

// appendPreserveNil appends v to s, reusing s's backing array when it has
// room. Unlike the built-in append, it keeps a nil slice nil until the first
// element is actually added. Parsers use it for optional fields so a reused
// parser that resets its slices to length zero yields exactly the same
// nil-vs-empty values as a zero-value struct, while still reusing capacity and
// avoiding per-parse allocations.
func appendPreserveNil[T any](s []T, v T) []T {
	if s == nil {
		return []T{v}
	}

	return append(s, v)
}
