package cronet

import (
	"crypto/rand"
	"testing"

	"github.com/sagernet/sing/common/buf"
)

// Isolate the framing call by removing the benchmark's own setup copy.
//
// The first version refilled the buffer inside the timed loop, and the profile showed 73% of the
// time in runtime.memmove -- that fill, not framing. This version keeps a pre-filled buffer and
// reframes it, so any remaining copy belongs to the framing path.
func BenchmarkNaiveFramingIsolated(b *testing.B) {
	const size = 16 << 10
	payload := make([]byte, size)
	_, _ = rand.Read(payload)

	// The capacity must cover the WORST-CASE frame: header + payload + the maximum padding draw.
	// The buffer's END must sit at header+payload so that FreeLen() is the full 255, which is what
	// the framing path requires and what rearHeadroom() advertises.
	buffer := buf.NewSize(frameHeaderSize + size + maxFramePadding)
	// Resize(start, end) takes `end` as an offset RELATIVE to start, so the visible payload is
	// bytes [start, start+end). Passing an absolute end here is an off-by-start error that would
	// silently shorten the payload and leave the wrong free space.
	buffer.Resize(frameHeaderSize, size)
	if buffer.Len() != size {
		b.Fatalf("fixture payload is %d bytes, want %d", buffer.Len(), size)
	}
	copy(buffer.Bytes(), payload)

	b.ReportAllocs()
	b.SetBytes(int64(size))
	b.ResetTimer()
	for b.Loop() {
		// Rewind to the start geometry each iteration: the previous frame consumed rear headroom
		// for its padding. The payload BYTES are never rewritten, so any copy the profile shows
		// belongs to the framing path and not to this setup.
		buffer.Resize(frameHeaderSize, size)
		padding := &paddingConn{}
		if err := padding.writeBufferWithPadding(&benchWriter{}, buffer); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	buffer.Release()
}
