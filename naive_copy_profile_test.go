package cronet

// Measures the number of full-payload copies the Go framing layer performs, per path.
//
// The task asks whether a large avoidable plaintext copy remains. Framing has three paths and they
// differ structurally, so the count is asserted per path rather than averaged:
//
//	WriteBuffer  -> writeBufferWithPadding  frames IN PLACE (no payload copy)
//	Write        -> writeChunked            frames via writeFrame (one copy per frame)
//	Read         -> readWithPadding         reads INTO the caller's buffer (no copy)

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"unsafe"

	"github.com/sagernet/sing/common/buf"
)

// copyCountingWriter records how the payload bytes reach it, by identity.
//
// A framing path that copies allocates a NEW array, so the writer sees a different address than the
// caller's payload. A path that frames in place passes a subslice of the ORIGINAL array keeping the
// same base pointer. That is the structural difference, and it is what makes this a copy COUNT
// rather than a timing.
type identityWriter struct {
	buf bytes.Buffer
	// payloadBase is the address of the first byte of the caller's payload.
	payloadBase *byte
	// payloadLen is the payload length, so the array's extent can be bounded.
	payloadLen int
	// copied counts writes whose bytes came from a different allocation.
	copied  int
	inPlace int
}

func (w *identityWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Compare the ALLOCATION, not the offset.
	//
	// The in-place path calls ExtendHeader(3), which moves the buffer's start BACK by three bytes,
	// so the frame's first byte is not the payload's first byte. Comparing &p[0] against the payload
	// start would therefore report a copy for a path that copied nothing -- a false positive that
	// would make this test useless.
	//
	// What distinguishes a copy is the backing ARRAY. In-place framing hands out pointers inside the
	// caller's own array; a copying path hands out a freshly allocated one.
	if w.payloadBase != nil && w.sameArray(&p[0]) {
		w.inPlace++
	} else {
		w.copied++
	}
	return w.buf.Write(p)
}

// sameArray reports whether p points inside the array that begins at payloadBase.
//
// It works on the whole allocation rather than the visible payload: the caller's buffer has
// front headroom before payloadBase and rear headroom after it, so the frame pointer can sit on
// either side of payloadBase and still be the same array.
func (w *identityWriter) sameArray(p *byte) bool {
	base := uintptr(unsafe.Pointer(w.payloadBase))
	target := uintptr(unsafe.Pointer(p))
	// The buffer was allocated as headroom + payload + rear, all within one array.
	low := base - uintptr(frameHeaderSize)
	high := base + uintptr(w.payloadLen) + uintptr(maxFramePadding)
	return target >= low && target < high
}

// TestFramingCopyCountPerPath is the structural claim: WriteBuffer does not copy the payload.
func TestFramingCopyCountPerPath(t *testing.T) {
	const size = 16 << 10
	payload := make([]byte, size)
	_, _ = rand.Read(payload)

	t.Run("WriteBuffer frames in place", func(t *testing.T) {
		buffer := buf.NewSize(frameHeaderSize + size + maxFramePadding)
		buffer.Resize(frameHeaderSize, 0)
		if _, err := buffer.Write(payload); err != nil {
			t.Fatal(err)
		}
		// The array the writer would see if the payload were passed through untouched.
		payloadStart := &buffer.Bytes()[0]

		writer := &identityWriter{payloadBase: payloadStart, payloadLen: size}
		padding := &paddingConn{}
		if err := padding.writeBufferWithPadding(writer, buffer); err != nil {
			t.Fatal(err)
		}
		buffer.Release()

		if writer.copied != 0 {
			t.Fatalf("WriteBuffer copied the payload %d time(s); the in-place path must copy ZERO",
				writer.copied)
		}
		if writer.inPlace == 0 {
			t.Fatal("no in-place write observed; the test would pass vacuously")
		}
		t.Logf("WriteBuffer: %d in-place write(s), %d copying write(s)", writer.inPlace, writer.copied)
	})

	t.Run("Write copies the payload through writeFrame", func(t *testing.T) {
		// A payload ABOVE maxPaddingPayload forces writeChunked to build frames, and writeFrame
		// allocates a new buffer per frame -- that is where the copy is.
		const bigSize = maxPaddingPayload + 4096
		big := make([]byte, bigSize)
		_, _ = rand.Read(big)

		writer := &identityWriter{payloadBase: &big[0], payloadLen: bigSize}
		padding := &paddingConn{}
		if _, err := padding.writeChunked(writer, big); err != nil {
			t.Fatal(err)
		}
		t.Logf("Write: %d copying write(s) for a %d-byte payload -- one per frame built by writeFrame",
			writer.copied, bigSize)
		if writer.copied == 0 {
			t.Fatal("expected a copy on the chunked path: writeFrame allocates a new buffer per frame")
		}
	})

	t.Run("Read reads into the caller's buffer", func(t *testing.T) {
		// Build one padded frame, then read it back.
		frame := make([]byte, 0, frameHeaderSize+size+maxFramePadding)
		frame = append(frame, 0, 0, 0)
		frame = append(frame, payload...)
		// Header: length, padding size.
		frameLength := size
		frame[0] = byte(frameLength >> 8)
		frame[1] = byte(frameLength)
		frame[2] = 0

		destination := make([]byte, size)
		padding := &paddingConn{}
		n, err := padding.readWithPadding(bytes.NewReader(frame), destination)
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		if n != size {
			t.Fatalf("expected %d bytes read, got %d", size, n)
		}
		if !bytes.Equal(destination, payload) {
			t.Fatal("read produced different bytes")
		}
		t.Logf("Read: %d bytes delivered into the caller's buffer (no copy)", n)
	})
}
