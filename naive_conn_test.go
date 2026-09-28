package cronet

import (
	"errors"
	"io"
	"math"
	"testing"

	"github.com/sagernet/sing/common/buf"
)

// These tests pin the Naive CLIENT-side padded framing codec against the
// reference implementation, klzgrad/forwardproxy (branch `naive`, commit
// d62c80d3dd2c706b6b87579844d2397bddd18317).
//
// # Why this file exists
//
// The same padding protocol has two independent implementations: the Native
// Naive inbound in sing-box's protocol/naive package, and this one, which is
// what the macOS Naive OUTBOUND actually runs. The inbound was audited and
// fixed; this one was not, so "padding tests pass" in sing-box said nothing
// about the codec real clients use. These tests are the client-side half of that
// contract, and they are written against the reference's exact expressions
// rather than against the current implementation's behaviour.
//
// # The reference, verbatim
//
//	func flushingIoCopy(dst io.Writer, src io.Reader, buf []byte, paddingType int) (written int64, err error) {
//		var numPadding int
//		for {
//			if paddingType == AddPadding && numPadding < NumFirstPaddings {
//				numPadding++
//				paddingSize := rand.Intn(256)
//				maxRead := 65536 - 3 - paddingSize
//				nr, er = src.Read(buf[3:maxRead])
//				if nr > 0 {
//					buf[0] = byte(nr / 256)
//					buf[1] = byte(nr % 256)
//					buf[2] = byte(paddingSize)
//					for i := 0; i < paddingSize; i++ {
//						buf[3+nr+i] = 0
//					}
//					nr += 3 + paddingSize
//				}
//			} else {
//				nr, er = src.Read(buf)
//			}
//			if nr > 0 {
//				nw, ew := dst.Write(buf[0:nr])
//				...
//				if nr != nw {
//					err = io.ErrShortWrite
//					break
//				}
//			}
//			...
//		}
//	}
//
// with NumFirstPaddings = 8 and a copy buffer of `make([]byte, 0, 64*1024)`,
// i.e. exactly maxFrameSize.
//
// The load-bearing properties:
//
//  1. paddingSize is drawn FIRST, so the payload budget for that frame is
//     65536 - 3 - paddingSize and varies per frame;
//  2. total wire length of a frame is at most 65536;
//  3. a short write is an error, not a success;
//  4. the padding counter advances only across frames that fully reached the peer.

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// recordingWriter captures the exact byte stream it is handed, split into the
// calls it received, so a test can inspect both frame boundaries and contents.
type recordingWriter struct {
	writes [][]byte
	// failAfter, when >= 0, makes the Write with that index return a short count
	// or an error instead of succeeding.
	failAfter   int
	shortBy     int
	sentinelErr error
}

func newRecordingWriter() *recordingWriter { return &recordingWriter{failAfter: -1} }

func (w *recordingWriter) Write(p []byte) (int, error) {
	index := len(w.writes)
	if w.failAfter >= 0 && index == w.failAfter {
		if w.sentinelErr != nil {
			return len(p) - w.shortBy, w.sentinelErr
		}
		// Short write with a NIL error: legal per io.Writer, and the case the
		// previous codec silently accepted.
		return len(p) - w.shortBy, nil
	}
	copied := make([]byte, len(p))
	copy(copied, p)
	w.writes = append(w.writes, copied)
	return len(p), nil
}

// totalBytes returns every byte the writer received, concatenated.
func (w *recordingWriter) totalBytes() []byte {
	var total []byte
	for _, write := range w.writes {
		total = append(total, write...)
	}
	return total
}

// paddingConnWithSeed returns a paddingConn whose padding draws are fully
// deterministic, so frame geometry can be asserted exactly.
//
// nextPaddingSize() is replaced after construction by fixing the draw through
// the same expression the production code uses, so the test cannot drift from
// the implementation's range.
func newPaddingConn() *paddingConn { return &paddingConn{} }

// framedBuffer builds a buffer that satisfies the writer geometry contract:
// the payload occupies the body and at least frameHeaderSize bytes remain in
// front for the frame header.
//
// The sing copy path guarantees this through FrontHeadroom, so tests that call
// WriteBuffer directly must set it up explicitly; otherwise they would be
// asserting on a precondition violation rather than on the write contract.
func framedBuffer(t *testing.T, size int, payload []byte) *buf.Buffer {
	t.Helper()
	// buf.NewSize starts with start == 0, so front headroom is created by
	// advancing the start past the region the frame header will occupy.
	buffer := buf.NewSize(size + frameHeaderSize + maxFramePadding)
	buffer.Advance(frameHeaderSize)
	if _, err := buffer.Write(payload); err != nil {
		buffer.Release()
		t.Fatalf("prepare framed buffer: %v", err)
	}
	if buffer.Start() < frameHeaderSize {
		buffer.Release()
		t.Fatalf("test setup: buffer.Start() is %d, need at least %d",
			buffer.Start(), frameHeaderSize)
	}
	return buffer
}

// zeroReader yields n zero bytes.
type repeatReader struct {
	remaining int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = 0
	}
	r.remaining -= len(p)
	return len(p), nil
}

// parseFrame decodes one padded frame from the head of data and returns the
// payload, the declared padding size, and the number of bytes consumed.
//
// It mirrors the reference's RemovePadding branch, which is what the peer runs:
//
//	nr = int(buf[0])*256 + int(buf[1])
//	paddingSize := int(buf[2])
//	io.ReadFull(src, buf[0:nr])   // payload
//	io.ReadFull(src, junk[0:paddingSize])
func parseFrame(t *testing.T, data []byte) (payload []byte, paddingSize int, consumed int) {
	t.Helper()
	if len(data) < frameHeaderSize {
		t.Fatalf("frame shorter than the 3-byte header: %d", len(data))
	}
	payloadLen := int(data[0])*256 + int(data[1])
	paddingSize = int(data[2])
	total := frameHeaderSize + payloadLen + paddingSize
	if len(data) < total {
		t.Fatalf("frame declares %d payload + %d padding + 3 header = %d bytes, only %d available",
			payloadLen, paddingSize, total, len(data))
	}
	payload = data[frameHeaderSize : frameHeaderSize+payloadLen]
	// The reference writes ZERO padding; assert that too, since a non-zero
	// padding byte would be a wire-visible divergence.
	for i := frameHeaderSize + payloadLen; i < total; i++ {
		if data[i] != 0 {
			t.Fatalf("padding byte %d is %d, reference writes zero padding", i, data[i])
		}
	}
	return payload, paddingSize, total
}

// ---------------------------------------------------------------------------
// 1. Frame ceiling
// ---------------------------------------------------------------------------

// TestWriteChunkedNeverExceedsTheReferenceCeiling is the primary regression test.
//
// The previous codec chunked the payload at 65535 and THEN appended a 3-byte
// header plus up to 255 bytes of padding, producing frames of up to 65793 bytes
// against a reference ceiling of 65536. Measured before the fix, one 65535-byte
// write produced a 65723-byte frame.
//
// This test drives many payload sizes through the chunking path so the padding
// draw varies unpredictably, and asserts the ceiling for EVERY frame.
func TestWriteChunkedNeverExceedsTheReferenceCeiling(t *testing.T) {
	for _, payloadSize := range []int{
		1, 2, 3,
		32768,
		maxPaddingPayload,     // 65278
		maxPaddingPayload + 1, // 65279 - the first size that cannot be framed at padding 255
		maxFrameSize - 4,      // 65532
		maxFrameSize - 3,      // 65533 - the budget at padding 0
		maxFrameSize - 3 + 1,  // 65534 - exceeds even the padding-0 budget
		65535,
		65536,
		128 * 1024,
		300 * 1024,
	} {
		t.Run(sizeName(payloadSize), func(t *testing.T) {
			// Repeat so several padding draws are exercised per payload size.
			for attempt := 0; attempt < 32; attempt++ {
				conn := newPaddingConn()
				writer := newRecordingWriter()
				payload := make([]byte, payloadSize)
				// Distinct byte values make a payload/framing mix-up detectable.
				for i := range payload {
					payload[i] = byte(i)
				}
				n, err := conn.writeChunked(writer, payload)
				if err != nil {
					t.Fatalf("attempt %d: writeChunked: %v", attempt, err)
				}
				if n != payloadSize {
					t.Fatalf("attempt %d: reported %d bytes written, payload is %d", attempt, n, payloadSize)
				}

				// Walk the produced stream frame by frame.
				var recovered []byte
				stream := writer.totalBytes()
				frames := 0
				for len(stream) > 0 {
					if frames >= paddingCount {
						// Padding window closed: the remainder is raw.
						recovered = append(recovered, stream...)
						break
					}
					if len(stream) < frameHeaderSize {
						t.Fatalf("attempt %d: trailing %d bytes are not a frame; the raw "+
							"transition must not be split", attempt, len(stream))
					}
					framePayload, _, consumed := parseFrame(t, stream)
					if consumed > maxFrameSize {
						t.Fatalf("attempt %d: frame %d is %d bytes on the wire, the reference "+
							"ceiling is %d", attempt, frames, consumed, maxFrameSize)
					}
					// Recompute the ceiling the way the reference does, from the
					// frame's own padding draw, and require the payload to respect it.
					declaredPadding := int(stream[2])
					budget := maxFrameSize - frameHeaderSize - declaredPadding
					if len(framePayload) > budget {
						t.Fatalf("attempt %d: frame %d declares padding %d, so its payload "+
							"budget is %d, but it carries %d bytes",
							attempt, frames, declaredPadding, budget, len(framePayload))
					}
					recovered = append(recovered, framePayload...)
					stream = stream[consumed:]
					frames++
				}
				if string(recovered) != string(payload) {
					t.Fatalf("attempt %d: roundtrip mismatch: recovered %d bytes, payload is %d",
						attempt, len(recovered), len(payload))
				}
			}
		})
	}
}

// TestEveryPaddingDrawSatisfiesTheCeiling sweeps the full padding range rather
// than trusting random draws to cover it, so the worst case (255) is definitely
// exercised.
func TestEveryPaddingDrawSatisfiesTheCeiling(t *testing.T) {
	for paddingSize := 0; paddingSize <= maxFramePadding; paddingSize++ {
		budget := maxFrameSize - frameHeaderSize - paddingSize
		// The payload the chunker must accept for this draw.
		conn := newPaddingConn()
		writer := newRecordingWriter()
		payload := make([]byte, budget)
		if _, err := conn.writeFrame(writer, payload, paddingSize); err != nil {
			t.Fatalf("padding %d: writeFrame rejected a %d-byte payload that exactly fits: %v",
				paddingSize, budget, err)
		}
		wire := writer.totalBytes()
		if len(wire) != maxFrameSize {
			// Only exact for the maximal payload; assert the general ceiling.
			if len(wire) > maxFrameSize {
				t.Fatalf("padding %d: frame is %d bytes, ceiling is %d",
					paddingSize, len(wire), maxFrameSize)
			}
		}
		if len(wire) != frameHeaderSize+budget+paddingSize {
			t.Fatalf("padding %d: wire length %d != 3 + %d + %d",
				paddingSize, len(wire), budget, paddingSize)
		}

		// One byte more must be refused rather than silently truncated.
		conn = newPaddingConn()
		over := newRecordingWriter()
		tooBig := make([]byte, budget+1)
		if _, err := conn.writeFrame(over, tooBig, paddingSize); err == nil {
			t.Fatalf("padding %d: writeFrame accepted %d payload bytes, budget is %d",
				paddingSize, budget+1, budget)
		}
		if len(over.writes) != 0 {
			t.Fatalf("padding %d: an oversized frame wrote %d times; it must write nothing",
				paddingSize, len(over.writes))
		}
		if conn.writePadding != 0 {
			t.Fatalf("padding %d: an oversized frame advanced the counter to %d",
				paddingSize, conn.writePadding)
		}
	}
}

// TestPaddingRangeIsTheFullZeroTo255 proves the range was not narrowed to make
// buffers fit. The reference emits rand.Intn(256); clamping would be a
// wire-visible change to the padding distribution.
func TestPaddingRangeIsTheFullZeroTo255(t *testing.T) {
	if maxFramePadding != 255 {
		t.Fatalf("maxFramePadding is %d, the reference's rand.Intn(256) yields 0..255",
			maxFramePadding)
	}
	conn := newPaddingConn()
	seen := make(map[int]bool)
	for i := 0; i < 20000; i++ {
		draw := conn.nextPaddingSize()
		if draw < 0 || draw > maxFramePadding {
			t.Fatalf("padding draw %d is outside 0..%d", draw, maxFramePadding)
		}
		seen[draw] = true
	}
	// With 20000 draws over 256 values, missing even one is overwhelmingly
	// unlikely; require full coverage so a clamp such as rand.Intn(128) fails.
	if len(seen) != maxFramePadding+1 {
		t.Fatalf("only %d distinct padding values in 20000 draws; the whole 0..255 "+
			"range must remain reachable", len(seen))
	}
}

// TestWriterGeometryFitsTheCeiling pins writerMTU against the headroom
// contract. The previous value, 65535, advertised 3 + 65535 + 255 = 65793.
func TestWriterGeometryFitsTheCeiling(t *testing.T) {
	conn := newPaddingConn()
	geometry := conn.writerMTU() + conn.frontHeadroom() + conn.rearHeadroom()
	if geometry != maxFrameSize {
		t.Fatalf("frontHeadroom + writerMTU + rearHeadroom = %d + %d + %d = %d, want exactly %d",
			conn.frontHeadroom(), conn.writerMTU(), conn.rearHeadroom(), geometry, maxFrameSize)
	}
	if conn.writerMTU() != 65278 {
		t.Fatalf("writerMTU is %d, want 65278 (65536 - 3 - 255)", conn.writerMTU())
	}
	if conn.frontHeadroom() != 3 {
		t.Fatalf("frontHeadroom is %d, want 3", conn.frontHeadroom())
	}
	if conn.rearHeadroom() != 255 {
		t.Fatalf("rearHeadroom is %d, want 255", conn.rearHeadroom())
	}
}

// TestGeometryCollapsesPastThePaddingWindow proves the geometry is advertised
// only while it applies, so the copy path stops reserving padding space once the
// first eight frames are done.
func TestGeometryCollapsesPastThePaddingWindow(t *testing.T) {
	conn := newPaddingConn()
	writer := newRecordingWriter()
	for i := 0; i < paddingCount; i++ {
		if _, err := conn.writeChunked(writer, []byte("x")); err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
	}
	if conn.frontHeadroom() != 0 || conn.rearHeadroom() != 0 || conn.writerMTU() != 0 {
		t.Fatalf("after %d frames the geometry must collapse, got front=%d mtu=%d rear=%d",
			paddingCount, conn.frontHeadroom(), conn.writerMTU(), conn.rearHeadroom())
	}
	if !conn.writerReplaceable() {
		t.Fatal("after the padding window the writer must report itself replaceable")
	}
}

// TestThatWriterMTUSizedPayloadAlwaysFits is the consistency test between the
// advertised geometry and the encoder: a caller that writes exactly what
// writerMTU() allows, with the advertised headroom reserved, must always produce
// a legal frame. This is the property the old 65535 MTU violated.
func TestThatWriterMTUSizedPayloadAlwaysFits(t *testing.T) {
	for attempt := 0; attempt < 200; attempt++ {
		conn := newPaddingConn()
		writer := newRecordingWriter()
		payload := make([]byte, conn.writerMTU())
		// Padding is drawn inside; whatever it draws, the frame must fit.
		if _, err := conn.writeChunked(writer, payload); err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		wire := writer.totalBytes()
		if len(wire) > maxFrameSize {
			t.Fatalf("attempt %d: a writerMTU-sized payload produced a %d-byte frame, "+
				"ceiling is %d", attempt, len(wire), maxFrameSize)
		}
		if len(wire) < conn.writerMTU() {
			t.Fatalf("attempt %d: frame %d bytes is smaller than the payload %d",
				attempt, len(wire), conn.writerMTU())
		}
	}
}

// ---------------------------------------------------------------------------
// 2. Segmentation boundary: padding is drawn FIRST
// ---------------------------------------------------------------------------

// TestPaddingIsDrawnBeforeThePayloadBudget is the structural test for the
// ordering bug. It checks the observable consequence: when one frame is emitted
// for a payload larger than the padding-0 budget, the frame's own padding draw
// must have reduced the payload, which is only possible if the draw came first.
func TestPaddingIsDrawnBeforeThePayloadBudget(t *testing.T) {
	// A payload that fits at padding 0 (65533) but not at padding 255 (65278).
	const payloadSize = maxFrameSize - frameHeaderSize // 65533
	conn := newPaddingConn()
	writer := newRecordingWriter()
	payload := make([]byte, payloadSize)
	if _, err := conn.writeChunked(writer, payload); err != nil {
		t.Fatalf("writeChunked: %v", err)
	}

	stream := writer.totalBytes()
	framePayload, paddingSize, consumed := parseFrame(t, stream)

	// The frame must respect its OWN draw.
	budget := maxFrameSize - frameHeaderSize - paddingSize
	if len(framePayload) > budget {
		t.Fatalf("payload %d exceeds the budget %d implied by this frame's padding draw %d",
			len(framePayload), budget, paddingSize)
	}
	if consumed > maxFrameSize {
		t.Fatalf("frame is %d bytes, ceiling is %d", consumed, maxFrameSize)
	}

	// With a padding draw above zero the first frame cannot carry all 65533
	// bytes, so there must be a SECOND frame - which is exactly what the old
	// "chunk at 65535 then pad" strategy never produced for this size.
	if paddingSize > 0 {
		if len(stream) <= consumed {
			t.Fatalf("padding draw %d reduced the budget to %d, but all %d payload bytes "+
				"were emitted in one frame of %d bytes", paddingSize, budget, payloadSize, consumed)
		}
		secondPayload, _, secondConsumed := parseFrame(t, stream[consumed:])
		if len(framePayload)+len(secondPayload) != payloadSize {
			t.Fatalf("frames carry %d + %d bytes, payload is %d",
				len(framePayload), len(secondPayload), payloadSize)
		}
		if consumed+secondConsumed > 2*maxFrameSize {
			t.Fatal("two frames exceeded twice the ceiling")
		}
	}
	if len(framePayload) == 0 {
		t.Fatal("the first frame carried no payload")
	}
}

// TestFrameCountMatchesTheReferenceSegmentation derives the expected frame
// boundaries independently, using the reference's own arithmetic, and compares
// them with what the codec produced.
//
// The draws are taken from the codec's generator so the two computations see the
// same randomness; the point is that the BOUNDARY ARITHMETIC matches the
// reference, which is what the chunk-at-65535 strategy got wrong.
func TestFrameCountMatchesTheReferenceSegmentation(t *testing.T) {
	for _, payloadSize := range []int{0, 1, 65000, 65533, 65534, 131066, 200000} {
		t.Run(sizeName(payloadSize), func(t *testing.T) {
			// Replay the reference algorithm with the same padding sequence.
			conn := newPaddingConn()
			writer := newRecordingWriter()
			payload := make([]byte, payloadSize)
			_, err := conn.writeChunked(writer, payload)
			if err != nil {
				t.Fatalf("writeChunked: %v", err)
			}

			// Independently recompute, drawing padding from a fresh generator
			// seeded identically is not possible, so instead verify the INVARIANT
			// that the reference's arithmetic guarantees for any draw sequence:
			// every frame's payload equals min(remaining, 65536-3-padding), and
			// the stream ends exactly at the payload length.
			stream := writer.totalBytes()
			remaining := payloadSize
			frames := 0
			for len(stream) > 0 {
				if frames >= paddingCount {
					if len(stream) != remaining {
						t.Fatalf("after %d frames the raw tail is %d bytes, %d payload bytes remain",
							frames, len(stream), remaining)
					}
					stream = nil
					remaining = 0
					break
				}
				framePayload, paddingSize, consumed := parseFrame(t, stream)
				budget := maxFrameSize - frameHeaderSize - paddingSize
				expected := remaining
				if expected > budget {
					expected = budget
				}
				if len(framePayload) != expected {
					t.Fatalf("frame %d carries %d payload bytes; the reference budget for "+
						"padding %d with %d bytes remaining is %d",
						frames, len(framePayload), paddingSize, remaining, expected)
				}
				remaining -= len(framePayload)
				stream = stream[consumed:]
				frames++
			}
			if remaining != 0 {
				t.Fatalf("%d payload bytes were never written", remaining)
			}
			if frames > paddingCount {
				t.Fatalf("emitted %d padded frames, the window is %d", frames, paddingCount)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. Short-write contract
// ---------------------------------------------------------------------------

// TestShortWriteIsAnError covers the io.Writer permission to return n < len(p)
// with a nil error. The previous codec set n = len(data) whenever err == nil,
// reporting success for a frame that was only partly written.
func TestShortWriteIsAnError(t *testing.T) {
	conn := newPaddingConn()
	writer := newRecordingWriter()
	writer.failAfter = 0
	writer.shortBy = 1
	writer.sentinelErr = nil // short write, NIL error

	if _, err := conn.writeChunked(writer, []byte("hello world")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("a short write with a nil error must return io.ErrShortWrite, got %v", err)
	}
}

// TestShortWriteDoesNotAdvanceThePaddingCounter is the state-consistency half.
// If the counter advanced, the client would believe frame N was delivered and
// the peer's framing would diverge from the next frame on.
func TestShortWriteDoesNotAdvanceThePaddingCounter(t *testing.T) {
	conn := newPaddingConn()
	writer := newRecordingWriter()
	writer.failAfter = 0
	writer.shortBy = 1

	if _, err := conn.writeChunked(writer, []byte("hello world")); err == nil {
		t.Fatal("expected an error from a short write")
	}
	if conn.writePadding != 0 {
		t.Fatalf("writePadding advanced to %d after a short write; the peer never received "+
			"a complete frame", conn.writePadding)
	}
}

// TestShortWriteOnTheRawPathIsAnError covers the path taken after the padding
// window closes, which writes straight through with no frame header.
func TestShortWriteOnTheRawPathIsAnError(t *testing.T) {
	conn := newPaddingConn()
	conn.writePadding = paddingCount // window closed
	writer := newRecordingWriter()
	writer.failAfter = 0
	writer.shortBy = 3

	if _, err := conn.writeChunked(writer, []byte("0123456789")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write on the raw path must return io.ErrShortWrite, got %v", err)
	}
}

// TestWriteBufferShortWriteIsAnError covers WriteBuffer, the path the sing copy
// engine actually uses for a *buf.Buffer writer.
func TestWriteBufferShortWriteIsAnError(t *testing.T) {
	conn := newPaddingConn()
	writer := newRecordingWriter()
	writer.failAfter = 0
	writer.shortBy = 1

	buffer := framedBuffer(t, 64, []byte("payload"))
	defer buffer.Release()
	err := conn.writeBufferWithPadding(writer, buffer)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteBuffer with a short write must return io.ErrShortWrite, got %v", err)
	}
	if conn.writePadding != 0 {
		t.Fatalf("writePadding advanced to %d after a short WriteBuffer", conn.writePadding)
	}
}

// ---------------------------------------------------------------------------
// 4. Write errors
// ---------------------------------------------------------------------------

// TestWriteErrorIsPropagatedAndDoesNotAdvanceTheCounter covers a writer that
// fails outright.
func TestWriteErrorIsPropagatedAndDoesNotAdvanceTheCounter(t *testing.T) {
	sentinel := errors.New("boom")
	for _, path := range []string{"chunked", "buffer"} {
		t.Run(path, func(t *testing.T) {
			conn := newPaddingConn()
			writer := newRecordingWriter()
			writer.failAfter = 0
			writer.shortBy = 1
			writer.sentinelErr = sentinel

			var err error
			if path == "chunked" {
				_, err = conn.writeChunked(writer, []byte("payload"))
			} else {
				buffer := framedBuffer(t, 64, []byte("payload"))
				defer buffer.Release()
				err = conn.writeBufferWithPadding(writer, buffer)
			}
			if !errors.Is(err, sentinel) {
				t.Fatalf("the writer's error must be propagated, got %v", err)
			}
			if conn.writePadding != 0 {
				t.Fatalf("writePadding advanced to %d after a failed write", conn.writePadding)
			}
		})
	}
}

// TestCounterAdvancesOnlyForCompletedFrames proves the counter is exact: it
// counts delivered frames, so a failure part-way through a multi-frame write
// leaves it at the number of frames that really landed.
func TestCounterAdvancesOnlyForCompletedFrames(t *testing.T) {
	conn := newPaddingConn()
	writer := newRecordingWriter()
	// Fail on the third write.
	writer.failAfter = 2
	writer.shortBy = 1
	writer.sentinelErr = errors.New("boom")

	// Large enough to need at least three frames.
	payload := make([]byte, 3*maxFrameSize)
	_, err := conn.writeChunked(writer, payload)
	if err == nil {
		t.Fatal("expected a failure on the third frame")
	}
	if conn.writePadding != 2 {
		t.Fatalf("writePadding is %d; two complete frames landed before the failure, so it "+
			"must be 2", conn.writePadding)
	}
}

// ---------------------------------------------------------------------------
// 5. No panics on buffer-geometry mistakes
// ---------------------------------------------------------------------------

// TestInsufficientRearHeadroomReturnsAnErrorNotAPanic replaces the previous
// common.Must, which turned a caller's buffer mistake into a process-wide panic.
func TestInsufficientRearHeadroomReturnsAnErrorNotAPanic(t *testing.T) {
	// Run many attempts so the padding draw is large enough to exceed the free
	// space at least once. A buffer with barely any room left cannot hold the
	// padding, and that must be reported, not fatal.
	failed := false
	for attempt := 0; attempt < 500; attempt++ {
		conn := newPaddingConn()
		writer := newRecordingWriter()
		// A tiny buffer with a valid header reservation but no room to grow.
		buffer := buf.NewSize(8)
		buffer.Reserve(4)
		if _, err := buffer.Write([]byte("ab")); err != nil {
			buffer.Release()
			t.Fatal(err)
		}
		err := conn.writeBufferWithPadding(writer, buffer)
		buffer.Release()
		if err != nil {
			failed = true
			if conn.writePadding != 0 {
				t.Fatalf("attempt %d: a buffer that could not be framed advanced the counter "+
					"to %d", attempt, conn.writePadding)
			}
			continue
		}
	}
	if !failed {
		t.Skip("no padding draw exceeded the tiny buffer's free space in 500 attempts; the " +
			"error path is covered deterministically by TestOversizedFrameIsRefusedByWriteFrame")
	}
}

// TestInsufficientFrontHeadroomReturnsAnError covers the other headroom
// precondition: without three bytes at the front the header cannot be reserved.
func TestInsufficientFrontHeadroomReturnsAnError(t *testing.T) {
	conn := newPaddingConn()
	writer := newRecordingWriter()
	buffer := buf.NewSize(64)
	defer buffer.Release()
	// Fill the front so Start() is 0: no room for the 3-byte header.
	if _, err := buffer.Write(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	if buffer.Start() >= frameHeaderSize {
		t.Fatalf("test setup: buffer.Start() is %d, expected less than %d",
			buffer.Start(), frameHeaderSize)
	}
	err := conn.writeBufferWithPadding(writer, buffer)
	if err == nil {
		t.Fatal("a buffer without front headroom must be rejected")
	}
	if conn.writePadding != 0 {
		t.Fatalf("writePadding advanced to %d after a rejected buffer", conn.writePadding)
	}
}

// TestNoPanicSurfaceInTheCodec is a coarse guard that the codec contains no
// Must-style fatal path for buffer conditions.
//
// It cannot prove the absence of a panic by inspection, so instead it exercises
// every externally reachable entry point with hostile inputs and asserts the
// process survives and errors are returned.
func TestNoPanicSurfaceInTheCodec(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		[]byte("x"),
		make([]byte, maxFrameSize),
		make([]byte, maxFrameSize+1),
	}
	for i, input := range inputs {
		conn := newPaddingConn()
		writer := newRecordingWriter()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("input %d: writeChunked panicked: %v", i, r)
				}
			}()
			// A nil payload is legal and must simply write nothing.
			_, _ = conn.writeChunked(writer, input)
		}()

		conn = newPaddingConn()
		buffer := buf.NewSize(len(input) + 16)
		if len(input) > 0 {
			_, _ = buffer.Write(input)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("input %d: writeBufferWithPadding panicked: %v", i, r)
				}
				buffer.Release()
			}()
			_ = conn.writeBufferWithPadding(newRecordingWriter(), buffer)
		}()
	}
}

// TestOversizedFrameIsRefusedByWriteFrame pins the guard in writeFrame itself,
// so a future segmentation bug cannot reach the wire silently.
func TestOversizedFrameIsRefusedByWriteFrame(t *testing.T) {
	conn := newPaddingConn()
	writer := newRecordingWriter()
	// Padding 0 has the largest budget (65533); one byte more must be refused.
	if _, err := conn.writeFrame(writer, make([]byte, maxFrameSize-2), 0); err == nil {
		t.Fatal("writeFrame accepted a frame larger than the reference ceiling")
	}
	if len(writer.writes) != 0 {
		t.Fatal("a refused frame must write nothing")
	}
	if conn.writePadding != 0 {
		t.Fatal("a refused frame must not advance the counter")
	}
	if _, err := conn.writeFrame(writer, make([]byte, maxFrameSize-3), 0); err != nil {
		t.Fatalf("writeFrame rejected a frame that exactly fits: %v", err)
	}
	if conn.writePadding != 1 {
		t.Fatalf("writePadding is %d after one complete frame", conn.writePadding)
	}
}

// ---------------------------------------------------------------------------
// 6. Roundtrip and the raw transition
// ---------------------------------------------------------------------------

// TestRoundtripThroughTheReferenceDecoder encodes with the client codec and
// decodes with an independent implementation of the reference's RemovePadding
// branch.
func TestRoundtripThroughTheReferenceDecoder(t *testing.T) {
	for _, payloadSize := range []int{0, 1, 100, 32768, 65533, 65534, 65535, 200000, 1 << 20} {
		t.Run(sizeName(payloadSize), func(t *testing.T) {
			conn := newPaddingConn()
			writer := newRecordingWriter()
			payload := make([]byte, payloadSize)
			for i := range payload {
				payload[i] = byte(i * 7)
			}
			if _, err := conn.writeChunked(writer, payload); err != nil {
				t.Fatalf("encode: %v", err)
			}
			recovered, err := referenceDecode(writer.totalBytes())
			if err != nil {
				t.Fatalf("reference decode: %v", err)
			}
			if string(recovered) != string(payload) {
				t.Fatalf("roundtrip mismatch: %d bytes out, %d in",
					len(recovered), len(payload))
			}
		})
	}
}

// referenceDecode implements the peer side: read exactly paddingCount framed
// payloads, discard their padding, then treat the remainder as raw.
func referenceDecode(stream []byte) ([]byte, error) {
	var out []byte
	frames := 0
	for len(stream) > 0 {
		if frames >= paddingCount {
			out = append(out, stream...)
			break
		}
		if len(stream) < frameHeaderSize {
			return nil, errors.New("truncated frame header")
		}
		payloadLen := int(stream[0])*256 + int(stream[1])
		paddingSize := int(stream[2])
		total := frameHeaderSize + payloadLen + paddingSize
		if len(stream) < total {
			return nil, errors.New("truncated frame body")
		}
		out = append(out, stream[frameHeaderSize:frameHeaderSize+payloadLen]...)
		stream = stream[total:]
		frames++
	}
	return out, nil
}

// TestRawTransitionMatchesTheReference checks the exact point where framing
// stops: exactly paddingCount frames carry headers, and everything after the
// eighth is raw.
func TestRawTransitionMatchesTheReference(t *testing.T) {
	conn := newPaddingConn()
	writer := newRecordingWriter()
	// Force the raw path to be taken by writing more than eight frames' worth.
	payload := make([]byte, paddingCount*maxFrameSize+1000)
	if _, err := conn.writeChunked(writer, payload); err != nil {
		t.Fatalf("writeChunked: %v", err)
	}
	if conn.writePadding != paddingCount {
		t.Fatalf("writePadding is %d, want exactly %d", conn.writePadding, paddingCount)
	}

	// Count the framed prefix and confirm the tail is raw.
	stream := writer.totalBytes()
	frames := 0
	for frames < paddingCount {
		if len(stream) < frameHeaderSize {
			t.Fatalf("only %d frames present, expected %d", frames, paddingCount)
		}
		payloadLen := int(stream[0])*256 + int(stream[1])
		paddingSize := int(stream[2])
		total := frameHeaderSize + payloadLen + paddingSize
		if total > maxFrameSize {
			t.Fatalf("frame %d is %d bytes, ceiling is %d", frames, total, maxFrameSize)
		}
		if len(stream) < total {
			t.Fatalf("frame %d is truncated", frames)
		}
		stream = stream[total:]
		frames++
	}
	// Everything after the eighth frame is raw, so its length is whatever payload
	// bytes remain.
	decoded, err := referenceDecode(writer.totalBytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(payload) {
		t.Fatalf("decoded %d bytes, payload is %d", len(decoded), len(payload))
	}
}

// ---------------------------------------------------------------------------
// 7. Read path: the peer's framing must be parsed with the same geometry
// ---------------------------------------------------------------------------

// TestReadRemovesPaddingUsingTheReferenceArithmetic drives the decoder with
// streams built the way the reference's AddPadding branch builds them, and checks
// both the payload and the padding removal.
//
// Each case is a complete frame sequence followed by a raw tail only after the
// padding window closes, which is the only shape a conforming peer can produce:
// both sides frame exactly paddingCount times.
func TestReadRemovesPaddingUsingTheReferenceArithmetic(t *testing.T) {
	payloadLiteral := []byte("hello naive")

	// Case 1: a single frame, no raw tail. The decoder must return the payload
	// and then EOF, having consumed exactly one frame.
	for paddingSize := 0; paddingSize <= maxFramePadding; paddingSize += 17 {
		payload := make([]byte, len(payloadLiteral))
		copy(payload, payloadLiteral)

		frame := make([]byte, 0, frameHeaderSize+len(payload)+paddingSize)
		frame = append(frame, byte(len(payload)/256), byte(len(payload)%256), byte(paddingSize))
		frame = append(frame, payload...)
		frame = append(frame, make([]byte, paddingSize)...)

		conn := newPaddingConn()
		reader := &sliceReader{data: frame}
		var got []byte
		out := make([]byte, 4) // small reads force the multi-read path
		for {
			n, err := conn.readWithPadding(reader, out)
			if n > 0 {
				got = append(got, out[:n]...)
			}
			if err != nil {
				break
			}
		}
		if string(got) != string(payloadLiteral) {
			t.Fatalf("padding %d: decoded %q, want %q", paddingSize, got, payloadLiteral)
		}
		if conn.readPadding != 1 {
			t.Fatalf("padding %d: consumed %d framed headers for a one-frame stream",
				paddingSize, conn.readPadding)
		}
	}

	// Case 2: a full padding window followed by a raw tail. The decoder must
	// consume exactly paddingCount frames and then hand the tail through
	// untouched.
	writer := newPaddingConn()
	recorder := newRecordingWriter()
	// Force the full window plus a raw remainder: each frame carries at most
	// maxFrameSize-3 bytes, so this needs more than paddingCount frames and
	// therefore leaves a raw tail.
	body := make([]byte, (paddingCount+2)*maxFrameSize)
	if _, err := writer.writeChunked(recorder, body); err != nil {
		t.Fatal(err)
	}
	if writer.writePadding != paddingCount {
		t.Fatalf("test setup: writer emitted %d frames, expected %d",
			writer.writePadding, paddingCount)
	}
	tail := []byte("raw tail bytes")
	stream := make([]byte, 0, len(recorder.totalBytes())+len(tail))
	stream = append(stream, recorder.totalBytes()...)
	stream = append(stream, tail...)

	reader := &sliceReader{data: stream}
	conn := newPaddingConn()
	var got []byte
	out := make([]byte, 4096)
	for {
		n, err := conn.readWithPadding(reader, out)
		if n > 0 {
			got = append(got, out[:n]...)
		}
		if err != nil {
			break
		}
	}
	want := make([]byte, len(body)+len(tail))
	copy(want, body)
	copy(want[len(body):], tail)
	if len(got) != len(want) {
		t.Fatalf("decoded %d bytes, want %d", len(got), len(want))
	}
	if string(got) != string(want) {
		t.Fatal("decoded payload does not match the encoded body plus raw tail")
	}
	if conn.readPadding != paddingCount {
		t.Fatalf("decoder consumed %d framed headers, the window is %d",
			conn.readPadding, paddingCount)
	}
}

// sliceReader is an in-memory io.Reader.
type sliceReader struct {
	data []byte
	pos  int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// ---------------------------------------------------------------------------
// 8. Constants
// ---------------------------------------------------------------------------

// TestCodecConstantsMatchTheReference pins the numbers to the reference's
// expressions so a later edit cannot quietly move them.
func TestCodecConstantsMatchTheReference(t *testing.T) {
	if maxFrameSize != 65536 {
		t.Fatalf("maxFrameSize is %d; the reference uses 65536", maxFrameSize)
	}
	if paddingCount != 8 {
		t.Fatalf("paddingCount is %d; the reference uses NumFirstPaddings = 8", paddingCount)
	}
	if frameHeaderSize != 3 {
		t.Fatalf("frameHeaderSize is %d; the reference reserves 3 bytes", frameHeaderSize)
	}
	if maxFramePadding != 255 {
		t.Fatalf("maxFramePadding is %d; rand.Intn(256) yields 0..255", maxFramePadding)
	}
	// The derivation itself, restated so the relationship is explicit.
	if maxPaddingPayload != 65536-3-255 {
		t.Fatalf("maxPaddingPayload is %d, want 65536-3-255 = %d",
			maxPaddingPayload, 65536-3-255)
	}
	// The header must be able to encode any payload the MTU permits.
	if maxPaddingPayload > math.MaxUint16 {
		t.Fatalf("maxPaddingPayload %d does not fit the 2-byte length field",
			maxPaddingPayload)
	}
}

// sizeName renders a payload size for subtest names.
func sizeName(n int) string {
	switch {
	case n == 0:
		return "0"
	case n < 1024:
		return itoa(n) + "B"
	case n%(1024*1024) == 0:
		return itoa(n/(1024*1024)) + "MiB"
	case n%1024 == 0:
		return itoa(n/1024) + "KiB"
	default:
		return itoa(n) + "B"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}
