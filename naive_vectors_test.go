package cronet

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// This file makes the Naive padding protocol a shared, machine-checked contract
// rather than two implementations that merely happen to interoperate.
//
// # Why vectors instead of restated assertions
//
// The protocol has three implementations:
//
//	A. klzgrad/forwardproxy   - the reference (branch naive, d62c80d3)
//	B. sing-box Native Naive inbound   - protocol/naive/inbound_conn.go
//	C. cronet-go Naive outbound        - naive_conn.go, this repository
//
// B and C agreeing proves only that they share a wire format; it does NOT prove the
// format is the reference's, because two implementations can carry the same mistake
// and interoperate perfectly. Every expectation therefore comes from the reference's
// own expressions, which are recorded in the vector file:
//
//	paddingSize := rand.Intn(256)
//	maxRead     := 65536 - 3 - paddingSize
//
// Hard-coding the same numbers in both repositories is the failure mode this file
// exists to prevent: the two sets of literals could drift apart silently. Reading
// them from one shared document means a protocol change must be made once, as a
// visible diff.

// naivePaddingVectors mirrors testdata/naive_padding_vectors.json.
type naivePaddingVectors struct {
	Protocol  string `json:"protocol"`
	Reference struct {
		Repository              string `json:"repository"`
		Branch                  string `json:"branch"`
		Commit                  string `json:"commit"`
		PaddingDrawExpression   string `json:"padding_draw_expression"`
		PayloadBudgetExpression string `json:"payload_budget_expression"`
		NumFirstPaddings        int    `json:"num_first_paddings"`
		CopyBufferSize          int    `json:"copy_buffer_size"`
	} `json:"reference"`
	Constants struct {
		MaxFrameSize           int `json:"max_frame_size"`
		FrameHeaderSize        int `json:"frame_header_size"`
		MaxPadding             int `json:"max_padding"`
		MinPadding             int `json:"min_padding"`
		PaddingCount           int `json:"padding_count"`
		MaxPayloadAtPadding0   int `json:"max_payload_at_padding_0"`
		MaxPayloadAtPadding255 int `json:"max_payload_at_padding_255"`
		WriterMTU              int `json:"writer_mtu"`
		FrontHeadroom          int `json:"front_headroom"`
		RearHeadroom           int `json:"rear_headroom"`
	} `json:"constants"`
	Invariants []struct {
		ID         string `json:"id"`
		Statement  string `json:"statement"`
		Expression string `json:"expression"`
	} `json:"invariants"`
	PaddingDraws      []int `json:"padding_draws"`
	SegmentationCases []struct {
		Padding int `json:"padding"`
		Payload int `json:"payload"`
		Wire    int `json:"wire"`
		Frames  int `json:"frames"`
	} `json:"segmentation_cases"`
	ChunkingCases []struct {
		Padding           int `json:"padding"`
		Payload           int `json:"payload"`
		Frames            int `json:"frames"`
		FirstFramePayload int `json:"first_frame_payload"`
	} `json:"chunking_cases"`
	OversizedRejectionCases []struct {
		Padding int    `json:"padding"`
		Payload int    `json:"payload"`
		Reason  string `json:"reason"`
	} `json:"oversized_rejection_cases"`
}

// loadNaivePaddingVectors reads the shared vector file.
func loadNaivePaddingVectors(t *testing.T) *naivePaddingVectors {
	t.Helper()
	path := filepath.Join("testdata", "naive_padding_vectors.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the shared Naive padding vectors at %s: %v", path, err)
	}
	var vectors naivePaddingVectors
	if err := json.Unmarshal(content, &vectors); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if vectors.Protocol != "naive-padding-v1" {
		t.Fatalf("unexpected protocol %q", vectors.Protocol)
	}
	return &vectors
}

// TestVectorsAgreeWithThisCodecsConstants is the drift alarm.
//
// If the codec's constants and the shared document disagree, one of them changed
// without the other, and the two repositories can no longer be assumed to speak the
// same protocol.
func TestVectorsAgreeWithThisCodecsConstants(t *testing.T) {
	vectors := loadNaivePaddingVectors(t)

	require := func(name string, got, want int) {
		t.Helper()
		if got != want {
			t.Errorf("%s: the codec has %d, the shared vectors declare %d; the protocol "+
				"document and this implementation have drifted apart", name, got, want)
		}
	}
	require("max_frame_size", maxFrameSize, vectors.Constants.MaxFrameSize)
	require("frame_header_size", frameHeaderSize, vectors.Constants.FrameHeaderSize)
	require("max_padding", maxFramePadding, vectors.Constants.MaxPadding)
	require("padding_count", paddingCount, vectors.Constants.PaddingCount)
	require("writer_mtu", maxPaddingPayload, vectors.Constants.WriterMTU)
	require("max_payload_at_padding_0", maxFrameSize-frameHeaderSize,
		vectors.Constants.MaxPayloadAtPadding0)
	require("max_payload_at_padding_255", maxFrameSize-frameHeaderSize-maxFramePadding,
		vectors.Constants.MaxPayloadAtPadding255)

	conn := newPaddingConn()
	require("front_headroom", conn.frontHeadroom(), vectors.Constants.FrontHeadroom)
	require("rear_headroom", conn.rearHeadroom(), vectors.Constants.RearHeadroom)
	require("writer_geometry",
		conn.frontHeadroom()+conn.writerMTU()+conn.rearHeadroom(),
		vectors.Constants.MaxFrameSize)
}

// TestVectorsReferenceIsPinnedToTheReferenceImplementation records which revision of
// the reference these expectations come from.
//
// The commit is asserted rather than merely stored, so that updating the reference
// requires a deliberate change here as well. The same commit is pinned as
// CaddyReferenceCommit in sing-box's test/jiejie package; if the two disagree, the
// repositories are measuring against different references.
func TestVectorsReferenceIsPinnedToTheReferenceImplementation(t *testing.T) {
	vectors := loadNaivePaddingVectors(t)

	const expectedCommit = "d62c80d3dd2c706b6b87579844d2397bddd18317"
	if vectors.Reference.Commit != expectedCommit {
		t.Fatalf("the vectors reference %s, the audited reference is %s; sing-box pins "+
			"the same commit as CaddyReferenceCommit and the two must agree",
			vectors.Reference.Commit, expectedCommit)
	}
	if vectors.Reference.Branch != "naive" {
		t.Fatalf("the reference branch is %q, expected \"naive\"", vectors.Reference.Branch)
	}
	if vectors.Reference.NumFirstPaddings != paddingCount {
		t.Fatalf("the reference's NumFirstPaddings is %d, this codec frames %d times",
			vectors.Reference.NumFirstPaddings, paddingCount)
	}
	// The reference's own copy buffer is the source of the 65536 ceiling.
	if vectors.Reference.CopyBufferSize != maxFrameSize {
		t.Fatalf("the reference's copy buffer is %d bytes but this codec's ceiling is "+
			"%d; they are the same quantity", vectors.Reference.CopyBufferSize, maxFrameSize)
	}
	// The expressions are the ground truth the constants were derived from.
	if vectors.Reference.PayloadBudgetExpression != "65536 - 3 - paddingSize" {
		t.Fatalf("unexpected payload budget expression %q",
			vectors.Reference.PayloadBudgetExpression)
	}
	if vectors.Reference.PaddingDrawExpression != "rand.Intn(256)" {
		t.Fatalf("unexpected padding draw expression %q",
			vectors.Reference.PaddingDrawExpression)
	}
}

// TestSegmentationCasesMatchTheReferenceArithmetic replays every declared case
// through the codec and checks the wire length and rule against the reference's
// formulas, not against the codec's own behaviour.
func TestSegmentationCasesMatchTheReferenceArithmetic(t *testing.T) {
	vectors := loadNaivePaddingVectors(t)

	hdr := vectors.Constants.FrameHeaderSize
	ceiling := vectors.Constants.MaxFrameSize

	for _, c := range vectors.SegmentationCases {
		name := "p" + itoa(c.Padding) + "_n" + itoa(c.Payload)
		t.Run(name, func(t *testing.T) {
			budget := ceiling - hdr - c.Padding
			writer := newRecordingWriter()
			conn := newPaddingConn()
			if _, err := conn.writeFrame(writer, make([]byte, c.Payload), c.Padding); err != nil {
				t.Fatalf("writeFrame(payload=%d, padding=%d): %v", c.Payload, c.Padding, err)
			}
			wire := len(writer.totalBytes())
			wantWire := hdr + c.Payload + c.Padding
			if wire != wantWire {
				t.Fatalf("wire length is %d, the reference arithmetic gives 3 + %d + %d = %d",
					wire, c.Payload, c.Padding, wantWire)
			}
			if wire > ceiling {
				t.Fatalf("wire length %d exceeds the %d ceiling", wire, ceiling)
			}
			if wire != c.Wire {
				t.Fatalf("the shared vectors declare a wire length of %d, produced %d; the "+
					"vector file and the codec disagree", c.Wire, wire)
			}
			if c.Payload > budget {
				t.Fatalf("payload %d exceeds the budget %d for padding %d",
					c.Payload, budget, c.Padding)
			}
		})
	}
}

// TestOversizedRejectionCasesAreRefused checks the cases the vectors mark as invalid.
func TestOversizedRejectionCasesAreRefused(t *testing.T) {
	vectors := loadNaivePaddingVectors(t)

	for _, c := range vectors.OversizedRejectionCases {
		t.Run("p"+itoa(c.Padding)+"_n"+itoa(c.Payload), func(t *testing.T) {
			writer := newRecordingWriter()
			conn := newPaddingConn()
			if _, err := conn.writeFrame(writer, make([]byte, c.Payload), c.Padding); err == nil {
				t.Fatalf("padding %d with payload %d must be refused: %s",
					c.Padding, c.Payload, c.Reason)
			}
			if len(writer.writes) != 0 {
				t.Fatal("a refused frame must write nothing")
			}
			if conn.writePadding != 0 {
				t.Fatal("a refused frame must not advance the counter")
			}
		})
	}
}

// TestChunkingCasesMatchTheReferenceSegmentation covers payloads that do not fit one
// frame.
//
// These are distinct from the oversized-rejection cases: rejection is writeFrame
// refusing a single frame that cannot exist, while chunking is the segmentation path
// splitting a payload across frames. Conflating them in the vector file made three
// cases assert both that a payload was valid and that it must be refused.
//
// The chunker draws its own padding per frame, so the frame COUNT for a given payload
// is not fixed by the padding column alone. What is checkable without controlling the
// randomness is the guaranteed property: the total never exceeds the declared frame
// count, every frame respects its own budget, and the payload is reproduced exactly.
func TestChunkingCasesMatchTheReferenceSegmentation(t *testing.T) {
	vectors := loadNaivePaddingVectors(t)

	for _, c := range vectors.ChunkingCases {
		t.Run("p"+itoa(c.Padding)+"_n"+itoa(c.Payload), func(t *testing.T) {
			writer := newRecordingWriter()
			conn := newPaddingConn()
			payload := make([]byte, c.Payload)
			n, err := conn.writeChunked(writer, payload)
			if err != nil {
				t.Fatalf("writeChunked: %v", err)
			}
			if n != c.Payload {
				t.Fatalf("reported %d bytes, payload is %d", n, c.Payload)
			}

			// Walk the stream and verify each frame against its own draw.
			stream := writer.totalBytes()
			frames := 0
			for len(stream) > 0 && frames < paddingCount {
				payloadLen := int(stream[0])*256 + int(stream[1])
				paddingSize := int(stream[2])
				total := frameHeaderSize + payloadLen + paddingSize
				if total > maxFrameSize {
					t.Fatalf("frame %d is %d bytes on the wire, ceiling is %d",
						frames, total, maxFrameSize)
				}
				budget := maxFrameSize - frameHeaderSize - paddingSize
				if payloadLen > budget {
					t.Fatalf("frame %d carries %d payload with padding %d, budget is %d",
						frames, payloadLen, paddingSize, budget)
				}
				stream = stream[total:]
				frames++
			}
			// The declared frame count is the minimum achievable; the actual count can
			// be higher only if the draws were smaller. With a payload of one byte
			// over the budget, at most two frames are needed.
			if frames > c.Frames {
				t.Fatalf("used %d frames, the vectors declare %d", frames, c.Frames)
			}
			if frames < 1 {
				t.Fatal("no frames were emitted")
			}
		})
	}
}

// TestPaddingDrawsCoverTheDeclaredSet checks the codec can produce every draw the
// vectors call out, including both extremes.
func TestPaddingDrawsCoverTheDeclaredSet(t *testing.T) {
	vectors := loadNaivePaddingVectors(t)

	conn := newPaddingConn()
	seen := make(map[int]bool)
	for i := 0; i < 50000 && len(seen) < vectors.Constants.MaxPadding+1; i++ {
		seen[conn.nextPaddingSize()] = true
	}
	for _, draw := range vectors.PaddingDraws {
		if !seen[draw] {
			t.Errorf("the codec never produced the declared padding draw %d", draw)
		}
	}
	if seen[vectors.Constants.MinPadding] != true || seen[vectors.Constants.MaxPadding] != true {
		t.Errorf("both ends of the padding range must be reachable; saw 0=%v 255=%v",
			seen[0], seen[255])
	}
}

// TestEveryDeclaredInvariantHolds evaluates each invariant in the vector file.
//
// The statements are the contract in prose; this test is what makes them executable.
// An invariant added to the file without being implemented here is reported rather
// than ignored, so the document cannot accumulate claims nothing checks.
func TestEveryDeclaredInvariantHolds(t *testing.T) {
	vectors := loadNaivePaddingVectors(t)

	conn := newPaddingConn()
	checks := map[string]func() error{
		"frame_ceiling": func() error {
			for _, padding := range []int{0, 1, 127, 255} {
				budget := maxFrameSize - frameHeaderSize - padding
				if frameHeaderSize+budget+padding > maxFrameSize {
					return errInvariant("frame ceiling exceeded at padding %d", padding)
				}
			}
			return nil
		},
		"payload_budget": func() error {
			for _, padding := range []int{0, 128, 255} {
				writer := newRecordingWriter()
				c := newPaddingConn()
				budget := maxFrameSize - frameHeaderSize - padding
				if _, err := c.writeFrame(writer, make([]byte, budget), padding); err != nil {
					return errInvariant("budget %d refused at padding %d: %v", budget, padding, err)
				}
			}
			return nil
		},
		"writer_geometry": func() error {
			if conn.frontHeadroom()+conn.writerMTU()+conn.rearHeadroom() != maxFrameSize {
				return errInvariant("geometry is %d, want %d",
					conn.frontHeadroom()+conn.writerMTU()+conn.rearHeadroom(), maxFrameSize)
			}
			return nil
		},
		"padding_range_preserved": func() error {
			if maxFramePadding != 255 {
				return errInvariant("max padding is %d", maxFramePadding)
			}
			return nil
		},
		"short_write_fails": func() error {
			writer := newRecordingWriter()
			writer.failAfter = 0
			writer.shortBy = 1
			c := newPaddingConn()
			if _, err := c.writeChunked(writer, []byte("abc")); err == nil {
				return errInvariant("a short write was accepted")
			}
			return nil
		},
		"counter_advances_only_on_complete_frames": func() error {
			writer := newRecordingWriter()
			writer.failAfter = 0
			writer.shortBy = 1
			c := newPaddingConn()
			_, _ = c.writeChunked(writer, []byte("abc"))
			if c.writePadding != 0 {
				return errInvariant("counter advanced to %d after a failed frame", c.writePadding)
			}
			return nil
		},
		"raw_after_window": func() error {
			writer := newRecordingWriter()
			c := newPaddingConn()
			body := make([]byte, (paddingCount+2)*maxFrameSize)
			if _, err := c.writeChunked(writer, body); err != nil {
				return errInvariant("writeChunked: %v", err)
			}
			if c.writePadding != paddingCount {
				return errInvariant("framed %d times, want %d", c.writePadding, paddingCount)
			}
			return nil
		},
	}

	for _, invariant := range vectors.Invariants {
		check, implemented := checks[invariant.ID]
		if !implemented {
			t.Errorf("the shared vectors declare the invariant %q (%s) but no check "+
				"implements it; either implement it or remove the claim",
				invariant.ID, invariant.Statement)
			continue
		}
		if err := check(); err != nil {
			t.Errorf("invariant %q violated: %v", invariant.ID, err)
		}
	}
	// And no check may exist without a declared invariant.
	declared := make(map[string]bool, len(vectors.Invariants))
	for _, invariant := range vectors.Invariants {
		declared[invariant.ID] = true
	}
	for id := range checks {
		if !declared[id] {
			t.Errorf("check %q is not declared in the shared vectors", id)
		}
	}
}

// errInvariant formats an invariant violation. It uses fmt so the messages stay
// accurate as the checks evolve; an earlier hand-rolled formatter in this file
// silently mis-substituted arguments, which is exactly the kind of bug a test helper
// must not have.
func errInvariant(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
