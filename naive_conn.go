package cronet

import (
	"context"
	"encoding/binary"
	"io"
	"math/rand"
	"net"

	"github.com/sagernet/sing/common/baderror"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/rw"
)

const (
	paddingCount = 8

	// maxFrameSize is the largest total frame the Naive reference emits.
	//
	// klzgrad/forwardproxy reads into `buf[3:maxRead]` with
	// `maxRead = 65536 - 3 - paddingSize`, so header + payload + padding occupies
	// at most 65536 bytes. The reference's own copy buffer is `make([]byte, 0,
	// 64*1024)`, i.e. exactly this size.
	maxFrameSize = 65536

	// maxFramePadding is the reference's padding range, rand.Intn(256) => 0..255.
	maxFramePadding = 255

	// frameHeaderSize is the 2-byte big-endian payload length plus the 1-byte
	// padding length.
	frameHeaderSize = 3

	// maxPaddingPayload is the largest payload that can be framed in place while
	// still leaving room for the WORST-CASE padding draw:
	//
	//	3 (header) + 65278 (payload) + 255 (padding) = 65536
	//
	// This is the value writerMTU() must advertise. It is NOT a chunking
	// constant: chunk boundaries are decided per frame from that frame's own
	// padding draw, exactly as the reference does.
	maxPaddingPayload = maxFrameSize - frameHeaderSize - maxFramePadding
)

func generatePaddingHeader() string {
	paddingLen := rand.Intn(32) + 30
	padding := make([]byte, paddingLen)
	bits := rand.Uint64()
	for i := 0; i < 16; i++ {
		padding[i] = "!#$()+<>?@[]^`{}"[bits&15]
		bits >>= 4
	}
	for i := 16; i < paddingLen; i++ {
		padding[i] = '~'
	}
	return string(padding)
}

type paddingConn struct {
	readPadding      int
	writePadding     int
	readRemaining    int
	paddingRemaining int
}

func (p *paddingConn) readWithPadding(reader io.Reader, buffer []byte) (n int, err error) {
	if p.readRemaining > 0 {
		if len(buffer) > p.readRemaining {
			buffer = buffer[:p.readRemaining]
		}
		n, err = reader.Read(buffer)
		if err != nil {
			return
		}
		p.readRemaining -= n
		return
	}
	if p.paddingRemaining > 0 {
		err = rw.SkipN(reader, p.paddingRemaining)
		if err != nil {
			return
		}
		p.paddingRemaining = 0
	}
	if p.readPadding < paddingCount {
		var paddingHeader []byte
		if len(buffer) >= 3 {
			paddingHeader = buffer[:3]
		} else {
			paddingHeader = make([]byte, 3)
		}
		_, err = io.ReadFull(reader, paddingHeader)
		if err != nil {
			return
		}
		originalDataSize := int(binary.BigEndian.Uint16(paddingHeader[:2]))
		paddingSize := int(paddingHeader[2])
		if len(buffer) > originalDataSize {
			buffer = buffer[:originalDataSize]
		}
		n, err = reader.Read(buffer)
		if err != nil {
			return
		}
		p.readPadding++
		p.readRemaining = originalDataSize - n
		p.paddingRemaining = paddingSize
		return
	}
	return reader.Read(buffer)
}

func (p *paddingConn) writeWithPadding(writer io.Writer, data []byte) (n int, err error) {
	if p.writePadding < paddingCount {
		// The caller sizes its payload against writerMTU(), which already leaves
		// room for the worst-case padding draw, so this frame always fits the
		// reference ceiling. Draw the padding the same way the reference does.
		paddingSize := p.nextPaddingSize()
		return p.writeFrame(writer, data, paddingSize)
	}
	return writeFull(writer, data)
}

// nextPaddingSize draws the padding length for one frame.
//
// REFERENCE PARITY: `paddingSize := rand.Intn(256)`, the full 0..255 range. The
// range must NOT be narrowed to make a buffer fit: the padding distribution is
// part of the protocol's wire appearance, and the reference emits every value in
// the range.
func (p *paddingConn) nextPaddingSize() int {
	return rand.Intn(maxFramePadding + 1)
}

// writeFull writes all of data, converting a short write into io.ErrShortWrite.
//
// io.Writer permits returning n < len(data) with a NIL error, and such a result
// must be treated as a failure. Checking only the error - as this codec
// previously did - reports success for a frame the peer never fully received,
// and then advances the padding frame counter, so our framing and the peer's
// diverge from that point on.
func writeFull(writer io.Writer, data []byte) (int, error) {
	written, err := writer.Write(data)
	if err != nil {
		return written, err
	}
	if written != len(data) {
		return written, io.ErrShortWrite
	}
	return written, nil
}

// writeFrame writes exactly one padded frame: header, payload, then padding.
//
// The frame counter advances ONLY after the whole frame reached the writer.
func (p *paddingConn) writeFrame(writer io.Writer, data []byte, paddingSize int) (n int, err error) {
	if len(data) > maxFrameSize-frameHeaderSize-paddingSize {
		// A frame that cannot fit the reference ceiling must not be emitted. This
		// is a programming error in the caller's segmentation, not a wire
		// condition, so report it instead of truncating or panicking.
		return 0, E.New("naive frame payload ", len(data), " with padding ", paddingSize,
			" exceeds the ", maxFrameSize, "-byte reference ceiling")
	}
	buffer := buf.NewSize(frameHeaderSize + len(data) + paddingSize)
	defer buffer.Release()
	header := buffer.Extend(frameHeaderSize)
	binary.BigEndian.PutUint16(header, uint16(len(data)))
	header[2] = byte(paddingSize)
	// These cannot fail on a buffer this function has just sized for exactly this
	// content, but they must not be common.Must: a writer implementing
	// WriteBuffer may be handed any buffer by any caller, and an internal
	// geometry slip must not take the whole process down.
	if _, err = buffer.Write(data); err != nil {
		return 0, E.Cause(err, "write naive frame payload")
	}
	if paddingSize > 0 {
		if err = buffer.WriteZeroN(paddingSize); err != nil {
			return 0, E.Cause(err, "write naive frame padding")
		}
	}
	// A frame header is already on the wire once ANY byte of the frame is
	// written, so the write must complete or the stream is corrupt.
	if _, err = writeFull(writer, buffer.Bytes()); err != nil {
		// Deliberately do NOT advance the frame counter: the peer never received
		// a complete frame, so its padding accounting must not move.
		return 0, err
	}
	p.writePadding++
	return len(data), nil
}

func (p *paddingConn) writeBufferWithPadding(writer io.Writer, buffer *buf.Buffer) error {
	framed := false
	if p.writePadding < paddingCount {
		bufferLen := buffer.Len()
		// A payload this large cannot be framed in place, because the in-place
		// path reserves exactly three bytes of header and then appends padding:
		// 3 + 65535 + 255 exceeds the reference ceiling. Hand it to writeChunked,
		// which sizes each frame against its own padding draw.
		//
		// The threshold is the reference ceiling minus the header and the maximum
		// padding, not 65535: a payload of 65535 would pass a `> 65535` test and
		// then be framed to 65723 bytes once padding was appended.
		if bufferLen > maxPaddingPayload {
			_, err := p.writeChunked(writer, buffer.Bytes())
			return err
		}
		if buffer.Start() < frameHeaderSize {
			return E.New("naive padding requires ", frameHeaderSize,
				" bytes of front headroom, buffer has ", buffer.Start())
		}
		paddingSize := p.nextPaddingSize()
		// The padding range is the protocol's full 0..255 and is deliberately
		// NOT clamped to the buffer. rearHeadroom() advertises 255 for exactly
		// this reason. Narrowing the range here would silently change the padding
		// distribution Naive specifies.
		//
		// If a caller passes a buffer that cannot hold the frame, that is a
		// programming error in the caller, not a protocol condition: report it as
		// an error. It must not be common.Must, which would turn it into a panic
		// and take the whole process down.
		if buffer.FreeLen() < paddingSize {
			return E.New("naive padding needs ", paddingSize,
				" bytes of free space for padding, buffer has ", buffer.FreeLen(),
				" (padding range 0..255 must be preserved, not clamped)")
		}
		header := buffer.ExtendHeader(frameHeaderSize)
		binary.BigEndian.PutUint16(header, uint16(bufferLen))
		header[2] = byte(paddingSize)
		if err := buffer.WriteZeroN(paddingSize); err != nil {
			return E.Cause(err, "write naive padding")
		}
		framed = true
	}
	if _, err := writeFull(writer, buffer.Bytes()); err != nil {
		// As above: a frame that was not fully written must not advance the
		// counter, or the peer's framing and ours diverge.
		return err
	}
	if framed {
		p.writePadding++
	}
	return nil
}

// writeChunked writes data as Naive frames while the padding window is open.
//
// REFERENCE PARITY. The segmentation follows klzgrad/forwardproxy's
// flushingIoCopy exactly:
//
//	paddingSize := rand.Intn(256)
//	maxRead     := 65536 - 3 - paddingSize
//	nr, er      := src.Read(buf[3:maxRead])
//
// The padding size is drawn FIRST and the payload budget is then reduced by it,
// so a frame's total length is at most 65536 regardless of the draw:
//
//	padding   0 -> payload budget 65533
//	padding   1 -> payload budget 65532
//	padding 255 -> payload budget 65278
//
// This is not equivalent to chunking the payload at 65535 and adding padding
// afterwards, which is what this function previously did: that produced frames
// of up to 3 + 65535 + 255 = 65793 bytes, 257 more than the reference's ceiling,
// and it disagreed with the reference about where every frame boundary falls
// once the reader returned a large block.
func (p *paddingConn) writeChunked(writer io.Writer, data []byte) (n int, err error) {
	for len(data) > 0 {
		if p.writePadding >= paddingCount {
			// Padding window closed: the 2-byte length field is gone from this
			// point on, so there is no frame-size limit to respect. Write the
			// remainder straight through.
			var written int
			written, err = writeFull(writer, data)
			n += written
			return
		}
		paddingSize := p.nextPaddingSize()
		maxPayload := maxFrameSize - frameHeaderSize - paddingSize
		chunk := data
		if len(chunk) > maxPayload {
			chunk = chunk[:maxPayload]
		}
		var written int
		written, err = p.writeFrame(writer, chunk, paddingSize)
		n += written
		if err != nil {
			return
		}
		data = data[len(chunk):]
	}
	return
}

func (p *paddingConn) frontHeadroom() int {
	if p.writePadding < paddingCount {
		return frameHeaderSize
	}
	return 0
}

func (p *paddingConn) rearHeadroom() int {
	if p.writePadding < paddingCount {
		return maxFramePadding
	}
	return 0
}

// writerMTU reports the payload size the copy path may hand this writer in one
// call while the padding window is open.
//
// It is the reference ceiling minus the header and the MAXIMUM padding, so that
// a caller reserving frontHeadroom/rearHeadroom around a WriterMTU-sized payload
// can always be framed:
//
//	frontHeadroom + writerMTU + rearHeadroom
//	= 3 + 65278 + 255
//	= 65536
//
// Returning 65535 - as this codec previously did - advertises a geometry of
// 65793 bytes, which overruns the reference ceiling by 257.
func (p *paddingConn) writerMTU() int {
	if p.writePadding < paddingCount {
		return maxPaddingPayload
	}
	return 0
}

func (p *paddingConn) readerReplaceable() bool {
	return p.readPadding == paddingCount
}

func (p *paddingConn) writerReplaceable() bool {
	return p.writePadding == paddingCount
}

type NaiveConn interface {
	net.Conn
	Handshake() error
	HandshakeContext(ctx context.Context) error
}
type naiveConn struct {
	net.Conn
	ctx    context.Context
	conn   *BidirectionalConn
	logger logger.ContextLogger
	paddingConn
}

func NewNaiveConn(ctx context.Context, conn *BidirectionalConn, l logger.ContextLogger) NaiveConn {
	return &naiveConn{Conn: conn, ctx: ctx, conn: conn, logger: l}
}

func (c *naiveConn) Handshake() error {
	headers, err := c.conn.WaitForHeaders()
	if err != nil {
		c.logger.WarnContext(c.ctx, "handshake failed: ", err)
		return err
	}
	if headers[":status"] != "200" {
		err = E.New("unexpected response status: ", headers[":status"])
		c.logger.WarnContext(c.ctx, "handshake failed: ", err)
		return err
	}
	c.logger.DebugContext(c.ctx, "handshake succeeded")
	return nil
}

func (c *naiveConn) HandshakeContext(ctx context.Context) error {
	headers, err := c.conn.WaitForHeadersContext(ctx)
	if err != nil {
		c.logger.WarnContext(c.ctx, "handshake failed: ", err)
		return err
	}
	if headers[":status"] != "200" {
		err = E.New("unexpected response status: ", headers[":status"])
		c.logger.WarnContext(c.ctx, "handshake failed: ", err)
		return err
	}
	c.logger.DebugContext(c.ctx, "handshake succeeded")
	return nil
}

func (c *naiveConn) Read(p []byte) (n int, err error) {
	n, err = c.readWithPadding(c.Conn, p)
	return n, baderror.WrapH2(err)
}

func (c *naiveConn) Write(p []byte) (n int, err error) {
	n, err = c.writeChunked(c.Conn, p)
	return n, baderror.WrapH2(err)
}

func (c *naiveConn) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	err := c.writeBufferWithPadding(c.Conn, buffer)
	return baderror.WrapH2(err)
}

func (c *naiveConn) FrontHeadroom() int { return c.frontHeadroom() }
func (c *naiveConn) RearHeadroom() int  { return c.rearHeadroom() }
func (c *naiveConn) WriterMTU() int     { return c.writerMTU() }
func (c *naiveConn) Upstream() any      { return c.Conn }

// EarlyCopyBufferGrowth asks the copy loop feeding this writer to grow its buffer after the FIRST
// transfer instead of after the default 512000 bytes.
//
// # Why this writer wants it, and why the inbound already had it
//
// Naive framing happens in place: the fast path prepends a 3-byte header and appends 0..255 bytes
// of padding into the buffer it is handed. That only avoids a copy when the buffer arrives with
// frontHeadroom() bytes before the payload and rearHeadroom() bytes after it, and when the payload
// fits writerMTU(). The copy loop sizes its buffer from exactly those three values, so once it has
// grown, every write is framed in place.
//
// Until it grows, each upload write is smaller than the geometry allows and is framed through the
// chunking path instead, which allocates and copies per frame. The threshold is the difference
// between the frame being built IN the caller's buffer and being built INTO A NEW ONE.
//
// The inbound side of this protocol has opted in for the same reason (protocol/naive
// inbound_conn.go). This is the client-side writer, which is the one the upload copy loop feeds.
//
// # Why it is a method on the writer rather than a special case in the route layer
//
// The copy destination is the only component that knows the geometry it can accept, and the route
// layer already asks it through adapter.CopyBufferGrowthTuner. Declaring the capability here means
// the route layer needs no protocol name, no tag and no configuration check -- it sees a writer
// that opts in, which is what structural typing is for. The type is an interface on the sing-box
// side, so this package does not import the adapter and no dependency is created in this direction.
func (c *naiveConn) EarlyCopyBufferGrowth() bool { return true }
func (c *naiveConn) ReaderReplaceable() bool     { return c.readerReplaceable() }
func (c *naiveConn) WriterReplaceable() bool     { return c.writerReplaceable() }
