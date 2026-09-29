package cronet

import (
	"context"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/pipe"
)

type BidirectionalConn struct {
	ctx              context.Context
	stream           BidirectionalStream
	logger           logger.ContextLogger
	cancelled        bool
	readWaitHeaders  bool
	writeWaitHeaders bool
	access           sync.Mutex
	close            chan struct{}
	done             chan struct{}
	err              error
	ready            chan struct{}
	handshake        chan struct{}
	read             chan int
	write            chan struct{}
	headers          map[string]string
	readSemaphore    chan struct{}
	writeSemaphore   chan struct{}
	readDone         chan struct{}
	writeDone        chan struct{}
	doneOnce         sync.Once
	readDoneOnce     sync.Once
	writeDoneOnce    sync.Once
	onTerminate      func()
	readDeadline     pipe.Deadline
	writeDeadline    pipe.Deadline
	// readPinned and writePinned hold the buffer the in-flight native operation is using.
	//
	// # Why the lifetime has to be tracked per operation
	//
	// bidirectional_stream_read/write hand a Go array's address to native code, which keeps it
	// until the matching on_read_completed/on_write_completed callback fires. The Go side must
	// therefore hold its own reference for that whole window, or the collector may free the array
	// while native code is still reading or writing it.
	//
	// runtime.Pinner is that reference. It must be released only once the completion callback has
	// actually run -- NOT when Read/Write returns, because those can return early:
	//
	//   - on deadline, Read/Write cancel the stream and return os.ErrDeadlineExceeded as soon as
	//     done closes, while the native operation may still be in flight;
	//   - on Close, the same happens through c.close.
	//
	// Releasing at return would hand the caller back a buffer that native code may still touch.
	// The callback is the only event that proves the window is closed, so the unpin lives there.
	readPinned  pinnedBuffer
	writePinned pinnedBuffer
}

// pinnedBuffer holds a Go slice alive across a native async operation.
//
// It is deliberately minimal: one Pinner, the slice it covers, and a flag. The zero value is
// ready to use and unpinning twice is a no-op, so the completion callback and the error paths can
// both call release without coordinating.
type pinnedBuffer struct {
	// access serialises pin against release.
	//
	// # Why a lock is required here
	//
	// The two calls come from different goroutines: pin runs on the caller's goroutine inside
	// Read/Write, and release runs on the ENGINE NETWORK THREAD from the completion callback. The
	// header documents that callbacks are serialised with respect to EACH OTHER, but says nothing
	// about the caller's goroutine, which is a different thread entirely.
	//
	// Without this lock the fields below are a data race, and -- worse than a reported race -- a
	// release that reads a stale active==false could skip Unpin and leave the array pinned for the
	// life of the connection.
	access sync.Mutex
	pinner runtime.Pinner
	slice  []byte
	active bool
}

// pin keeps buffer alive until release is called.
//
// A zero-length slice is not pinned: there is no array to keep alive, and Pin would panic on a nil
// pointer. That matches the callers, which pass nil/0 for an empty read or write.
func (p *pinnedBuffer) pin(buffer []byte) {
	if len(buffer) == 0 {
		return
	}
	p.access.Lock()
	defer p.access.Unlock()
	p.slice = buffer
	p.active = true
	p.pinner.Pin(&buffer[0])
}

// release drops the reference, allowing the array to be collected again.
//
// It is safe to call when nothing is pinned and safe to call more than once, which matters because
// a failed operation can be released by both the callback and the calling goroutine.
func (p *pinnedBuffer) release() {
	p.access.Lock()
	defer p.access.Unlock()
	if !p.active {
		return
	}
	p.active = false
	p.pinner.Unpin()
	// Keep the slice reachable until after Unpin, so the compiler cannot treat the pin as dead
	// before it is dropped.
	runtime.KeepAlive(p.slice)
	p.slice = nil
}

func (e StreamEngine) CreateConn(ctx context.Context, l logger.ContextLogger, readWaitHeaders bool, writeWaitHeaders bool) *BidirectionalConn {
	conn := &BidirectionalConn{
		ctx:              ctx,
		logger:           l,
		readWaitHeaders:  readWaitHeaders,
		writeWaitHeaders: writeWaitHeaders,
		close:            make(chan struct{}),
		done:             make(chan struct{}),
		ready:            make(chan struct{}),
		handshake:        make(chan struct{}),
		read:             make(chan int),
		write:            make(chan struct{}),
		readSemaphore:    make(chan struct{}, 1),
		writeSemaphore:   make(chan struct{}, 1),
		readDone:         make(chan struct{}),
		writeDone:        make(chan struct{}),
		readDeadline:     pipe.MakeDeadline(),
		writeDeadline:    pipe.MakeDeadline(),
	}
	conn.readSemaphore <- struct{}{}
	conn.writeSemaphore <- struct{}{}
	conn.stream = e.CreateStream(&bidirectionalHandler{BidirectionalConn: conn})
	return conn
}

func (c *BidirectionalConn) waitReady(waitHeaders bool, deadline <-chan struct{}) error {
	var gate <-chan struct{}
	if waitHeaders {
		gate = c.handshake
	} else {
		gate = c.ready
	}
	select {
	case <-gate:
		return nil
	case <-c.done:
		return c.err
	case <-c.close:
		return net.ErrClosed
	case <-deadline:
		return os.ErrDeadlineExceeded
	}
}

func (c *BidirectionalConn) Start(method string, url string, headers map[string]string, priority int, endOfStream bool) error {
	c.access.Lock()
	if !c.stream.Start(method, url, headers, priority, endOfStream) {
		c.access.Unlock()
		c.terminate(os.ErrInvalid)
		return os.ErrInvalid
	}
	c.access.Unlock()
	return nil
}

func (c *BidirectionalConn) cancelLocked() {
	if c.cancelled {
		return
	}
	c.cancelled = true
	c.stream.Cancel()
}

func (c *BidirectionalConn) terminate(err error) {
	var onTerminate func()
	c.access.Lock()
	c.readDoneOnce.Do(func() { close(c.readDone) })
	c.writeDoneOnce.Do(func() { close(c.writeDone) })
	c.cancelled = true
	c.doneOnce.Do(func() {
		c.err = err
		close(c.done)
		onTerminate = c.onTerminate
		c.stream.Destroy()
		cleanupBidirectionalStream(c.stream.ptr)
	})
	c.access.Unlock()

	// Terminal safety net for pinning.
	//
	// # Why this is safe here, and why it is needed
	//
	// Every caller of terminate is either a TERMINAL callback or a local failure:
	//
	//	OnReadCompleted (bytesRead == 0)  the read already unpinned above
	//	OnSucceeded / OnFailed / OnCanceled
	//	                                  the header guarantees "no further callback methods will
	//	                                  be invoked" for all three
	//	Start failure                      no operation was ever in flight
	//
	// So once terminate has been entered from a terminal callback, no further native access to a
	// pinned buffer can occur, and the references can be dropped.
	//
	// It is NOT sufficient to unpin when Read/Write returns, which is the bug this fixes: those
	// return early on deadline and on Close, while the native operation may still be running. The
	// terminal callback is the first moment the window is provably closed.
	//
	// Unpin is idempotent, so a normal completion (which already released in its own callback)
	// passes through here as a no-op rather than a double release.
	c.readPinned.release()
	c.writePinned.release()

	if onTerminate != nil {
		onTerminate()
	}
}

func (c *BidirectionalConn) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	select {
	case <-c.close:
		return 0, net.ErrClosed
	case <-c.done:
		return 0, c.err
	case <-c.readSemaphore:
	}
	defer func() { c.readSemaphore <- struct{}{} }()

	if err := c.waitReady(c.readWaitHeaders, c.readDeadline.Wait()); err != nil {
		return 0, err
	}

	c.access.Lock()
	select {
	case <-c.close:
		c.access.Unlock()
		return 0, net.ErrClosed
	case <-c.done:
		c.access.Unlock()
		return 0, c.err
	default:
	}
	// Pin BEFORE the native call. The native side writes into p asynchronously and reports
	// completion through OnReadCompleted, so the array must stay alive from here until that
	// callback runs -- which is why the corresponding release is in the callback, not here.
	c.readPinned.pin(p)
	c.stream.Read(p)
	c.access.Unlock()

	select {
	case bytesRead := <-c.read:
		return bytesRead, nil
	case <-c.readDeadline.Wait():
		c.access.Lock()
		c.cancelLocked()
		c.access.Unlock()
		for {
			select {
			case <-c.read:
			case <-c.done:
				return 0, os.ErrDeadlineExceeded
			}
		}
	case <-c.done:
		<-c.readDone
		return 0, c.err
	case <-c.close:
		<-c.readDone
		return 0, net.ErrClosed
	}
}

func (c *BidirectionalConn) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	select {
	case <-c.close:
		return 0, net.ErrClosed
	case <-c.done:
		return 0, c.err
	case <-c.writeSemaphore:
	}
	defer func() { c.writeSemaphore <- struct{}{} }()

	if err := c.waitReady(c.writeWaitHeaders, c.writeDeadline.Wait()); err != nil {
		return 0, err
	}

	c.access.Lock()
	select {
	case <-c.close:
		c.access.Unlock()
		return 0, net.ErrClosed
	case <-c.done:
		c.access.Unlock()
		return 0, c.err
	default:
	}
	// Pin BEFORE the native call, for the same reason as Read: the native side reads p until
	// OnWriteCompleted fires, and this goroutine may return before that.
	c.writePinned.pin(p)
	c.stream.Write(p, false)
	c.access.Unlock()

	select {
	case <-c.write:
		return len(p), nil
	case <-c.writeDeadline.Wait():
		c.access.Lock()
		c.cancelLocked()
		c.access.Unlock()
		for {
			select {
			case <-c.write:
			case <-c.done:
				return 0, os.ErrDeadlineExceeded
			}
		}
	case <-c.done:
		<-c.writeDone
		return 0, c.err
	case <-c.close:
		<-c.writeDone
		return 0, net.ErrClosed
	}
}

func (c *BidirectionalConn) Done() <-chan struct{} {
	return c.done
}

func (c *BidirectionalConn) setOnTerminate(fn func()) {
	c.access.Lock()
	select {
	case <-c.done:
		c.access.Unlock()
		fn()
		return
	default:
	}
	c.onTerminate = fn
	c.access.Unlock()
}

func (c *BidirectionalConn) Err() error {
	return c.err
}

func (c *BidirectionalConn) Close() error {
	c.access.Lock()

	select {
	case <-c.close:
		c.access.Unlock()
		return net.ErrClosed
	case <-c.done:
		c.access.Unlock()
		return nil
	default:
	}

	close(c.close)
	c.cancelLocked()
	c.access.Unlock()
	return nil
}

func (c *BidirectionalConn) LocalAddr() net.Addr {
	return nil
}

func (c *BidirectionalConn) RemoteAddr() net.Addr {
	return nil
}

func (c *BidirectionalConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

func (c *BidirectionalConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *BidirectionalConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Set(t)
	return nil
}

func (c *BidirectionalConn) WaitForHeaders() (map[string]string, error) {
	select {
	case <-c.handshake:
		return c.headers, nil
	case <-c.done:
		return nil, c.err
	case <-c.close:
		return nil, net.ErrClosed
	}
}

func (c *BidirectionalConn) WaitForHeadersContext(ctx context.Context) (map[string]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.handshake:
		return c.headers, nil
	case <-c.done:
		return nil, c.err
	case <-c.close:
		return nil, net.ErrClosed
	}
}

type bidirectionalHandler struct {
	*BidirectionalConn
	readyOnce     sync.Once
	handshakeOnce sync.Once
}

func (c *bidirectionalHandler) OnStreamReady(stream BidirectionalStream) {
	c.readyOnce.Do(func() { close(c.ready) })
}

func (c *bidirectionalHandler) OnResponseHeadersReceived(stream BidirectionalStream, headers map[string]string, negotiatedProtocol string) {
	c.headers = headers
	c.logger.DebugContext(c.ctx, "response received, protocol: ", negotiatedProtocol, ", status: ", headers[":status"])
	c.handshakeOnce.Do(func() { close(c.handshake) })
}

func (c *bidirectionalHandler) OnReadCompleted(stream BidirectionalStream, bytesRead int) {
	// THE unpin point for a read.
	//
	// This callback is the only event that proves native code has finished writing the buffer
	// passed to bidirectional_stream_read, so it is where the reference can be dropped. It runs
	// before the result is delivered to the waiting goroutine, so the caller cannot observe a
	// buffer that is still pinned and cannot reuse one that is not yet safe.
	//
	// It is also on the paths below that do NOT deliver a result (terminate on end-of-stream, and
	// the close/done branches), which is what keeps a truncated read from leaking a pin.
	c.readPinned.release()

	if bytesRead == 0 {
		c.terminate(io.EOF)
		return
	}

	select {
	case <-c.close:
		c.readDoneOnce.Do(func() { close(c.readDone) })
	case <-c.done:
		c.readDoneOnce.Do(func() { close(c.readDone) })
	case c.read <- bytesRead:
	}
}

func (c *bidirectionalHandler) OnWriteCompleted(stream BidirectionalStream) {
	// THE unpin point for a write, for the same reason as OnReadCompleted: this is the event that
	// proves native code has consumed the buffer passed to bidirectional_stream_write.
	c.writePinned.release()

	select {
	case <-c.close:
		c.writeDoneOnce.Do(func() { close(c.writeDone) })
	case <-c.done:
		c.writeDoneOnce.Do(func() { close(c.writeDone) })
	case c.write <- struct{}{}:
	}
}

func (c *bidirectionalHandler) OnResponseTrailersReceived(stream BidirectionalStream, trailers map[string]string) {
}

func (c *bidirectionalHandler) OnSucceeded(stream BidirectionalStream) {
	c.terminate(io.EOF)
}

func (c *bidirectionalHandler) OnFailed(stream BidirectionalStream, netError int) {
	c.logger.WarnContext(c.ctx, "stream failed: ", NetError(netError))
	c.terminate(NetError(netError))
}

func (c *bidirectionalHandler) OnCanceled(stream BidirectionalStream) {
	c.logger.DebugContext(c.ctx, "stream canceled")
	c.terminate(context.Canceled)
}
