package cronet

import (
	"runtime"
	"sync"
	"testing"
)

// Tests for the lifetime of buffers handed to native Cronet code.
//
// # The defect these pin down
//
// bidirectional_stream_read and bidirectional_stream_write take a Go array address and keep using
// it until the matching on_read_completed / on_write_completed callback fires. The C header states
// this directly: on_write_completed is "invoked when all data passed to
// bidirectional_stream_write() is sent" and receives the data pointer back, which only makes sense
// if the callee retained it.
//
// Before BidirectionalConn pinned anything, the caller's slice was the ONLY reference to that
// array. Read and Write can return before the callback fires -- on deadline and on Close they
// return as soon as done/close closes -- so a caller could legitimately reuse or release the buffer
// while native code was still reading or writing it.
//
// These tests cover the mechanism directly. The end-to-end lifetime is exercised by the Naive
// integration tests where a live tunnel is available.

// TestPinnedBufferKeepsTheArrayAlive is the core property: a pinned array must not be collected.
//
// It pins a large array, drops every other reference, forces collection, and reads the array back
// through the pin. runtime.KeepAlive alone would not achieve this -- it orders one point against a
// finalizer rather than retaining the object across a window.
func TestPinnedBufferKeepsTheArrayAlive(t *testing.T) {
	var pinned pinnedBuffer
	buffer := make([]byte, 1<<20)
	for index := range buffer {
		buffer[index] = byte(index)
	}
	pinned.pin(buffer)

	// Drop the caller's reference so the pin is the only thing keeping the array alive.
	buffer = nil
	for range 3 {
		runtime.GC()
	}

	if len(pinned.slice) != 1<<20 {
		t.Fatalf("pinned slice length changed to %d", len(pinned.slice))
	}
	for _, index := range []int{0, 1, 1024, (1 << 20) - 1} {
		if pinned.slice[index] != byte(index) {
			t.Fatalf("pinned array was corrupted at offset %d", index)
		}
	}
	pinned.release()
}

// TestPinnedBufferReleaseIsIdempotent covers the terminal-path double release.
//
// A completed operation unpins in its own callback, and terminate unpins again as a safety net.
// runtime.Pinner.Unpin panics when nothing is pinned, so a non-idempotent release would turn an
// ordinary close into a crash.
func TestPinnedBufferReleaseIsIdempotent(t *testing.T) {
	var pinned pinnedBuffer
	pinned.release() // before any pin

	pinned.pin(make([]byte, 128))
	pinned.release()
	pinned.release()
	pinned.release()

	if pinned.active {
		t.Fatal("release must clear the active flag")
	}
}

// TestPinnedBufferIgnoresEmptyBuffers covers the zero-length case.
//
// Read and Write return early for len(p) == 0, and the helper must not pin an empty slice either:
// runtime.Pinner.Pin panics on a nil pointer, and there is no array to keep alive.
func TestPinnedBufferIgnoresEmptyBuffers(t *testing.T) {
	var pinned pinnedBuffer

	pinned.pin(nil)
	if pinned.active {
		t.Fatal("a nil slice must not be pinned")
	}
	pinned.pin([]byte{})
	if pinned.active {
		t.Fatal("an empty slice must not be pinned")
	}
	pinned.release()
}

// TestPinnedBufferConcurrentPinAndRelease is the data-race guard.
//
// This is the real concurrency the connection creates, and it is why pinnedBuffer carries a mutex:
//
//	pin     runs on the CALLER'S goroutine, inside Read/Write
//	release runs on the ENGINE NETWORK THREAD, from the completion callback
//
// The header guarantees callbacks are serialised with respect to each other; it says nothing about
// the caller's goroutine, which is a different thread. Removing the lock makes this test report a
// data race, so the lock is load-bearing rather than defensive.
func TestPinnedBufferConcurrentPinAndRelease(t *testing.T) {
	for range 200 {
		var pinned pinnedBuffer
		buffer := make([]byte, 1024)

		var waitGroup sync.WaitGroup
		waitGroup.Add(2)
		go func() {
			defer waitGroup.Done()
			pinned.pin(buffer)
		}()
		go func() {
			defer waitGroup.Done()
			pinned.release()
		}()
		waitGroup.Wait()

		// The terminal path releases again; it must stay safe.
		pinned.release()
	}
}

// TestPinnedBufferDoesNotRetainAfterRelease proves a released pin does not leak the array.
//
// A pin that is never dropped keeps the buffer alive for the life of the connection. That is a
// memory leak rather than a race, and the race detector would not report it, so it is asserted
// directly.
func TestPinnedBufferDoesNotRetainAfterRelease(t *testing.T) {
	var pinned pinnedBuffer
	pinned.pin(make([]byte, 1<<16))
	pinned.release()

	if pinned.slice != nil {
		t.Fatal("release left the slice referenced, which would retain the array")
	}
}

// TestPinnedBufferPinAfterReleaseWorks proves the pair can be reused across operations.
//
// Every Read/Write pins, and the matching callback releases, so the pair is used many times over a
// connection's life. runtime.Pinner permits reuse only while every Pin is matched by an Unpin.
func TestPinnedBufferPinAfterReleaseWorks(t *testing.T) {
	var pinned pinnedBuffer
	for index := range 100 {
		buffer := make([]byte, 256)
		buffer[0] = byte(index)
		pinned.pin(buffer)
		if !pinned.active {
			t.Fatalf("iteration %d: pin did not take effect", index)
		}
		if pinned.slice[0] != byte(index) {
			t.Fatalf("iteration %d: pinned slice is not the one just pinned", index)
		}
		pinned.release()
	}
}
