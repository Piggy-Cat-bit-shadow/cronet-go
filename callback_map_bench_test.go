package cronet

// Item 41-43: is the callback map a hotspot? Measure before considering any change.
//
// The registry is a RWMutex-guarded map[uintptr]BidirectionalStreamCallback, read once per native
// callback (OnReadCompleted, OnWriteCompleted, OnStreamReady, ...). The task says to change it ONLY
// if a profile proves it significant, and to try the smallest experiment first (current map vs
// sync.Map) rather than going straight to a native annotation handle.
//
// This benchmark measures the read cost directly, so the decision rests on a number rather than on
// the shape of the code.

import (
	"sync"
	"testing"
)

// BenchmarkCallbackMapLookup measures the existing RWMutex+map lookup.
func BenchmarkCallbackMapLookup(b *testing.B) {
	const ptrs = 64
	keys := make([]uintptr, ptrs)
	for i := range keys {
		keys[i] = uintptr(0x1000 + i*0x100)
		entry := &bidirectionalStreamEntry{callback: nopCallback{}}
		bidirectionalStreamAccess.Lock()
		bidirectionalStreamMap[keys[i]] = entry
		bidirectionalStreamAccess.Unlock()
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		_ = instanceOfBidirectionalStreamCallback(keys[i%ptrs])
	}
}

// BenchmarkCallbackMapLookupParallel is the case that actually matters: callbacks arrive on the
// engine network thread while the caller's goroutine registers and removes streams, so the read
// path contends with writers.
func BenchmarkCallbackMapLookupParallel(b *testing.B) {
	const ptrs = 64
	keys := make([]uintptr, ptrs)
	for i := range keys {
		keys[i] = uintptr(0x2000 + i*0x100)
		entry := &bidirectionalStreamEntry{callback: nopCallback{}}
		bidirectionalStreamAccess.Lock()
		bidirectionalStreamMap[keys[i]] = entry
		bidirectionalStreamAccess.Unlock()
	}

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = instanceOfBidirectionalStreamCallback(keys[i%ptrs])
			i++
		}
	})
}

// BenchmarkSyncMapLookup is the smallest experiment the task allows: the same workload against
// sync.Map, so the decision can be made on a comparison rather than on an assumption.
func BenchmarkSyncMapLookup(b *testing.B) {
	const ptrs = 64
	var m sync.Map
	keys := make([]uintptr, ptrs)
	for i := range keys {
		keys[i] = uintptr(0x3000 + i*0x100)
		m.Store(keys[i], nopCallback{})
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		_, _ = m.Load(keys[i%ptrs])
	}
}

func BenchmarkSyncMapLookupParallel(b *testing.B) {
	const ptrs = 64
	var m sync.Map
	keys := make([]uintptr, ptrs)
	for i := range keys {
		keys[i] = uintptr(0x4000 + i*0x100)
		m.Store(keys[i], nopCallback{})
	}

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_, _ = m.Load(keys[i%ptrs])
			i++
		}
	})
}

// nopCallback satisfies the interface so the map stores a realistic value size.
type nopCallback struct{}

func (nopCallback) OnStreamReady(BidirectionalStream)                                        {}
func (nopCallback) OnResponseHeadersReceived(BidirectionalStream, map[string]string, string) {}
func (nopCallback) OnReadCompleted(BidirectionalStream, int)                                 {}
func (nopCallback) OnWriteCompleted(BidirectionalStream)                                     {}
func (nopCallback) OnResponseTrailersReceived(BidirectionalStream, map[string]string)        {}
func (nopCallback) OnSucceeded(BidirectionalStream)                                          {}
func (nopCallback) OnFailed(BidirectionalStream, int)                                        {}
func (nopCallback) OnCanceled(BidirectionalStream)                                           {}
