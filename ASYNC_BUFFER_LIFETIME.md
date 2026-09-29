# Async buffer lifetime: the contract, established from source

This is the analysis that decides whether the Go side must pin buffers handed to Cronet. It is
derived from the vendored C header and the cgo bridge in this repository, not from assumption.

## The authoritative contract

From `include/bidirectional_stream_c.h`:

```c
/* Writes request data from |buffer| of |buffer_length| length.
 * Each call will result in an invocation the callback's on_write_completed()
 * method if data is sent, or its on_failed() method if there's an error. */
int bidirectional_stream_write(bidirectional_stream* stream,
                               const char* buffer, int buffer_length, bool end_of_stream);

/* Invoked when all data passed to bidirectional_stream_write() is
 * sent. To continue writing, call bidirectional_stream_write(). */
void (*on_write_completed)(bidirectional_stream* stream, const char* data);
```

```c
/* Reads response data into |buffer| of |capacity| length. Must only be called
 * at most once in response to each invocation of the
 * on_stream_ready()/on_response_headers_received() and on_read_completed()
 * methods.
 * Each call will result in an invocation of the callback's on_read_completed()
 * method if data is read, or its on_failed() method if there's an error. */
int bidirectional_stream_read(bidirectional_stream* stream, char* buffer, int capacity);

/* Invoked when data is read into the buffer passed to
 * bidirectional_stream_read(). Only part of the buffer may be populated. */
void (*on_read_completed)(bidirectional_stream* stream, char* data, int bytes_read);
```

### What this establishes

1. **Write buffer is retained.** `on_write_completed` fires *when all data passed to
   `bidirectional_stream_write()` is sent*. The `data` parameter is passed back to the callback,
   which is only meaningful if the implementation kept the pointer. Between the `write` call and
   `on_write_completed`, the callee may read the buffer.

2. **Read buffer is retained.** The buffer is *written into* asynchronously; `on_read_completed`
   reports how many bytes landed in it. Between the `read` call and `on_read_completed`, the callee
   writes the buffer.

3. **`on_canceled` is the only documented "no further callbacks" boundary.** The header states:
   *"The on_canceled() method ... will be invoked when cancelation is complete and no further
   callback methods will be invoked."* Only `on_canceled` carries that guarantee.

4. **`destroy` is posted, not synchronous.** *"Destroy could be called from any thread, including
   network thread, but is posted, so |stream| is valid until calling task is complete."* Combined
   with the goroutine-side comment in `bidirectional_stream_cgo.go` (*"The destroy operation is
   asynchronous - callbacks may still be invoked after this returns"*), `Destroy()` returning does
   **not** mean pending operations have stopped.

### Conclusion

**Both pointers cross an async boundary and are retained by native code. Pinning is required.**

The Go garbage collector is non-moving, so a `[]byte` backing array does not relocate and the raw
address stays valid. What pinning actually prevents is the array being **freed** while native code
still holds the only reference to it — the Go side must not drop its last reference until the
completion callback has fired. `runtime.Pinner` expresses exactly that, and `runtime.KeepAlive`
alone does not, because it only orders the finalizer relative to a single point.

## What happens today, and why it is unsafe

`BidirectionalConn.Write`:

```go
c.stream.Write(p, false)     // native retains &p[0]
c.access.Unlock()
select {
case <-c.write:              // OnWriteCompleted
    return len(p), nil
case <-c.writeDeadline.Wait():
    c.cancelLocked()
    for {
        select {
        case <-c.write:
        case <-c.done:
            return 0, os.ErrDeadlineExceeded   // <-- returns while native may still hold &p[0]
        }
    }
...
}
```

The deadline path returns `os.ErrDeadlineExceeded` as soon as `c.done` closes. `c.done` closes in
`terminate()`, which is reached from `OnFailed` / `OnCanceled` / `OnSucceeded` — and also from
`cancelLocked`. After `terminate` the caller naturally reuses or releases `p`, while the native
side may still be reading it: the header guarantees `on_canceled` precedes the end of callbacks, but
the *posted* `destroy` and the engine's own teardown are not ordered against the Go function
returning.

The `<-c.close` path has the same shape.

## The fix

Pin the backing array for the duration of the operation and unpin only when the completion callback
has actually fired, so the Go side provably holds a reference — and therefore provably does not
reuse the memory — for as long as native code can touch it.

The eight-frame padding window is irrelevant here: this applies to every `Write` and every `Read`,
for the whole life of the connection.
