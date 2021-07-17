package process

import (
	"io"
	"os"
	"time"
)

// TailReader implements a thin wrapper around io.ReadCloser in
// order to create a ReadCloser that blocks when there is no input
// in the reader. The doneCh is a channel that can be used to
// inform the TailReader when there will no longer be any more
// bytes written, and closing this channel will finally allow
// the Read function to return io.EOF.
type TailReader struct {
	io.ReadCloser
	done   bool
	doneCh chan struct{}
}

type TailReaderOptions struct {
	// Path to the file to tail
	Path string
	// DoneCh should be closed by the consumer when
	// the file at Path will no longer be written;
	// this causes the Reader to return EOF.
	DoneCh chan struct{}
}

func NewTailReader(opts TailReaderOptions) (*TailReader, error) {
	f, err := os.Open(opts.Path)
	if err != nil {
		return nil, err
	}

	return &TailReader{
		ReadCloser: f,
		doneCh:     opts.DoneCh,
	}, nil
}

func (r *TailReader) Close() error {
	r.done = true
	return r.ReadCloser.Close()
}

func (r *TailReader) Read(p []byte) (int, error) {
	for {
		n, err := r.ReadCloser.Read(p)
		if err == io.EOF && r.done {
			return n, err
		} else if err != io.EOF {
			return n, err
		} else if n > 0 {
			return n, nil
		}

		select {
		case <-r.doneCh:
			r.done = true
		case <-time.After(50 * time.Millisecond):
			// TODO: improve performance/scalability by using inotify
		}
	}
}
