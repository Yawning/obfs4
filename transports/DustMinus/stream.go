package DustMinus

import (
	"errors"
	"time"

	"github.com/blanu/Dust/go/Dust"
)

var (
	// TODO: support deadlines, of course.  obfs4proxy doesn't seem to use them right now, but...
	ErrDeadlineNotSupported = errors.New("transport/DustMinus: I/O deadline not supported")
)

type streamConn struct {
	*Dust.RawConn
}

func (s *streamConn) Read(p []byte) (n int, err error) {
	return s.RawConn.Read(p)
}

func (s *streamConn) Write(p []byte) (n int, err error) {
	mtu := s.MTU()

	for len(p) > 0 {
		var pn int
		if len(p) > mtu {
			pn = mtu
		} else {
			pn = len(p)
		}

		subn, suberr := s.RawConn.Write(p[:pn])
		n += subn
		if suberr != nil {
			err = suberr
			return
		}
		p = p[pn:]
	}

	return
}

func (s *streamConn) SetDeadline(t time.Time) error {
	return ErrDeadlineNotSupported
}

func (s *streamConn) SetReadDeadline(t time.Time) error {
	return ErrDeadlineNotSupported
}

func (s *streamConn) SetWriteDeadline(t time.Time) error {
	return ErrDeadlineNotSupported
}
