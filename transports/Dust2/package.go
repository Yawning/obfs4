package Dust2

import (
	"github.com/op/go-logging"

	obfs4log "git.torproject.org/pluggable-transports/obfs4.git/common/log"
	"git.torproject.org/pluggable-transports/obfs4.git/transports/base"
)

const (
	transportName = "Dust2"
)

var log = logging.MustGetLogger("transport/Dust2")

type Transport struct{}
var _ base.Transport = (*Transport)(nil)

func (t *Transport) Name() string {
	return transportName
}

type obfs4logBackend struct{}

func (_ *obfs4logBackend) Log(level logging.Level, calldepth int, rec *logging.Record) error {
	str := rec.Formatted(calldepth+1)

	switch level {
	case logging.CRITICAL, logging.ERROR:
		obfs4log.Errorf("%s", str)
	case logging.WARNING:
		obfs4log.Warnf("%s", str)
	case logging.NOTICE:
		obfs4log.Noticef("%s", str)
	case logging.INFO:
		obfs4log.Infof("%s", str)
	case logging.DEBUG:
		obfs4log.Debugf("%s", str)
	}

	return nil
}

func translateLevel(level int) logging.Level {
	switch level {
	case obfs4log.LevelError, obfs4log.LevelWarn:
		// obfs4proxy considers NOTICE to be above ERROR/WARNING for some reason, so
		// we have to let it do the filtering here.  Hrgh.
		return logging.NOTICE
	case obfs4log.LevelInfo:
		return logging.INFO
	case obfs4log.LevelDebug:
		return logging.DEBUG
	default:
		// Hmm.
		return logging.NOTICE
	}
}

func init() {
	backend := &obfs4logBackend{}
	formatSpec := "%{module:s}: %{message}"
	formatter := logging.MustStringFormatter(formatSpec)
	formatted := logging.NewBackendFormatter(backend, formatter)
	leveled := logging.AddModuleLevel(formatted)
	leveled.SetLevel(translateLevel(obfs4log.Level()), "")
	logging.SetBackend(leveled)
}
