package Dust2

import (
	"os"

	"github.com/op/go-logging"

	obfs4log "git.torproject.org/pluggable-transports/obfs4.git/common/log"
	"git.torproject.org/pluggable-transports/obfs4.git/transports/base"

	"github.com/blanu/Dust/go/v2/interface"
)

const (
	transportName = "Dust2"

	envvarDebug = "OBFS4PROXY_DUST_DEBUG"
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

func init() {
	backend := &obfs4logBackend{}
	formatSpec := "%{module:s}: %{message}"
	formatter := logging.MustStringFormatter(formatSpec)
	formatted := logging.NewBackendFormatter(backend, formatter)
	leveled := logging.AddModuleLevel(formatted)

	// TODO: actually pick up log level... ?!
	leveled.SetLevel(logging.NOTICE, "")

	if os.Getenv(envvarDebug) == "1" {
		for _, module := range Dust.LogModules {
			leveled.SetLevel(logging.DEBUG, module)
		}
	}

	logging.SetBackend(leveled)
}
