package DustMinus

import (
	stdlog "log"

	"github.com/op/go-logging"

	"git.torproject.org/pluggable-transports/obfs4.git/transports/base"
)

const (
	transportName = "DustMinus"
)

type Transport struct{}
var _ base.Transport = (*Transport)(nil)

func (t *Transport) Name() string {
	return transportName
}

type stdlogBackend struct{}

func (_ *stdlogBackend) Log(level logging.Level, calldepth int, rec *logging.Record) error {
	stdlog.Print(rec.Formatted(calldepth+1))
	return nil
}

func init() {
	backend := &stdlogBackend{}
	formatSpec := "(DustMinus) %{level:s} %{module:s}: %{message}"
	formatter := logging.MustStringFormatter(formatSpec)
	formatted := logging.NewBackendFormatter(backend, formatter)
	leveled := logging.AddModuleLevel(formatted)
	// TODO: actually pick up log level... ?!
	leveled.SetLevel(logging.INFO, "")
	logging.SetBackend(leveled)
}
