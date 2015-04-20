package Dust2

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"git.torproject.org/pluggable-transports/obfs4.git/transports/base"
	"github.com/blanu/Dust/go/v2/interface"
)

const (
	idFilename = "Dust2_id"
)

type serverFactory struct {
	transport *Transport
	stateDir  string
	private   *Dust.ServerPrivate
}

// lazyBridgeLine lazily wraps a public server identity for logging display as a bridge line.
type lazyBridgeLine struct {
	public *Dust.ServerPublic
}

func (lazy lazyBridgeLine) String() string {
	unparsed := lazy.public.Unparse()

	// TODO: lock down spec so that values can't contain horizontal whitespace.  (They
	// don't currently, but it should be documented.)
	parts := make([]string, 0, len(unparsed))
	for key, val := range unparsed {
		parts = append(parts, key+"="+val)
	}
	sort.Strings(parts)

	return fmt.Sprintf("Bridge %s ADDRESS %s", transportName, strings.Join(parts, " "))
}

func writeNewIdentity(unparsed map[string]string, idPath string) (private *Dust.ServerPrivate, err error) {
	ep, err := Dust.ParseEndpointParams(unparsed)
	if err != nil {
		log.Error("parsing endpoint parameters: %s", err)
		return
	}

	private, err = Dust.NewServerPrivate(ep)
	if err != nil {
		log.Error("generating new identity: %s", err)
		return
	}

	err = private.SavePrivateFile(idPath)
	if err != nil {
		log.Error("saving new identity to %s: %s", idPath, err)
		return
	}

	log.Notice("New bridge identity!  %s", &lazyBridgeLine{private.Public()})
	return
}

func (t *Transport) ServerFactory(stateDir string, args *pt.Args) (base.ServerFactory, error) {
	idPath := filepath.Join(stateDir, idFilename)

	unparsed, err := inPtArgs(args)
	if err != nil {
		return nil, err
	}

	var private *Dust.ServerPrivate

	_, statErr := os.Stat(idPath)
	switch {
	case statErr == nil:
		// ID file exists.  Try to load it.
		private, err = Dust.LoadServerPrivateFile(idPath)
		if err != nil {
			log.Error("loading identity file from %s: %s", idPath, err)
			return nil, err
		}

		// TODO: doesn't check ID file for congruence with existing parameters.

	case statErr != nil && os.IsNotExist(statErr):
		// ID file doesn't exist.  Try to write a new one.
		private, err = writeNewIdentity(unparsed, idPath)
		if err != nil {
			// We already logged the error in writeNewIdentity.
			return nil, err
		}
		
	default:
		log.Error("stat %s: %s", idPath, statErr)
		return nil, statErr
	}

	return &serverFactory{
		transport: t,
		stateDir:  stateDir,
		private:   private,
	}, nil
}

func (sf *serverFactory) Transport() base.Transport {
	return sf.transport
}

func (sf *serverFactory) Args() *pt.Args {
	return outPtArgs(sf.private.Public().Unparse())
}

func (sf *serverFactory) WrapConn(visible net.Conn) (net.Conn, error) {
	rconn, err := Dust.BeginRawStreamServer(visible, sf.private)
	if err != nil {
		return nil, err
	}

	return rconn, nil
}
