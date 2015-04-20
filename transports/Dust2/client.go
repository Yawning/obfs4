package Dust2

import (
	"errors"
	"net"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"git.torproject.org/pluggable-transports/obfs4.git/transports/base"
	"github.com/blanu/Dust/go/v2/interface"
)

type clientFactory struct {
	transport *Transport
	stateDir  string
}

var (
	ErrMultipleValuesNotSupported = errors.New("transport/Dust2: multiple values for key not supported")
)

func (t *Transport) ClientFactory(stateDir string) (base.ClientFactory, error) {
	return &clientFactory{
		transport: t,
		stateDir:  stateDir,
	}, nil
}

func (cf *clientFactory) Transport() base.Transport {
	return cf.transport
}

type clientArgs *Dust.ServerPublic

func (cf *clientFactory) ParseArgs(args *pt.Args) (interface{}, error) {
	unparsed, err := inPtArgs(args)
	if err != nil {
		return nil, err
	}

	public, err := Dust.ParseServerPublic(unparsed)
	if err != nil {
		return nil, err
	}

	return clientArgs(public), nil
}

func (cf *clientFactory) WrapConn(visible net.Conn, args interface{}) (net.Conn, error) {
	public := (*Dust.ServerPublic)(args.(clientArgs))
	rconn, err := Dust.BeginRawStreamClient(visible, public)
	if err != nil {
		return nil, err
	}

	return rconn, err
}
