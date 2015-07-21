package RTSP

import (
	"testing"

	"github.com/blanu/Dust/go/model1/testing"
)

func TestC2S(t *testing.T) {
	enc, _, errc := theModel.MakeClientPair()
	_, dec, errs := theModel.MakeServerPair()
	if errc != nil || errs != nil {
		t.Fatalf("making codec pairs: %v, %v", errc, errs)
	}
	testing1.TestOneDirection(t, enc, dec)
}

func TestS2C(t *testing.T) {
	_, dec, errc := theModel.MakeClientPair()
	enc, _, errs := theModel.MakeServerPair()
	if errc != nil || errs != nil {
		t.Fatalf("making codec pairs: %v, %v", errc, errs)
	}
	testing1.TestOneDirection(t, enc, dec)
}
