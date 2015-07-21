package Dust2

import (
	"git.torproject.org/pluggable-transports/goptlib.git"
)

func inPtArgs(args *pt.Args) (result map[string]string, err error) {
	result = make(map[string]string)
	for key, vals := range *args {
		switch len(vals) {
		case 0:
			// No values?  Huh.  Well, never mind then.
		case 1:
			result[key] = vals[0]
		default:
			return nil, ErrMultipleValuesNotSupported
		}
	}
	return
}

func outPtArgs(p map[string]string) *pt.Args {
	result := make(map[string][]string)
	for key, val := range p {
		result[key] = []string{val}
	}

	ptArgs := pt.Args(result)
	return &ptArgs
}
