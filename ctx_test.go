package c2pa

import "context"

// mustLayers builds a merkle tree under a background context, for tests that
// exercise the tree rather than cancellation.
func mustLayers(alg string, leaves [][]byte) [][][]byte {
	layers, err := merkleLayers(context.Background(), alg, leaves)
	if err != nil {
		panic(err) // a background context never ends
	}
	return layers
}
