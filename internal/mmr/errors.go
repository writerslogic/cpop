package mmr

import "errors"

// MMR-specific errors
var (
	// ErrInvalidNodeData indicates corrupted or truncated node data.
	ErrInvalidNodeData = errors.New("mmr: invalid node data")

	// ErrIndexOutOfRange indicates an attempt to access a node beyond the MMR size.
	ErrIndexOutOfRange = errors.New("mmr: index out of range")

	// ErrEmptyMMR indicates an operation on an empty MMR that requires data.
	ErrEmptyMMR = errors.New("mmr: empty mmr")

	// ErrCorruptedStore indicates the backing store has inconsistent data.
	ErrCorruptedStore = errors.New("mmr: corrupted store")

	// ErrNodeNotFound indicates the requested node does not exist.
	ErrNodeNotFound = errors.New("mmr: node not found")

	// ErrInvalidProof indicates a proof verification failure.
	ErrInvalidProof = errors.New("mmr: invalid proof")

	// ErrHashMismatch indicates expected and actual hashes don't match.
	ErrHashMismatch = errors.New("mmr: hash mismatch")
)
