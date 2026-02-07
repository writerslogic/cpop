//go:build !darwin && !linux && !windows

// Package keyhierarchy implements a three-tier ratcheting key hierarchy for witnessd.
//
// This file provides a fallback for platforms without native hardware PUF support.
// On these platforms, only the software PUF is available.
//
// Patent Pending: USPTO Application No. 19/460,364
package keyhierarchy

import (
	"errors"
)

// ErrNoHardwarePUF indicates no hardware PUF is available on this platform
var ErrNoHardwarePUF = errors.New("keyhierarchy: no hardware PUF available on this platform")

// DetectHardwarePUF returns an error on unsupported platforms.
func DetectHardwarePUF() (PUFProvider, error) {
	return nil, ErrNoHardwarePUF
}
