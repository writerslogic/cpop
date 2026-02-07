package keyhierarchy

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
)

// MockPUF implements PUFProvider for benchmarking.
type MockPUF struct {
	response []byte
	deviceID string
}

func NewMockPUF() *MockPUF {
	response := make([]byte, 32)
	rand.Read(response)
	return &MockPUF{
		response: response,
		deviceID: "benchmark-device-001",
	}
}

func (m *MockPUF) GetResponse(challenge []byte) ([]byte, error) {
	// Simulate PUF response derivation
	h := sha256.New()
	h.Write(m.response)
	h.Write(challenge)
	return h.Sum(nil), nil
}

func (m *MockPUF) DeviceID() string {
	return m.deviceID
}

// BenchmarkMasterKeyDerivation benchmarks master identity derivation from PUF.
func BenchmarkMasterKeyDerivation(b *testing.B) {
	puf := NewMockPUF()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		identity, err := DeriveMasterIdentity(puf)
		if err != nil {
			b.Fatalf("derivation failed: %v", err)
		}
		_ = identity
	}
}

// BenchmarkSessionStart benchmarks starting a new session with key derivation.
func BenchmarkSessionStart(b *testing.B) {
	puf := NewMockPUF()

	var documentHash [32]byte
	copy(documentHash[:], []byte("benchmark-document-hash"))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		session, err := StartSession(puf, documentHash)
		if err != nil {
			b.Fatalf("session start failed: %v", err)
		}
		session.End()
	}
}

// BenchmarkRatchetAdvance benchmarks single ratchet advance (sign + advance).
func BenchmarkRatchetAdvance(b *testing.B) {
	puf := NewMockPUF()

	var documentHash [32]byte
	copy(documentHash[:], []byte("benchmark-document-hash"))

	session, err := StartSession(puf, documentHash)
	if err != nil {
		b.Fatalf("session start failed: %v", err)
	}
	defer session.End()

	var checkpointHash [32]byte
	copy(checkpointHash[:], []byte("benchmark-checkpoint-hash"))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Each SignCheckpoint advances the ratchet
		sig, err := session.SignCheckpoint(checkpointHash)
		if err != nil {
			// After many iterations, ratchet may be wiped
			// This is expected - create new session
			b.StopTimer()
			session, _ = StartSession(puf, documentHash)
			b.StartTimer()
			continue
		}
		_ = sig
	}
}

// BenchmarkSignCheckpoint benchmarks checkpoint signing specifically.
func BenchmarkSignCheckpoint(b *testing.B) {
	iterations := []int{1, 10, 100, 500}

	for _, numSigs := range iterations {
		b.Run(fmt.Sprintf("signatures_%d", numSigs), func(b *testing.B) {
			puf := NewMockPUF()

			var documentHash [32]byte
			copy(documentHash[:], []byte("benchmark-document-hash"))

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				session, _ := StartSession(puf, documentHash)
				b.StartTimer()

				for j := 0; j < numSigs; j++ {
					var checkpointHash [32]byte
					checkpointHash[0] = byte(j)
					checkpointHash[1] = byte(j >> 8)

					_, err := session.SignCheckpoint(checkpointHash)
					if err != nil {
						b.Fatalf("sign failed: %v", err)
					}
				}

				b.StopTimer()
				session.End()
			}

			b.ReportMetric(float64(numSigs), "signatures/session")
		})
	}
}

// BenchmarkVerifySessionCertificate benchmarks certificate verification.
func BenchmarkVerifySessionCertificate(b *testing.B) {
	puf := NewMockPUF()

	var documentHash [32]byte
	copy(documentHash[:], []byte("benchmark-document-hash"))

	session, _ := StartSession(puf, documentHash)
	defer session.End()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := VerifySessionCertificate(session.Certificate)
		if err != nil {
			b.Fatalf("verification failed: %v", err)
		}
	}
}

// BenchmarkVerifyCheckpointSignatures benchmarks signature chain verification.
func BenchmarkVerifyCheckpointSignatures(b *testing.B) {
	chainLengths := []int{10, 50, 100, 500}

	for _, length := range chainLengths {
		b.Run(fmt.Sprintf("chain_%d", length), func(b *testing.B) {
			puf := NewMockPUF()

			var documentHash [32]byte
			copy(documentHash[:], []byte("benchmark-document-hash"))

			session, _ := StartSession(puf, documentHash)

			// Generate signature chain
			for j := 0; j < length; j++ {
				var checkpointHash [32]byte
				checkpointHash[0] = byte(j)
				checkpointHash[1] = byte(j >> 8)
				session.SignCheckpoint(checkpointHash)
			}

			signatures := session.Signatures()
			session.End()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				err := VerifyCheckpointSignatures(signatures)
				if err != nil {
					b.Fatalf("verification failed: %v", err)
				}
			}

			b.ReportMetric(float64(length), "signatures_verified")
		})
	}
}

// BenchmarkVerifyKeyHierarchy benchmarks full key hierarchy verification.
func BenchmarkVerifyKeyHierarchy(b *testing.B) {
	puf := NewMockPUF()

	var documentHash [32]byte
	copy(documentHash[:], []byte("benchmark-document-hash"))

	identity, _ := DeriveMasterIdentity(puf)
	session, _ := StartSession(puf, documentHash)

	// Generate some signatures
	for j := 0; j < 50; j++ {
		var checkpointHash [32]byte
		checkpointHash[0] = byte(j)
		session.SignCheckpoint(checkpointHash)
	}

	evidence := session.Export(identity)
	session.End()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := VerifyKeyHierarchy(evidence)
		if err != nil {
			b.Fatalf("verification failed: %v", err)
		}
	}
}

// BenchmarkExportRecoveryState benchmarks recovery state export.
func BenchmarkExportRecoveryState(b *testing.B) {
	puf := NewMockPUF()

	var documentHash [32]byte
	copy(documentHash[:], []byte("benchmark-document-hash"))

	session, _ := StartSession(puf, documentHash)

	// Add some signatures
	for j := 0; j < 10; j++ {
		var checkpointHash [32]byte
		checkpointHash[0] = byte(j)
		session.SignCheckpoint(checkpointHash)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		state, err := session.ExportRecoveryState(puf)
		if err != nil {
			b.Fatalf("export failed: %v", err)
		}
		_ = state
	}

	session.End()
}

// BenchmarkRecoverSession benchmarks session recovery.
func BenchmarkRecoverSession(b *testing.B) {
	puf := NewMockPUF()

	var documentHash [32]byte
	copy(documentHash[:], []byte("benchmark-document-hash"))

	session, _ := StartSession(puf, documentHash)

	// Add some signatures
	for j := 0; j < 10; j++ {
		var checkpointHash [32]byte
		checkpointHash[0] = byte(j)
		session.SignCheckpoint(checkpointHash)
	}

	recoveryState, _ := session.ExportRecoveryState(puf)
	session.End()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		recoveredSession, err := RecoverSession(puf, recoveryState, documentHash)
		if err != nil {
			b.Fatalf("recovery failed: %v", err)
		}
		recoveredSession.End()
	}
}

// BenchmarkSecureWipe benchmarks the secure memory wipe function.
func BenchmarkSecureWipe(b *testing.B) {
	sizes := []int{32, 64, 256, 1024}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				secureWipe(data)
				// Refill for next iteration
				rand.Read(data)
			}

			b.ReportMetric(float64(size), "bytes_wiped")
		})
	}
}

// BenchmarkHKDFDerivation benchmarks HKDF key derivation (core crypto operation).
func BenchmarkHKDFDerivation(b *testing.B) {
	secret := make([]byte, 32)
	rand.Read(secret)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simulate the HKDF derivation pattern used in key hierarchy
		h := sha256.New()
		h.Write(secret)
		h.Write([]byte("benchmark-domain"))
		derived := h.Sum(nil)
		_ = derived
	}
}

// BenchmarkBuildCertData benchmarks certificate data construction.
func BenchmarkBuildCertData(b *testing.B) {
	puf := NewMockPUF()

	var documentHash [32]byte
	copy(documentHash[:], []byte("benchmark-document-hash"))

	session, _ := StartSession(puf, documentHash)
	defer session.End()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		data := buildCertData(
			session.Certificate.SessionID,
			session.Certificate.SessionPubKey,
			session.Certificate.CreatedAt,
			session.Certificate.DocumentHash,
		)
		_ = data
	}
}

// BenchmarkConcurrentSessions benchmarks starting multiple sessions concurrently.
func BenchmarkConcurrentSessions(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		puf := NewMockPUF()

		var documentHash [32]byte
		rand.Read(documentHash[:])

		for pb.Next() {
			session, err := StartSession(puf, documentHash)
			if err != nil {
				b.Fatalf("session start failed: %v", err)
			}

			// Sign a few checkpoints
			for j := 0; j < 5; j++ {
				var checkpointHash [32]byte
				checkpointHash[0] = byte(j)
				session.SignCheckpoint(checkpointHash)
			}

			session.End()
		}
	})
}

// BenchmarkKeyHierarchyMemory measures memory allocations for key operations.
func BenchmarkKeyHierarchyMemory(b *testing.B) {
	puf := NewMockPUF()

	var documentHash [32]byte
	copy(documentHash[:], []byte("benchmark-document-hash"))

	b.Run("FullSessionLifecycle", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			session, _ := StartSession(puf, documentHash)

			// Typical session: 100 checkpoints
			for j := 0; j < 100; j++ {
				var checkpointHash [32]byte
				checkpointHash[0] = byte(j)
				checkpointHash[1] = byte(j >> 8)
				session.SignCheckpoint(checkpointHash)
			}

			identity, _ := DeriveMasterIdentity(puf)
			evidence := session.Export(identity)
			_ = evidence

			session.End()
		}
	})
}

// BenchmarkRatchetChainLength measures performance impact of long ratchet chains.
func BenchmarkRatchetChainLength(b *testing.B) {
	lengths := []int{10, 100, 500, 1000}

	for _, length := range lengths {
		b.Run(fmt.Sprintf("length_%d", length), func(b *testing.B) {
			puf := NewMockPUF()

			var documentHash [32]byte
			copy(documentHash[:], []byte("benchmark-document-hash"))

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				session, _ := StartSession(puf, documentHash)

				for j := 0; j < length; j++ {
					var checkpointHash [32]byte
					checkpointHash[0] = byte(j)
					checkpointHash[1] = byte(j >> 8)
					session.SignCheckpoint(checkpointHash)
				}

				session.End()
			}

			// Report average time per signature
			b.ReportMetric(float64(length), "signatures_per_session")
		})
	}
}
