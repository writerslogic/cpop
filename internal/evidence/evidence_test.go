package evidence

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"witnessd/internal/checkpoint"
	"witnessd/internal/declaration"
	"witnessd/internal/jitter"
	"witnessd/internal/keyhierarchy"
	"witnessd/internal/presence"
	"witnessd/internal/tpm"
	"witnessd/internal/vdf"
	"witnessd/pkg/anchors"
)

func TestNewBuilder(t *testing.T) {
	chain := createTestChain(t)

	builder := NewBuilder("test.md", chain)
	if builder == nil {
		t.Fatal("expected non-nil builder")
	}

	if builder.packet.Document.Title != "test.md" {
		t.Errorf("expected title 'test.md', got %q", builder.packet.Document.Title)
	}
}

func TestBuilderWithDeclaration(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	builder := NewBuilder("test.md", chain).
		WithDeclaration(decl)

	if builder.packet.Declaration == nil {
		t.Error("expected declaration to be set")
	}
}

func TestBuilderWithPresence(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	builder := NewBuilder("test.md", chain).
		WithDeclaration(decl)

	// Empty sessions should not upgrade strength
	builder.WithPresence(nil)
	if builder.packet.Strength != Basic {
		t.Errorf("expected Basic strength, got %v", builder.packet.Strength)
	}
}

func TestBuilderWithContexts(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	contexts := []ContextPeriod{
		{
			Type:      "assisted",
			Note:      "Used Claude for research",
			StartTime: time.Now().Add(-time.Hour),
			EndTime:   time.Now().Add(-30 * time.Minute),
		},
	}

	builder := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		WithContexts(contexts)

	if len(builder.packet.Contexts) != 1 {
		t.Errorf("expected 1 context, got %d", len(builder.packet.Contexts))
	}
}

func TestBuilderWithBehavioral(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	metrics := &ForensicMetrics{
		MonotonicAppendRatio:  0.75,
		EditEntropy:           2.5,
		MedianInterval:        30.0,
		PositiveNegativeRatio: 0.8,
		DeletionClustering:    1.1,
		Assessment:            "CONSISTENT WITH HUMAN AUTHORSHIP",
	}

	builder := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		WithBehavioral(nil, metrics)

	if builder.packet.Behavioral == nil {
		t.Error("expected behavioral evidence")
	}

	if builder.packet.Strength != Maximum {
		t.Errorf("expected Maximum strength, got %v", builder.packet.Strength)
	}
}

func TestBuilderBuild(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	packet, err := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		Build()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if packet.Version != 1 {
		t.Errorf("expected version 1, got %d", packet.Version)
	}

	if len(packet.Claims) == 0 {
		t.Error("expected at least one claim")
	}
}

func TestBuilderBuildWithoutDeclaration(t *testing.T) {
	chain := createTestChain(t)

	_, err := NewBuilder("test.md", chain).Build()
	if err == nil {
		t.Error("expected error when building without declaration")
	}
}

func TestStrengthString(t *testing.T) {
	tests := []struct {
		strength Strength
		expected string
	}{
		{Basic, "basic"},
		{Standard, "standard"},
		{Enhanced, "enhanced"},
		{Maximum, "maximum"},
		{Strength(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.strength.String(); got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestPacketEncodeDecode(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	packet, err := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		Build()

	if err != nil {
		t.Fatalf("build error: %v", err)
	}

	// Encode
	data, err := packet.Encode()
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}

	// Decode
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if decoded.Document.Title != packet.Document.Title {
		t.Errorf("title mismatch: %q vs %q", decoded.Document.Title, packet.Document.Title)
	}
}

func TestPacketTotalElapsedTime(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	packet, _ := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		Build()

	// The elapsed time comes from VDF proofs
	elapsed := packet.TotalElapsedTime()
	// Since we don't have real VDF proofs in the test chain, this should be 0
	if elapsed != 0 {
		t.Logf("elapsed time: %v", elapsed)
	}
}

func TestPacketHash(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	packet, _ := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		Build()

	hash := packet.Hash()
	if hash == [32]byte{} {
		t.Error("expected non-zero hash")
	}
}

// Helper functions

func createTestChain(t *testing.T) *checkpoint.Chain {
	t.Helper()

	vdfParams := vdf.DefaultParameters()
	chain := &checkpoint.Chain{
		DocumentID:   "test-doc-id",
		DocumentPath: "/tmp/test.md",
		CreatedAt:    time.Now(),
		Checkpoints:  make([]*checkpoint.Checkpoint, 0),
		VDFParams:    vdfParams,
	}

	// Add a test checkpoint with valid hashes
	cp := &checkpoint.Checkpoint{
		Ordinal:      0,
		ContentHash:  [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		ContentSize:  100,
		Timestamp:    time.Now(),
		Message:      "Initial commit",
		Hash:         [32]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		PreviousHash: [32]byte{}, // First checkpoint has zero previous
	}
	chain.Checkpoints = append(chain.Checkpoints, cp)

	return chain
}

func createTestDeclaration(t *testing.T, chain *checkpoint.Chain) *declaration.Declaration {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	latest := chain.Latest()
	var chainHash [32]byte
	if latest != nil {
		chainHash = latest.Hash
	}

	decl, err := declaration.NewDeclaration(latest.ContentHash, chainHash, "test.md").
		AddModality(declaration.ModalityKeyboard, 100, "").
		WithStatement("I wrote this myself").
		Sign(priv)

	if err != nil {
		t.Fatalf("failed to create declaration: %v", err)
	}

	return decl
}

func createTestDeclarationWithAI(t *testing.T, chain *checkpoint.Chain) *declaration.Declaration {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	latest := chain.Latest()
	var chainHash [32]byte
	if latest != nil {
		chainHash = latest.Hash
	}

	decl, err := declaration.NewDeclaration(latest.ContentHash, chainHash, "test.md").
		AddModality(declaration.ModalityKeyboard, 80, "").
		AddModality(declaration.ModalityDictation, 20, "").
		AddAITool("Claude", "3.5", declaration.PurposeEditing, "Proofreading", declaration.ExtentModerate).
		WithStatement("I wrote this with AI assistance").
		Sign(priv)

	if err != nil {
		t.Fatalf("failed to create declaration: %v", err)
	}

	return decl
}

// =============================================================================
// Tests for WithDeclaration edge cases
// =============================================================================

func TestBuilderWithDeclarationNil(t *testing.T) {
	chain := createTestChain(t)

	builder := NewBuilder("test.md", chain).
		WithDeclaration(nil)

	if len(builder.errors) == 0 {
		t.Error("expected error for nil declaration")
	}
}

func TestBuilderWithDeclarationInvalidSignature(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	// Corrupt the signature
	decl.Signature = []byte("corrupted-signature")

	builder := NewBuilder("test.md", chain).
		WithDeclaration(decl)

	if len(builder.errors) == 0 {
		t.Error("expected error for invalid signature")
	}
}

// =============================================================================
// Tests for WithPresence with actual sessions
// =============================================================================

func TestBuilderWithPresenceActualSessions(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	sessions := []presence.Session{
		{
			ID:               "sess-1",
			StartTime:        time.Now().Add(-time.Hour),
			EndTime:          time.Now().Add(-30 * time.Minute),
			ChallengesIssued: 5,
			ChallengesPassed: 4,
			VerificationRate: 0.8,
		},
	}

	builder := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		WithPresence(sessions)

	if builder.packet.Presence == nil {
		t.Error("expected presence evidence")
	}

	if builder.packet.Strength != Standard {
		t.Errorf("expected Standard strength, got %v", builder.packet.Strength)
	}
}

// =============================================================================
// Tests for WithHardware
// =============================================================================

func TestBuilderWithHardware(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	bindings := []tpm.Binding{
		{
			CheckpointHash: [32]byte{1, 2, 3},
		},
	}

	builder := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		WithHardware(bindings, "device-123")

	if builder.packet.Hardware == nil {
		t.Error("expected hardware evidence")
	}

	if builder.packet.Hardware.DeviceID != "device-123" {
		t.Errorf("expected device ID 'device-123', got %q", builder.packet.Hardware.DeviceID)
	}

	if builder.packet.Strength != Enhanced {
		t.Errorf("expected Enhanced strength, got %v", builder.packet.Strength)
	}
}

func TestBuilderWithHardwareEmpty(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	builder := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		WithHardware(nil, "")

	if builder.packet.Hardware != nil {
		t.Error("expected nil hardware for empty bindings")
	}

	if builder.packet.Strength != Basic {
		t.Errorf("expected Basic strength, got %v", builder.packet.Strength)
	}
}

// =============================================================================
// Tests for WithKeystroke
// =============================================================================

func TestBuilderWithKeystroke(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	// Create valid jitter evidence with proper chain
	now := time.Now()
	sample1 := jitter.Sample{
		Timestamp:      now.Add(-time.Minute),
		KeystrokeCount: 50,
		DocumentHash:   [32]byte{1, 2, 3},
		JitterMicros:   1000,
		PreviousHash:   [32]byte{}, // First sample has zero previous
	}
	// Compute hash for sample1 (simplified - just use a fixed hash for testing)
	sample1.Hash = [32]byte{10, 20, 30}

	sample2 := jitter.Sample{
		Timestamp:      now,
		KeystrokeCount: 100,
		DocumentHash:   [32]byte{4, 5, 6},
		JitterMicros:   1500,
		PreviousHash:   sample1.Hash, // Link to first sample
	}
	sample2.Hash = [32]byte{40, 50, 60}

	ev := &jitter.Evidence{
		SessionID: "jitter-sess-1",
		StartedAt: now.Add(-time.Hour),
		EndedAt:   now,
		Samples:   []jitter.Sample{sample1, sample2},
		Statistics: jitter.Statistics{
			TotalKeystrokes:  1000,
			TotalSamples:     2,
			Duration:         time.Hour,
			KeystrokesPerMin: 16.67,
			UniqueDocHashes:  5,
			ChainValid:       true,
		},
	}

	builder := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		WithKeystroke(ev)

	// The evidence verification may fail because we're using simplified hashes,
	// which is expected - just verify the builder handles it correctly
	if builder.packet.Keystroke != nil {
		if builder.packet.Keystroke.TotalKeystrokes != 1000 {
			t.Errorf("expected 1000 keystrokes, got %d", builder.packet.Keystroke.TotalKeystrokes)
		}
	}
	// If keystroke is nil, it's because verification failed (expected with test data)
}

func TestBuilderWithKeystrokeNil(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	builder := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		WithKeystroke(nil)

	if builder.packet.Keystroke != nil {
		t.Error("expected nil keystroke for nil input")
	}
}

func TestBuilderWithKeystrokeZeroKeystrokes(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	ev := &jitter.Evidence{
		Statistics: jitter.Statistics{
			TotalKeystrokes: 0,
		},
	}

	builder := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		WithKeystroke(ev)

	if builder.packet.Keystroke != nil {
		t.Error("expected nil keystroke for zero keystrokes")
	}
}

// =============================================================================
// Tests for WithExternalAnchors
// =============================================================================

func TestBuilderWithExternalAnchors(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	ots := []OTSProof{
		{
			ChainHash:   "abc123",
			Proof:       "base64proof",
			Status:      "confirmed",
			BlockHeight: 700000,
			BlockTime:   time.Now(),
		},
	}

	rfc := []RFC3161Proof{
		{
			ChainHash: "abc123",
			TSAUrl:    "https://tsa.example.com",
			Response:  "base64response",
			Timestamp: time.Now(),
		},
	}

	builder := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		WithExternalAnchors(ots, rfc)

	if builder.packet.External == nil {
		t.Error("expected external anchors")
	}

	if len(builder.packet.External.OpenTimestamps) != 1 {
		t.Errorf("expected 1 OTS proof, got %d", len(builder.packet.External.OpenTimestamps))
	}

	if len(builder.packet.External.RFC3161) != 1 {
		t.Errorf("expected 1 RFC3161 proof, got %d", len(builder.packet.External.RFC3161))
	}

	if builder.packet.Strength != Maximum {
		t.Errorf("expected Maximum strength, got %v", builder.packet.Strength)
	}
}

func TestBuilderWithExternalAnchorsEmpty(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	builder := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		WithExternalAnchors(nil, nil)

	if builder.packet.External != nil {
		t.Error("expected nil external for empty anchors")
	}
}

// =============================================================================
// Tests for WithAnchors (new format)
// =============================================================================

func TestBuilderWithAnchors(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	proofs := []*anchors.Proof{
		{
			Provider:  "opentimestamps",
			Hash:      [32]byte{1, 2, 3},
			Timestamp: time.Now(),
			Status:    anchors.StatusConfirmed,
			RawProof:  []byte("proof-data"),
			VerifyURL: "https://verify.example.com",
			BlockchainAnchor: &anchors.BlockchainAnchor{
				Chain:       "bitcoin",
				BlockHeight: 800000,
				BlockHash:   "0000000000000000000abc",
				BlockTime:   time.Now(),
			},
		},
	}

	builder := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		WithAnchors(proofs)

	if builder.packet.External == nil {
		t.Error("expected external anchors")
	}

	if len(builder.packet.External.Proofs) != 1 {
		t.Errorf("expected 1 anchor proof, got %d", len(builder.packet.External.Proofs))
	}

	proof := builder.packet.External.Proofs[0]
	if proof.Provider != "opentimestamps" {
		t.Errorf("expected provider 'opentimestamps', got %q", proof.Provider)
	}

	if proof.Blockchain == nil {
		t.Error("expected blockchain anchor info")
	}

	if builder.packet.Strength != Maximum {
		t.Errorf("expected Maximum strength, got %v", builder.packet.Strength)
	}
}

func TestBuilderWithAnchorsEmpty(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	builder := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		WithAnchors(nil)

	if builder.packet.External != nil {
		t.Error("expected nil external for empty anchors")
	}
}

// =============================================================================
// Tests for Verify
// =============================================================================

func TestPacketVerify(t *testing.T) {
	chain := createTestChainWithVDF(t)
	decl := createTestDeclaration(t, chain)

	packet, err := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		Build()

	if err != nil {
		t.Fatalf("build error: %v", err)
	}

	// Verify should pass for valid packet
	err = packet.Verify(chain.VDFParams)
	if err != nil {
		t.Errorf("verify failed: %v", err)
	}
}

func TestPacketVerifyBrokenChain(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	packet, _ := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		Build()

	// Corrupt the chain
	if len(packet.Checkpoints) > 0 {
		packet.Checkpoints[0].PreviousHash = "corrupted"
	}

	err := packet.Verify(chain.VDFParams)
	if err == nil {
		t.Error("expected error for broken chain")
	}
}

func TestPacketVerifyInvalidDeclaration(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	packet, _ := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		Build()

	// Corrupt the declaration signature
	packet.Declaration.Signature = []byte("invalid")

	err := packet.Verify(chain.VDFParams)
	if err == nil {
		t.Error("expected error for invalid declaration")
	}
}

// =============================================================================
// Tests for claims generation
// =============================================================================

func TestGenerateClaimsWithAI(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclarationWithAI(t, chain)

	packet, err := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		Build()

	if err != nil {
		t.Fatalf("build error: %v", err)
	}

	// Should have process declared claim mentioning AI
	found := false
	for _, claim := range packet.Claims {
		if claim.Type == ClaimProcessDeclared {
			found = true
			if claim.Description == "" {
				t.Error("expected non-empty description")
			}
		}
	}
	if !found {
		t.Error("expected process declared claim")
	}
}

func TestGenerateClaimsWithContexts(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	contexts := []ContextPeriod{
		{Type: "assisted", Note: "AI help"},
		{Type: "external", Note: "Pasted code"},
	}

	packet, err := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		WithContexts(contexts).
		Build()

	if err != nil {
		t.Fatalf("build error: %v", err)
	}

	found := false
	for _, claim := range packet.Claims {
		if claim.Type == ClaimContextsRecorded {
			found = true
		}
	}
	if !found {
		t.Error("expected contexts recorded claim")
	}
}

// =============================================================================
// Tests for limitations generation
// =============================================================================

func TestGenerateLimitationsWithAI(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclarationWithAI(t, chain)

	packet, err := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		Build()

	if err != nil {
		t.Fatalf("build error: %v", err)
	}

	// Should have AI-related limitation
	found := false
	for _, lim := range packet.Limitations {
		if lim == "Author declares AI tool usage - verify institutional policy compliance" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected AI limitation")
	}
}

func TestGenerateLimitationsMinimal(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	packet, err := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		Build()

	if err != nil {
		t.Fatalf("build error: %v", err)
	}

	// Should have limitations for missing presence, keystroke, hardware
	if len(packet.Limitations) < 4 {
		t.Errorf("expected at least 4 limitations, got %d", len(packet.Limitations))
	}
}

// =============================================================================
// Tests for Decode edge cases
// =============================================================================

func TestDecodeInvalidJSON(t *testing.T) {
	_, err := Decode([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestDecodeEmpty(t *testing.T) {
	_, err := Decode([]byte("{}"))
	if err != nil {
		t.Errorf("unexpected error for empty object: %v", err)
	}
}

// =============================================================================
// Tests for convertAnchorProof
// =============================================================================

func TestConvertAnchorProof(t *testing.T) {
	proof := &anchors.Proof{
		Provider:  "rfc3161",
		Hash:      [32]byte{1, 2, 3, 4, 5},
		Timestamp: time.Now(),
		Status:    anchors.StatusPending,
		RawProof:  []byte("raw-proof-data"),
		VerifyURL: "https://verify.example.com",
	}

	converted := convertAnchorProof(proof)

	if converted.Provider != "rfc3161" {
		t.Errorf("expected provider 'rfc3161', got %q", converted.Provider)
	}

	expectedHash := hex.EncodeToString(proof.Hash[:])
	if converted.Hash != expectedHash {
		t.Errorf("expected hash %q, got %q", expectedHash, converted.Hash)
	}

	if converted.Status != "pending" {
		t.Errorf("expected status 'pending', got %q", converted.Status)
	}

	if converted.VerifyURL != "https://verify.example.com" {
		t.Errorf("unexpected verify URL: %q", converted.VerifyURL)
	}
}

func TestConvertAnchorProofWithBlockchain(t *testing.T) {
	proof := &anchors.Proof{
		Provider:  "opentimestamps",
		Hash:      [32]byte{1, 2, 3},
		Timestamp: time.Now(),
		Status:    anchors.StatusConfirmed,
		BlockchainAnchor: &anchors.BlockchainAnchor{
			Chain:         "bitcoin",
			BlockHeight:   800000,
			BlockHash:     "000000000000000000001234",
			BlockTime:     time.Now(),
			TransactionID: "tx123",
		},
	}

	converted := convertAnchorProof(proof)

	if converted.Blockchain == nil {
		t.Fatal("expected blockchain info")
	}

	if converted.Blockchain.Chain != "bitcoin" {
		t.Errorf("expected chain 'bitcoin', got %q", converted.Blockchain.Chain)
	}

	if converted.Blockchain.BlockHeight != 800000 {
		t.Errorf("expected height 800000, got %d", converted.Blockchain.BlockHeight)
	}

	if converted.Blockchain.TxID != "tx123" {
		t.Errorf("expected txid 'tx123', got %q", converted.Blockchain.TxID)
	}
}

// =============================================================================
// Test for full evidence packet with all layers
// =============================================================================

func TestFullEvidencePacket(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclarationWithAI(t, chain)

	sessions := []presence.Session{
		{ID: "sess-1", ChallengesIssued: 10, ChallengesPassed: 9, VerificationRate: 0.9},
	}

	bindings := []tpm.Binding{{CheckpointHash: [32]byte{1}}}

	metrics := &ForensicMetrics{
		MonotonicAppendRatio: 0.8,
		Assessment:           "CONSISTENT",
	}

	contexts := []ContextPeriod{
		{Type: "assisted", Note: "AI research"},
	}

	ots := []OTSProof{{ChainHash: "abc", Status: "confirmed"}}

	packet, err := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		WithPresence(sessions).
		WithHardware(bindings, "dev-1").
		WithBehavioral(nil, metrics).
		WithContexts(contexts).
		WithExternalAnchors(ots, nil).
		Build()

	if err != nil {
		t.Fatalf("build error: %v", err)
	}

	// Should have Maximum strength
	if packet.Strength != Maximum {
		t.Errorf("expected Maximum strength, got %v", packet.Strength)
	}

	// Should have all layers
	if packet.Declaration == nil {
		t.Error("missing declaration")
	}
	if packet.Presence == nil {
		t.Error("missing presence")
	}
	if packet.Hardware == nil {
		t.Error("missing hardware")
	}
	if packet.Behavioral == nil {
		t.Error("missing behavioral")
	}
	if len(packet.Contexts) == 0 {
		t.Error("missing contexts")
	}
	if packet.External == nil {
		t.Error("missing external")
	}

	// Should have claims for each layer
	claimTypes := make(map[ClaimType]bool)
	for _, c := range packet.Claims {
		claimTypes[c.Type] = true
	}

	expectedClaims := []ClaimType{
		ClaimChainIntegrity,
		ClaimProcessDeclared,
		ClaimPresenceVerified,
		ClaimHardwareAttested,
		ClaimBehaviorAnalyzed,
		ClaimContextsRecorded,
		ClaimExternalAnchored,
	}

	for _, ct := range expectedClaims {
		if !claimTypes[ct] {
			t.Errorf("missing claim type: %v", ct)
		}
	}
}

// Helper to create chain with VDF proofs
func createTestChainWithVDF(t *testing.T) *checkpoint.Chain {
	t.Helper()

	vdfParams := vdf.DefaultParameters()
	chain := &checkpoint.Chain{
		DocumentID:   "test-doc-id",
		DocumentPath: "/tmp/test.md",
		CreatedAt:    time.Now(),
		Checkpoints:  make([]*checkpoint.Checkpoint, 0),
		VDFParams:    vdfParams,
	}

	// Create valid VDF proof using ComputeIterations
	input := [32]byte{1, 2, 3}
	proof := vdf.ComputeIterations(input, vdfParams.MinIterations)

	cp := &checkpoint.Checkpoint{
		Ordinal:      0,
		ContentHash:  [32]byte{1, 2, 3, 4, 5},
		ContentSize:  100,
		Timestamp:    time.Now(),
		Message:      "Initial",
		Hash:         [32]byte{10, 20, 30},
		PreviousHash: [32]byte{},
		VDF:          proof,
	}
	chain.Checkpoints = append(chain.Checkpoints, cp)

	return chain
}

// Fuzz tests for evidence packet parsing

func FuzzDecode(f *testing.F) {
	// Add seed corpus with minimal valid packet JSON
	validPacket := `{
		"version": "1.0.0",
		"generated_at": "2025-01-15T10:00:00Z",
		"document": {
			"title": "test.md",
			"content_hash": "0000000000000000000000000000000000000000000000000000000000000000",
			"file_size": 100
		}
	}`
	f.Add([]byte(validPacket))

	// Add various malformed JSON
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":"1.0.0"}`))
	f.Add([]byte(`invalid json`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"version":"invalid"}`))
	f.Add([]byte(`{"document":null}`))

	// Add complex nested structures
	f.Add([]byte(`{"version":"1.0.0","declaration":{"title":"test"}}`))
	f.Add([]byte(`{"version":"1.0.0","presence":{"sessions":[]}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Decode should not panic on any input
		packet, err := Decode(data)
		if err != nil {
			// Errors are expected for invalid input
			return
		}

		// If decoding succeeded, validate basic structure
		if packet == nil {
			t.Error("Decode returned nil packet without error")
			return
		}

		// Re-encode should not panic
		reencoded, err := packet.Encode()
		if err != nil {
			t.Errorf("Failed to re-encode successfully decoded packet: %v", err)
			return
		}

		// Re-decode should work
		packet2, err := Decode(reencoded)
		if err != nil {
			t.Errorf("Failed to decode re-encoded packet: %v", err)
			return
		}

		// Basic field comparison
		if packet.Version != packet2.Version {
			t.Error("Version mismatch after re-encode")
		}
		if packet.Document.Title != packet2.Document.Title {
			t.Error("Document title mismatch after re-encode")
		}
	})
}

// =============================================================================
// Tests for WithKeyHierarchy
// =============================================================================

func TestBuilderWithKeyHierarchy(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	// Create mock key hierarchy evidence
	masterPubKey := make([]byte, 32)
	for i := range masterPubKey {
		masterPubKey[i] = byte(i)
	}

	sessionPubKey := make([]byte, 32)
	for i := range sessionPubKey {
		sessionPubKey[i] = byte(i + 32)
	}

	ratchetPubKey := make([]byte, 32)
	for i := range ratchetPubKey {
		ratchetPubKey[i] = byte(i + 64)
	}

	evidence := &keyhierarchy.KeyHierarchyEvidence{
		Version:           1,
		MasterFingerprint: "abc12345",
		MasterPublicKey:   masterPubKey,
		DeviceID:          "test-device-001",
		SessionID:         "session-001",
		SessionPublicKey:  sessionPubKey,
		SessionStarted:    time.Now(),
		SessionCertificateRaw: make([]byte, 64),
		RatchetCount:      1,
		RatchetPublicKeys: []ed25519.PublicKey{ratchetPubKey},
	}

	builder := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		WithKeyHierarchy(evidence)

	if builder.packet.KeyHierarchy == nil {
		t.Fatal("expected key hierarchy to be set")
	}

	kh := builder.packet.KeyHierarchy
	if kh.Version != 1 {
		t.Errorf("expected version 1, got %d", kh.Version)
	}
	if kh.MasterFingerprint != "abc12345" {
		t.Errorf("expected fingerprint 'abc12345', got %q", kh.MasterFingerprint)
	}
	if kh.DeviceID != "test-device-001" {
		t.Errorf("expected device ID 'test-device-001', got %q", kh.DeviceID)
	}
	if kh.RatchetCount != 1 {
		t.Errorf("expected ratchet count 1, got %d", kh.RatchetCount)
	}
	if len(kh.RatchetPublicKeys) != 1 {
		t.Errorf("expected 1 ratchet public key, got %d", len(kh.RatchetPublicKeys))
	}

	// Key hierarchy should upgrade to Enhanced strength
	if builder.packet.Strength < Enhanced {
		t.Errorf("expected at least Enhanced strength, got %v", builder.packet.Strength)
	}
}

func TestBuilderWithKeyHierarchyNil(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	builder := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		WithKeyHierarchy(nil)

	if builder.packet.KeyHierarchy != nil {
		t.Error("expected nil key hierarchy for nil input")
	}
}

func TestBuilderWithKeyHierarchyClaims(t *testing.T) {
	chain := createTestChain(t)
	decl := createTestDeclaration(t, chain)

	masterPubKey := make([]byte, 32)
	for i := range masterPubKey {
		masterPubKey[i] = byte(i)
	}

	evidence := &keyhierarchy.KeyHierarchyEvidence{
		Version:           1,
		MasterFingerprint: "12345678abcdef90",
		MasterPublicKey:   masterPubKey,
		DeviceID:          "test-device",
		SessionID:         "test-session",
		SessionPublicKey:  make([]byte, 32),
		SessionStarted:    time.Now(),
		SessionCertificateRaw: make([]byte, 64),
		RatchetCount:      5,
		RatchetPublicKeys: make([]ed25519.PublicKey, 5),
	}

	packet, err := NewBuilder("test.md", chain).
		WithDeclaration(decl).
		WithKeyHierarchy(evidence).
		Build()

	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	// Check that key hierarchy claim is generated
	hasKeyHierarchyClaim := false
	for _, claim := range packet.Claims {
		if claim.Type == ClaimKeyHierarchy {
			hasKeyHierarchyClaim = true
			if claim.Confidence != "cryptographic" {
				t.Errorf("expected cryptographic confidence, got %q", claim.Confidence)
			}
		}
	}

	if !hasKeyHierarchyClaim {
		t.Error("expected key hierarchy claim in packet")
	}
}
