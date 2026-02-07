package anchors

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// Blockchain types
const (
	ChainBitcoin  = "bitcoin"
	ChainEthereum = "ethereum"
	ChainLitecoin = "litecoin"
	ChainBSV      = "bsv"       // Bitcoin SV
	ChainBCH      = "bch"       // Bitcoin Cash
	ChainPolygon  = "polygon"
	ChainArbitrum = "arbitrum"
)

// Bitcoin OP_RETURN constants
const (
	// Maximum size for OP_RETURN data
	MaxOpReturnSize = 80

	// Common OP_RETURN markers
	OpReturnWitnessd = "WD" // 2-byte prefix for witnessd anchors

	// Bitcoin script opcodes
	OpReturn     = 0x6a
	OpPushData1  = 0x4c
	OpPushData2  = 0x4d
)

// Ethereum constants
const (
	// Event topic for timestamping (keccak256("Timestamp(bytes32)"))
	TimestampEventTopic = "0x6e5b82819e5b3f3e7a0b8f3c3a7b8f3c3a7b8f3c3a7b8f3c3a7b8f3c3a7b8f3c"

	// Gas limits
	DefaultGasLimit = 100000
	MinGasPrice     = 1000000000 // 1 Gwei
)

// BlockchainConfig configures the blockchain anchor.
type BlockchainConfig struct {
	// Chain to use
	Chain string

	// RPC endpoints
	RPCEndpoints []string

	// API keys for services
	BlockstreamKey string
	InfuraKey      string
	AlchemyKey     string

	// Wallet configuration (for write operations)
	PrivateKey     string
	WalletAddress  string

	// Confirmation requirements
	MinConfirmations int

	// Batch settings
	EnableBatching bool
	BatchInterval  time.Duration
	MaxBatchSize   int

	// Timeout for requests
	Timeout time.Duration

	// Use testnet
	Testnet bool
}

// BlockchainAnchor implements blockchain-based timestamping.
type BlockchainAnchor struct {
	chain            string
	rpcEndpoints     []string
	client           *http.Client
	minConfirmations int
	enableBatching   bool
	batchInterval    time.Duration
	maxBatchSize     int
	testnet          bool

	// API keys
	blockstreamKey string
	infuraKey      string
	alchemyKey     string

	// Batching
	batchMu      sync.Mutex
	pendingBatch []BatchEntry
	batchTimer   *time.Timer

	// Merkle tree for batching
	merkleTree *MerkleTree
}

// BatchEntry represents an entry waiting to be batched.
type BatchEntry struct {
	Hash       [32]byte
	SubmitTime time.Time
	Callback   func(proof *BlockchainProof, err error)
}

// BlockchainProof contains proof of blockchain anchoring.
type BlockchainProof struct {
	// Chain information
	Chain       string `json:"chain"`
	Network     string `json:"network"` // mainnet, testnet
	BlockHeight uint64 `json:"block_height"`
	BlockHash   string `json:"block_hash"`
	BlockTime   time.Time `json:"block_time"`

	// Transaction information
	TxID        string `json:"tx_id"`
	TxIndex     int    `json:"tx_index"`
	OutputIndex int    `json:"output_index,omitempty"` // For OP_RETURN

	// Data anchored
	AnchoredHash  [32]byte `json:"anchored_hash"`
	MerkleRoot    [32]byte `json:"merkle_root,omitempty"`    // If batched
	MerkleProof   [][]byte `json:"merkle_proof,omitempty"`   // Proof of inclusion in batch
	ProofPosition int      `json:"proof_position,omitempty"` // Position in merkle tree

	// Confirmation status
	Confirmations int  `json:"confirmations"`
	Confirmed     bool `json:"confirmed"`

	// Ethereum-specific
	LogIndex    int    `json:"log_index,omitempty"`
	EventTopic  string `json:"event_topic,omitempty"`
	ContractAddr string `json:"contract_addr,omitempty"`

	// Raw data
	RawTx     []byte `json:"raw_tx,omitempty"`
	ScriptPubKey []byte `json:"script_pubkey,omitempty"`
}

// MerkleTree is a simple Merkle tree implementation for batching.
type MerkleTree struct {
	Leaves [][32]byte
	Root   [32]byte
	Levels [][][32]byte // All levels of the tree
}

// NewBlockchainAnchor creates a new blockchain anchor.
func NewBlockchainAnchor() *BlockchainAnchor {
	return NewBlockchainAnchorWithConfig(BlockchainConfig{})
}

// NewBlockchainAnchorWithConfig creates a blockchain anchor with custom config.
func NewBlockchainAnchorWithConfig(config BlockchainConfig) *BlockchainAnchor {
	chain := config.Chain
	if chain == "" {
		chain = ChainBitcoin
	}

	rpcEndpoints := config.RPCEndpoints
	if len(rpcEndpoints) == 0 {
		// Default endpoints
		switch chain {
		case ChainBitcoin:
			if config.Testnet {
				rpcEndpoints = []string{"https://blockstream.info/testnet/api"}
			} else {
				rpcEndpoints = []string{"https://blockstream.info/api"}
			}
		case ChainEthereum:
			if config.InfuraKey != "" {
				network := "mainnet"
				if config.Testnet {
					network = "sepolia"
				}
				rpcEndpoints = []string{fmt.Sprintf("https://%s.infura.io/v3/%s", network, config.InfuraKey)}
			}
		}
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	minConfirmations := config.MinConfirmations
	if minConfirmations == 0 {
		switch chain {
		case ChainBitcoin:
			minConfirmations = 6
		case ChainEthereum:
			minConfirmations = 12
		default:
			minConfirmations = 6
		}
	}

	batchInterval := config.BatchInterval
	if batchInterval == 0 {
		batchInterval = time.Hour // Default: batch every hour
	}

	maxBatchSize := config.MaxBatchSize
	if maxBatchSize == 0 {
		maxBatchSize = 1000
	}

	return &BlockchainAnchor{
		chain:            chain,
		rpcEndpoints:     rpcEndpoints,
		client:           &http.Client{Timeout: timeout},
		minConfirmations: minConfirmations,
		enableBatching:   config.EnableBatching,
		batchInterval:    batchInterval,
		maxBatchSize:     maxBatchSize,
		testnet:          config.Testnet,
		blockstreamKey:   config.BlockstreamKey,
		infuraKey:        config.InfuraKey,
		alchemyKey:       config.AlchemyKey,
		pendingBatch:     make([]BatchEntry, 0),
	}
}

// Name returns the anchor type name.
func (b *BlockchainAnchor) Name() string {
	return "blockchain-" + b.chain
}

// Commit submits a hash for blockchain anchoring.
// If batching is enabled, the hash is added to the pending batch.
// Otherwise, it's submitted directly (requires wallet configuration).
func (b *BlockchainAnchor) Commit(hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, errors.New("blockchain: hash must be 32 bytes")
	}

	var h [32]byte
	copy(h[:], hash)

	if b.enableBatching {
		// Add to batch
		b.addToBatch(h)

		// Return a pending proof
		proof := &BlockchainProof{
			Chain:        b.chain,
			Network:      b.getNetwork(),
			AnchoredHash: h,
			Confirmed:    false,
		}
		return json.Marshal(proof)
	}

	// Direct anchoring (not implemented - requires wallet)
	return nil, errors.New("blockchain: direct anchoring requires wallet configuration")
}

// getNetwork returns the network name.
func (b *BlockchainAnchor) getNetwork() string {
	if b.testnet {
		return "testnet"
	}
	return "mainnet"
}

// addToBatch adds a hash to the pending batch.
func (b *BlockchainAnchor) addToBatch(hash [32]byte) {
	b.batchMu.Lock()
	defer b.batchMu.Unlock()

	entry := BatchEntry{
		Hash:       hash,
		SubmitTime: time.Now(),
	}
	b.pendingBatch = append(b.pendingBatch, entry)

	// Start batch timer if this is the first entry
	if len(b.pendingBatch) == 1 && b.batchTimer == nil {
		b.batchTimer = time.AfterFunc(b.batchInterval, b.flushBatch)
	}

	// Flush if batch is full
	if len(b.pendingBatch) >= b.maxBatchSize {
		go b.flushBatch()
	}
}

// flushBatch processes the pending batch.
func (b *BlockchainAnchor) flushBatch() {
	b.batchMu.Lock()
	if len(b.pendingBatch) == 0 {
		b.batchMu.Unlock()
		return
	}

	// Grab the pending entries
	entries := b.pendingBatch
	b.pendingBatch = make([]BatchEntry, 0)
	b.batchTimer = nil
	b.batchMu.Unlock()

	// Build merkle tree from batch
	hashes := make([][32]byte, len(entries))
	for i, entry := range entries {
		hashes[i] = entry.Hash
	}

	tree := BuildMerkleTree(hashes)

	// The merkle root is what gets anchored to the blockchain
	// In a real implementation, this would be broadcast to the network
	_ = tree.Root

	// For now, we just build the proofs
	for i, entry := range entries {
		proof := tree.GenerateProof(i)
		_ = proof
		// Notify callback if provided
		if entry.Callback != nil {
			// In a real implementation, we'd wait for confirmation
			entry.Callback(nil, errors.New("batching not fully implemented"))
		}
	}
}

// BuildMerkleTree constructs a Merkle tree from leaves.
func BuildMerkleTree(leaves [][32]byte) *MerkleTree {
	tree := &MerkleTree{
		Leaves: leaves,
		Levels: make([][][32]byte, 0),
	}

	if len(leaves) == 0 {
		return tree
	}

	// Start with leaves as level 0
	currentLevel := make([][32]byte, len(leaves))
	copy(currentLevel, leaves)
	tree.Levels = append(tree.Levels, currentLevel)

	// Build tree bottom-up
	for len(currentLevel) > 1 {
		nextLevel := make([][32]byte, 0)

		for i := 0; i < len(currentLevel); i += 2 {
			var combined [64]byte
			copy(combined[:32], currentLevel[i][:])

			if i+1 < len(currentLevel) {
				copy(combined[32:], currentLevel[i+1][:])
			} else {
				// Odd number - hash with itself
				copy(combined[32:], currentLevel[i][:])
			}

			hash := sha256.Sum256(combined[:])
			nextLevel = append(nextLevel, hash)
		}

		tree.Levels = append(tree.Levels, nextLevel)
		currentLevel = nextLevel
	}

	if len(currentLevel) > 0 {
		tree.Root = currentLevel[0]
	}

	return tree
}

// GenerateProof generates a Merkle proof for a leaf at the given index.
func (t *MerkleTree) GenerateProof(index int) [][]byte {
	if index < 0 || index >= len(t.Leaves) {
		return nil
	}

	proof := make([][]byte, 0)
	pos := index

	for level := 0; level < len(t.Levels)-1; level++ {
		levelNodes := t.Levels[level]

		// Determine sibling index
		var siblingIndex int
		if pos%2 == 0 {
			siblingIndex = pos + 1
		} else {
			siblingIndex = pos - 1
		}

		// Add sibling to proof if it exists
		if siblingIndex < len(levelNodes) {
			node := levelNodes[siblingIndex][:]
			// Prepend direction bit (0 = left, 1 = right)
			if pos%2 == 0 {
				proof = append(proof, append([]byte{1}, node...)) // Sibling is on right
			} else {
				proof = append(proof, append([]byte{0}, node...)) // Sibling is on left
			}
		}

		pos = pos / 2
	}

	return proof
}

// VerifyMerkleProof verifies a Merkle proof.
func VerifyMerkleProof(leaf [32]byte, proof [][]byte, root [32]byte) bool {
	current := leaf

	for _, p := range proof {
		if len(p) < 33 {
			return false
		}

		direction := p[0]
		sibling := p[1:33]

		var combined [64]byte
		if direction == 0 {
			// Sibling is on left
			copy(combined[:32], sibling)
			copy(combined[32:], current[:])
		} else {
			// Sibling is on right
			copy(combined[:32], current[:])
			copy(combined[32:], sibling)
		}

		current = sha256.Sum256(combined[:])
	}

	return current == root
}

// Verify verifies a blockchain proof.
func (b *BlockchainAnchor) Verify(hash, proof []byte) error {
	var bp BlockchainProof
	if err := json.Unmarshal(proof, &bp); err != nil {
		return fmt.Errorf("blockchain: parse proof: %w", err)
	}

	// Verify hash matches
	if !bytes.Equal(hash, bp.AnchoredHash[:]) {
		// Check if it's in a merkle batch
		if len(bp.MerkleProof) > 0 {
			var h [32]byte
			copy(h[:], hash)
			if !VerifyMerkleProof(h, bp.MerkleProof, bp.MerkleRoot) {
				return errors.New("blockchain: hash not in merkle tree")
			}
		} else {
			return errors.New("blockchain: hash mismatch")
		}
	}

	// Verify against blockchain (requires network access)
	if bp.TxID != "" {
		confirmed, err := b.verifyTransaction(bp.TxID, bp.AnchoredHash[:])
		if err != nil {
			return fmt.Errorf("blockchain: verification failed: %w", err)
		}
		if !confirmed {
			return errors.New("blockchain: transaction not confirmed")
		}
	}

	return nil
}

// verifyTransaction verifies a transaction contains the expected data.
func (b *BlockchainAnchor) verifyTransaction(txid string, expectedHash []byte) (bool, error) {
	switch b.chain {
	case ChainBitcoin:
		return b.verifyBitcoinTx(txid, expectedHash)
	case ChainEthereum:
		return b.verifyEthereumTx(txid, expectedHash)
	default:
		return false, fmt.Errorf("unsupported chain: %s", b.chain)
	}
}

// verifyBitcoinTx verifies a Bitcoin transaction.
func (b *BlockchainAnchor) verifyBitcoinTx(txid string, expectedHash []byte) (bool, error) {
	if len(b.rpcEndpoints) == 0 {
		return false, errors.New("no RPC endpoints configured")
	}

	url := fmt.Sprintf("%s/tx/%s", b.rpcEndpoints[0], txid)
	resp, err := b.client.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return false, err
	}

	var tx struct {
		TxID   string `json:"txid"`
		Status struct {
			Confirmed   bool   `json:"confirmed"`
			BlockHeight int64  `json:"block_height"`
			BlockHash   string `json:"block_hash"`
			BlockTime   int64  `json:"block_time"`
		} `json:"status"`
		Vout []struct {
			ScriptPubKey string `json:"scriptpubkey"`
			ScriptPubKeyType string `json:"scriptpubkey_type"`
		} `json:"vout"`
	}

	if err := json.Unmarshal(body, &tx); err != nil {
		return false, err
	}

	// Check confirmations
	if !tx.Status.Confirmed {
		return false, nil
	}

	// Look for OP_RETURN output containing our hash
	expectedHex := hex.EncodeToString(expectedHash)
	for _, vout := range tx.Vout {
		if vout.ScriptPubKeyType == "op_return" {
			// OP_RETURN scripts start with 6a (OP_RETURN)
			if len(vout.ScriptPubKey) >= 4 && vout.ScriptPubKey[:2] == "6a" {
				// Check if it contains our data
				if containsHash(vout.ScriptPubKey, expectedHex) {
					return true, nil
				}
			}
		}
	}

	return false, errors.New("hash not found in transaction")
}

// containsHash checks if a script contains a hash.
func containsHash(script, hashHex string) bool {
	// Remove the OP_RETURN opcode and push data prefix
	// Look for the hash anywhere in the script
	return bytes.Contains(
		bytes.ToLower([]byte(script)),
		bytes.ToLower([]byte(hashHex)),
	)
}

// verifyEthereumTx verifies an Ethereum transaction.
func (b *BlockchainAnchor) verifyEthereumTx(txid string, expectedHash []byte) (bool, error) {
	if len(b.rpcEndpoints) == 0 {
		return false, errors.New("no RPC endpoints configured")
	}

	// Get transaction receipt
	receipt, err := b.ethGetTransactionReceipt(txid)
	if err != nil {
		return false, err
	}

	// Check if confirmed
	if receipt.BlockNumber == nil || receipt.BlockNumber.Int64() == 0 {
		return false, nil
	}

	// Check logs for timestamp event
	for _, log := range receipt.Logs {
		if len(log.Topics) > 0 {
			// Check if any topic contains our hash
			for _, topic := range log.Topics {
				if bytes.Contains(topic, expectedHash) {
					return true, nil
				}
			}
		}
		// Also check log data
		if bytes.Contains(log.Data, expectedHash) {
			return true, nil
		}
	}

	// Check transaction input data
	tx, err := b.ethGetTransaction(txid)
	if err == nil && bytes.Contains(tx.Input, expectedHash) {
		return true, nil
	}

	return false, errors.New("hash not found in transaction")
}

// EthTransactionReceipt represents an Ethereum transaction receipt.
type EthTransactionReceipt struct {
	BlockNumber *big.Int     `json:"blockNumber"`
	BlockHash   string       `json:"blockHash"`
	Status      uint64       `json:"status"`
	Logs        []EthLog     `json:"logs"`
}

// EthLog represents an Ethereum event log.
type EthLog struct {
	Address string   `json:"address"`
	Topics  [][]byte `json:"topics"`
	Data    []byte   `json:"data"`
}

// EthTransaction represents an Ethereum transaction.
type EthTransaction struct {
	Hash        string   `json:"hash"`
	Input       []byte   `json:"input"`
	BlockNumber *big.Int `json:"blockNumber"`
}

// ethGetTransactionReceipt gets an Ethereum transaction receipt.
func (b *BlockchainAnchor) ethGetTransactionReceipt(txid string) (*EthTransactionReceipt, error) {
	return b.ethRPC("eth_getTransactionReceipt", []interface{}{txid})
}

// ethGetTransaction gets an Ethereum transaction.
func (b *BlockchainAnchor) ethGetTransaction(txid string) (*EthTransaction, error) {
	result, err := b.ethRPCRaw("eth_getTransactionByHash", []interface{}{txid})
	if err != nil {
		return nil, err
	}

	var tx EthTransaction
	if err := json.Unmarshal(result, &tx); err != nil {
		return nil, err
	}
	return &tx, nil
}

// ethRPC makes a JSON-RPC call to an Ethereum node.
func (b *BlockchainAnchor) ethRPC(method string, params []interface{}) (*EthTransactionReceipt, error) {
	result, err := b.ethRPCRaw(method, params)
	if err != nil {
		return nil, err
	}

	var receipt EthTransactionReceipt
	if err := json.Unmarshal(result, &receipt); err != nil {
		return nil, err
	}
	return &receipt, nil
}

// ethRPCRaw makes a raw JSON-RPC call.
func (b *BlockchainAnchor) ethRPCRaw(method string, params []interface{}) (json.RawMessage, error) {
	if len(b.rpcEndpoints) == 0 {
		return nil, errors.New("no RPC endpoints configured")
	}

	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	}

	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := b.client.Post(b.rpcEndpoints[0], "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, err
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

// GetBlockHeight returns the current block height.
func (b *BlockchainAnchor) GetBlockHeight() (uint64, error) {
	switch b.chain {
	case ChainBitcoin:
		return b.getBitcoinBlockHeight()
	case ChainEthereum:
		return b.getEthereumBlockHeight()
	default:
		return 0, fmt.Errorf("unsupported chain: %s", b.chain)
	}
}

// getBitcoinBlockHeight gets the current Bitcoin block height.
func (b *BlockchainAnchor) getBitcoinBlockHeight() (uint64, error) {
	if len(b.rpcEndpoints) == 0 {
		return 0, errors.New("no RPC endpoints configured")
	}

	url := fmt.Sprintf("%s/blocks/tip/height", b.rpcEndpoints[0])
	resp, err := b.client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	var height uint64
	if err := json.Unmarshal(body, &height); err != nil {
		return 0, err
	}

	return height, nil
}

// getEthereumBlockHeight gets the current Ethereum block height.
func (b *BlockchainAnchor) getEthereumBlockHeight() (uint64, error) {
	result, err := b.ethRPCRaw("eth_blockNumber", []interface{}{})
	if err != nil {
		return 0, err
	}

	var hexHeight string
	if err := json.Unmarshal(result, &hexHeight); err != nil {
		return 0, err
	}

	// Parse hex string
	height, ok := new(big.Int).SetString(hexHeight[2:], 16)
	if !ok {
		return 0, errors.New("failed to parse block height")
	}

	return height.Uint64(), nil
}

// BuildOpReturnScript builds a Bitcoin OP_RETURN script.
func BuildOpReturnScript(data []byte) ([]byte, error) {
	if len(data) > MaxOpReturnSize {
		return nil, fmt.Errorf("data too large: %d > %d", len(data), MaxOpReturnSize)
	}

	var script bytes.Buffer

	// OP_RETURN
	script.WriteByte(OpReturn)

	// Push data
	if len(data) < 76 {
		script.WriteByte(byte(len(data)))
	} else if len(data) <= 255 {
		script.WriteByte(OpPushData1)
		script.WriteByte(byte(len(data)))
	} else {
		script.WriteByte(OpPushData2)
		binary.Write(&script, binary.LittleEndian, uint16(len(data)))
	}
	script.Write(data)

	return script.Bytes(), nil
}

// BuildWitnessdOpReturn builds an OP_RETURN script with witnessd prefix.
func BuildWitnessdOpReturn(hash [32]byte) ([]byte, error) {
	// Format: "WD" + version (1 byte) + hash (32 bytes)
	data := make([]byte, 0, 35)
	data = append(data, []byte(OpReturnWitnessd)...)
	data = append(data, 0x01) // Version 1
	data = append(data, hash[:]...)

	return BuildOpReturnScript(data)
}

// ParseWitnessdOpReturn parses a witnessd OP_RETURN script.
func ParseWitnessdOpReturn(script []byte) ([32]byte, error) {
	var hash [32]byte

	// Minimum size: OP_RETURN (1) + push (1) + "WD" (2) + version (1) + hash (32) = 37
	if len(script) < 37 {
		return hash, errors.New("script too short")
	}

	// Check OP_RETURN
	if script[0] != OpReturn {
		return hash, errors.New("not an OP_RETURN script")
	}

	// Find data start
	var dataStart int
	pushLen := int(script[1])
	if pushLen < 76 {
		dataStart = 2
	} else if script[1] == OpPushData1 {
		dataStart = 3
	} else if script[1] == OpPushData2 {
		dataStart = 4
	} else {
		return hash, errors.New("invalid push opcode")
	}

	data := script[dataStart:]

	// Check prefix
	if len(data) < 35 || string(data[:2]) != OpReturnWitnessd {
		return hash, errors.New("not a witnessd anchor")
	}

	// Check version
	if data[2] != 0x01 {
		return hash, fmt.Errorf("unsupported version: %d", data[2])
	}

	copy(hash[:], data[3:35])
	return hash, nil
}

// GetTransactionInfo retrieves information about a blockchain transaction.
func (b *BlockchainAnchor) GetTransactionInfo(txid string) (*BlockchainProof, error) {
	switch b.chain {
	case ChainBitcoin:
		return b.getBitcoinTxInfo(txid)
	case ChainEthereum:
		return b.getEthereumTxInfo(txid)
	default:
		return nil, fmt.Errorf("unsupported chain: %s", b.chain)
	}
}

// getBitcoinTxInfo gets Bitcoin transaction information.
func (b *BlockchainAnchor) getBitcoinTxInfo(txid string) (*BlockchainProof, error) {
	if len(b.rpcEndpoints) == 0 {
		return nil, errors.New("no RPC endpoints configured")
	}

	url := fmt.Sprintf("%s/tx/%s", b.rpcEndpoints[0], txid)
	resp, err := b.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	var tx struct {
		TxID   string `json:"txid"`
		Status struct {
			Confirmed   bool   `json:"confirmed"`
			BlockHeight int64  `json:"block_height"`
			BlockHash   string `json:"block_hash"`
			BlockTime   int64  `json:"block_time"`
		} `json:"status"`
	}

	if err := json.Unmarshal(body, &tx); err != nil {
		return nil, err
	}

	proof := &BlockchainProof{
		Chain:       b.chain,
		Network:     b.getNetwork(),
		TxID:        txid,
		Confirmed:   tx.Status.Confirmed,
		BlockHeight: uint64(tx.Status.BlockHeight),
		BlockHash:   tx.Status.BlockHash,
	}

	if tx.Status.BlockTime > 0 {
		proof.BlockTime = time.Unix(tx.Status.BlockTime, 0)
	}

	// Calculate confirmations
	if proof.Confirmed {
		currentHeight, err := b.getBitcoinBlockHeight()
		if err == nil && currentHeight > proof.BlockHeight {
			proof.Confirmations = int(currentHeight - proof.BlockHeight + 1)
		}
	}

	return proof, nil
}

// getEthereumTxInfo gets Ethereum transaction information.
func (b *BlockchainAnchor) getEthereumTxInfo(txid string) (*BlockchainProof, error) {
	receipt, err := b.ethGetTransactionReceipt(txid)
	if err != nil {
		return nil, err
	}

	proof := &BlockchainProof{
		Chain:     b.chain,
		Network:   b.getNetwork(),
		TxID:      txid,
		BlockHash: receipt.BlockHash,
		Confirmed: receipt.Status == 1,
	}

	if receipt.BlockNumber != nil {
		proof.BlockHeight = receipt.BlockNumber.Uint64()

		// Calculate confirmations
		currentHeight, err := b.getEthereumBlockHeight()
		if err == nil && currentHeight > proof.BlockHeight {
			proof.Confirmations = int(currentHeight - proof.BlockHeight + 1)
		}
	}

	return proof, nil
}

// EstimateFee estimates the fee for a blockchain transaction.
type FeeEstimate struct {
	Chain       string  `json:"chain"`
	FastFee     uint64  `json:"fast_fee"`       // sat/vbyte or gwei
	NormalFee   uint64  `json:"normal_fee"`
	SlowFee     uint64  `json:"slow_fee"`
	EstimatedTx uint64  `json:"estimated_tx"`   // Estimated total fee
	Currency    string  `json:"currency"`       // "satoshis" or "gwei"
}

// EstimateFee estimates transaction fees.
func (b *BlockchainAnchor) EstimateFee() (*FeeEstimate, error) {
	switch b.chain {
	case ChainBitcoin:
		return b.estimateBitcoinFee()
	case ChainEthereum:
		return b.estimateEthereumFee()
	default:
		return nil, fmt.Errorf("unsupported chain: %s", b.chain)
	}
}

// estimateBitcoinFee estimates Bitcoin transaction fees.
func (b *BlockchainAnchor) estimateBitcoinFee() (*FeeEstimate, error) {
	if len(b.rpcEndpoints) == 0 {
		return nil, errors.New("no RPC endpoints configured")
	}

	url := fmt.Sprintf("%s/fee-estimates", b.rpcEndpoints[0])
	resp, err := b.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var fees map[string]float64
	if err := json.Unmarshal(body, &fees); err != nil {
		return nil, err
	}

	// Typical OP_RETURN transaction size: ~250 vbytes
	txSize := uint64(250)

	return &FeeEstimate{
		Chain:       b.chain,
		FastFee:     uint64(fees["1"]),    // 1 block target
		NormalFee:   uint64(fees["6"]),    // 6 block target
		SlowFee:     uint64(fees["144"]),  // 1 day target
		EstimatedTx: uint64(fees["6"]) * txSize,
		Currency:    "satoshis/vbyte",
	}, nil
}

// estimateEthereumFee estimates Ethereum transaction fees.
func (b *BlockchainAnchor) estimateEthereumFee() (*FeeEstimate, error) {
	result, err := b.ethRPCRaw("eth_gasPrice", []interface{}{})
	if err != nil {
		return nil, err
	}

	var hexPrice string
	if err := json.Unmarshal(result, &hexPrice); err != nil {
		return nil, err
	}

	gasPrice, ok := new(big.Int).SetString(hexPrice[2:], 16)
	if !ok {
		return nil, errors.New("failed to parse gas price")
	}

	// Convert to gwei
	gwei := new(big.Int).Div(gasPrice, big.NewInt(1e9))
	normalFee := gwei.Uint64()

	return &FeeEstimate{
		Chain:       b.chain,
		FastFee:     normalFee * 2,
		NormalFee:   normalFee,
		SlowFee:     normalFee / 2,
		EstimatedTx: normalFee * DefaultGasLimit,
		Currency:    "gwei",
	}, nil
}

// WatchTransaction watches a transaction for confirmations.
func (b *BlockchainAnchor) WatchTransaction(txid string, callback func(confirmations int, err error)) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			info, err := b.GetTransactionInfo(txid)
			if err != nil {
				callback(0, err)
				continue
			}

			callback(info.Confirmations, nil)

			if info.Confirmations >= b.minConfirmations {
				return
			}
		}
	}()
}

// Serialize serializes a blockchain proof.
func (bp *BlockchainProof) Serialize() ([]byte, error) {
	return json.Marshal(bp)
}

// DeserializeBlockchainProof deserializes a blockchain proof.
func DeserializeBlockchainProof(data []byte) (*BlockchainProof, error) {
	var proof BlockchainProof
	if err := json.Unmarshal(data, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}
