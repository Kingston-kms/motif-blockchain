package evmmodule

import (
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	//"fmt"
	"github.com/motifd/motif-blockchain/evmcore"
	"github.com/motifd/motif-blockchain/gossip/blockproc"
	"github.com/motifd/motif-blockchain/inter"
	"github.com/motifd/motif-blockchain/motif"
	"github.com/motifd/motif-blockchain/utils"
)

type EVMModule struct{}

func New() *EVMModule {
	return &EVMModule{}
}

func (p *EVMModule) Start(block blockproc.BlockCtx, statedb *state.StateDB, reader evmcore.DummyChain, onNewLog func(*types.Log), net motif.Rules) blockproc.EVMProcessor {
	var prevBlockHash common.Hash
	if block.Idx != 0 {
		prevBlockHash = reader.GetHeader(common.Hash{}, uint64(block.Idx-1)).Hash
	}
	return &MotifEVMProcessor{
		block:         block,
		reader:        reader,
		statedb:       statedb,
		onNewLog:      onNewLog,
		net:           net,
		blockIdx:      utils.U64toBig(uint64(block.Idx)),
		prevBlockHash: prevBlockHash,
	}
}

type MotifEVMProcessor struct {
	block    blockproc.BlockCtx
	reader   evmcore.DummyChain
	statedb  *state.StateDB
	onNewLog func(*types.Log)
	net      motif.Rules

	blockIdx      *big.Int
	prevBlockHash common.Hash

	gasUsed uint64

	incomingTxs types.Transactions
	skippedTxs  []uint32
	receipts    types.Receipts
}

func (p *MotifEVMProcessor) evmBlockWith(txs types.Transactions) *evmcore.EvmBlock {
	h := &evmcore.EvmHeader{
		Number:     p.blockIdx,
		Hash:       common.Hash(p.block.Atropos),
		ParentHash: p.prevBlockHash,
		Root:       common.Hash{},
		Time:       p.block.Time,
		Coinbase:   common.Address{},
		GasLimit:   math.MaxUint64,
		GasUsed:    p.gasUsed,
	}

	return evmcore.NewEvmBlock(h, txs)
}

func (p *MotifEVMProcessor) Execute(txs types.Transactions, internal bool) types.Receipts {
	evmProcessor := evmcore.NewStateProcessor(p.net.EvmChainConfig(), p.reader)

	// Process txs
	evmBlock := p.evmBlockWith(txs) 
	receipts, _, skipped, err := evmProcessor.Process(evmBlock, p.statedb, motif.DefaultVMConfig, &p.gasUsed, internal, func(log *types.Log, _ *state.StateDB) {
		p.onNewLog(log)
	})
	if err != nil {
		log.Crit("EVM internal error", "err", err)
	}

	offset := uint32(len(p.incomingTxs))
	if offset > 0 {
		for i, n := range skipped {
			skipped[i] = n + offset
		}
	}

	p.incomingTxs = append(p.incomingTxs, txs...)
	p.skippedTxs = append(p.skippedTxs, skipped...)
	p.receipts = append(p.receipts, receipts...)

	return receipts
}

func (p *MotifEVMProcessor) Finalize() (evmBlock *evmcore.EvmBlock, skippedTxs []uint32, receipts types.Receipts) {
	evmBlock = p.evmBlockWith(
		// Filter skipped transactions. Receipts are filtered already
		inter.FilterSkippedTxs(p.incomingTxs, p.skippedTxs),
	)
	// Get state root
	newStateHash, err := p.statedb.Commit(true)
	if err != nil {
		log.Crit("Failed to commit state", "err", err)
	}
	evmBlock.Root = newStateHash

	return evmBlock, p.skippedTxs, p.receipts
}
