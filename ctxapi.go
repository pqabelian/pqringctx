package pqringctx

// CTX
const (
	MaxAllowedCtxTxoSize           uint32 = 1024 * 1024      // 2^20, 1M bytes
	MaxAllowedCtxTxWitnessCbTxSize uint32 = 8 * 1024 * 1024  // 2^23, 8M bytes
	MaxAllowedCtxTxWitnessTrTxSize uint32 = 16 * 1024 * 1024 // 2^24, 16M bytes

)

// review done 2025.12.21
