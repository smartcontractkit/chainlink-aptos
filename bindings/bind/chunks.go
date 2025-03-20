package bind

import (
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
)

type ChunkedPayload struct {
	Metadata    []byte
	CodeIndices []uint16
	Chunks      [][]byte
}

// CreateChunks splits the metadata and bytecode into chunks of size chunkSizeByte
func CreateChunks(output compile.CompiledPackage, chunkSizeByte uint) ([]ChunkedPayload, error) {
	// This should come up with the most optimal distribution of chunks.
	// It starts by filling the metadata chunks, then fills the bytecode chunks, starting from the first module.
	// The last metadata chunk is filled with additional bytecode if there's still space remaining.
	//
	// Aptos CLI does it simpler by only mixing metadata and bytecode chunks if they can fit completely:
	// https://github.com/aptos-labs/aptos-core/blob/e0002dd4ca29d1b65fe10c555ac730a773a54b2f/aptos-move/framework/src/chunked_publish.rs#L21-L21
	// But this might result in an extra chunk, which is not optimal
	var outputChunks []ChunkedPayload

	// Chunk the metadata
	for i := 0; i < len(output.Metadata); i += int(chunkSizeByte) {
		end := i + int(chunkSizeByte)
		if end > len(output.Metadata) {
			end = len(output.Metadata)
		}
		outputChunks = append(outputChunks, ChunkedPayload{
			Metadata: output.Metadata[i:end],
		})
	}

	lastChunk := ChunkedPayload{}
	taken := 0

	// If the last metadata chunk isn't full yet, pop it and add the first bytecode chunk to it
	if len(outputChunks) > 0 && len(outputChunks[len(outputChunks)-1].Metadata) < int(chunkSizeByte) {
		lastChunk = outputChunks[len(outputChunks)-1]
		outputChunks = outputChunks[:len(outputChunks)-1]
		taken = len(lastChunk.Metadata)
	}

	for i := 0; i < len(output.Bytecode); i++ {
		for start := 0; start < len(output.Bytecode[i]); {
			end := start + min(len(output.Bytecode[i])-start, int(chunkSizeByte)-taken)

			lastChunk.CodeIndices = append(lastChunk.CodeIndices, uint16(i))
			lastChunk.Chunks = append(lastChunk.Chunks, output.Bytecode[i][start:end])

			taken += end - start
			start = end

			if taken == int(chunkSizeByte) {
				// Output chunk is full, move to the next output chunk
				outputChunks = append(outputChunks, lastChunk)
				lastChunk = ChunkedPayload{}
				taken = 0
				continue
			}
		}
	}

	// The last chunk might not be full, but we still need to append it
	if len(lastChunk.Chunks) > 0 {
		outputChunks = append(outputChunks, lastChunk)
	}

	return outputChunks, nil
}

// AssembleChunks takes a chunked payload and assembles it back into the original metadata and bytecode
func AssembleChunks(chunks []ChunkedPayload) (metadata []byte, bytecode [][]byte) {
	metadata = []byte{}
	code := make(map[uint16][]byte)
	lastModuleIdx := uint16(0)
	for _, chunk := range chunks {
		if len(chunk.Metadata) > 0 {
			metadata = append(metadata, chunk.Metadata...)
		}
		for i2, bytes := range chunk.Chunks {
			idx := chunk.CodeIndices[i2]
			code[idx] = append(code[idx], bytes...)
			if idx > lastModuleIdx {
				lastModuleIdx = idx
			}
		}
	}

	i := uint16(0)
	for i <= lastModuleIdx {
		bytecode = append(bytecode, code[i])
		i++
	}
	return metadata, bytecode
}
