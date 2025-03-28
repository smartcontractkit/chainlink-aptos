package bind

import (
	"reflect"
	"testing"

	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
)

func Test_createChunks(t *testing.T) {
	t.Parallel()
	type args struct {
		output        compile.CompiledPackage
		chunkSizeByte uint
	}
	tests := []struct {
		name    string
		args    args
		want    []ChunkedPayload
		wantErr bool
	}{
		{
			name: "Mix metadata and bytecode",
			args: args{
				output: compile.CompiledPackage{
					Metadata: []byte{1, 2, 3},
					Bytecode: [][]byte{
						{1, 2, 3},
						{4, 5, 6},
					},
				},
				chunkSizeByte: 2,
			},
			want: []ChunkedPayload{
				{
					Metadata:    []byte{1, 2},
					CodeIndices: nil,
					Chunks:      nil,
				},
				{
					Metadata:    []byte{3},
					CodeIndices: []uint16{0},
					Chunks:      [][]byte{{1}},
				},
				{
					Metadata:    nil,
					CodeIndices: []uint16{0},
					Chunks:      [][]byte{{2, 3}},
				},
				{
					Metadata:    nil,
					CodeIndices: []uint16{1},
					Chunks:      [][]byte{{4, 5}},
				},
				{
					Metadata:    nil,
					CodeIndices: []uint16{1},
					Chunks:      [][]byte{{6}},
				},
			},
			wantErr: false,
		},
		{
			name: "Multiple bytecodes in one chunk",
			args: args{
				output: compile.CompiledPackage{
					Metadata: []byte{1, 2, 3, 4, 5},
					Bytecode: [][]byte{
						{1},
						{2},
						{3},
						{4, 5},
						{6, 7, 8, 9, 10},
					},
				},
				chunkSizeByte: 3,
			},
			want: []ChunkedPayload{
				{
					Metadata: []byte{1, 2, 3},
				},
				{
					Metadata:    []byte{4, 5},
					CodeIndices: []uint16{0},
					Chunks:      [][]byte{{1}},
				},
				{
					CodeIndices: []uint16{1, 2, 3},
					Chunks:      [][]byte{{2}, {3}, {4}},
				},
				{
					CodeIndices: []uint16{3, 4},
					Chunks:      [][]byte{{5}, {6, 7}},
				},
				{
					CodeIndices: []uint16{4},
					Chunks:      [][]byte{{8, 9, 10}},
				},
			},
			wantErr: false,
		},
		{
			name: "All output fitting in one chunk",
			args: args{
				output: compile.CompiledPackage{
					Metadata: []byte{1, 2, 3, 4, 5},
					Bytecode: [][]byte{
						{1},
						{23},
						{4, 5},
						{6, 7, 8, 9, 10},
						{11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
						{21},
					},
				},
				chunkSizeByte: 500,
			},
			want: []ChunkedPayload{
				{
					Metadata:    []byte{1, 2, 3, 4, 5},
					CodeIndices: []uint16{0, 1, 2, 3, 4, 5},
					Chunks: [][]byte{
						{1},
						{23},
						{4, 5},
						{6, 7, 8, 9, 10},
						{11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
						{21},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "One bytecode split into three output chunks",
			args: args{
				output: compile.CompiledPackage{
					Metadata: []byte{0, 0},
					Bytecode: [][]byte{
						{1, 2, 3},
						{4, 5, 6, 7}, // This bytecode will be split into three output chunks - 2,3,4
						{8, 9, 10},
					},
				},
				chunkSizeByte: 2,
			},
			want: []ChunkedPayload{
				{
					Metadata:    []byte{0, 0},
					CodeIndices: nil,
					Chunks:      nil,
				},
				{
					Metadata:    nil,
					CodeIndices: []uint16{0},
					Chunks:      [][]byte{{1, 2}},
				},
				{
					Metadata:    nil,
					CodeIndices: []uint16{0, 1},
					Chunks:      [][]byte{{3}, {4}},
				},
				{
					Metadata:    nil,
					CodeIndices: []uint16{1},
					Chunks:      [][]byte{{5, 6}},
				},
				{
					Metadata:    nil,
					CodeIndices: []uint16{1, 2},
					Chunks:      [][]byte{{7}, {8}},
				},
				{
					Metadata:    nil,
					CodeIndices: []uint16{2},
					Chunks:      [][]byte{{9, 10}},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := CreateChunks(tt.args.output, tt.args.chunkSizeByte)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateChunks() error = %+v, wantErr %+v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateChunks() got = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestAssembleChunks(t *testing.T) {
	tests := []struct {
		name         string
		input        []ChunkedPayload
		wantMetadata []byte
		wantBytecode [][]byte
	}{
		{
			name: "Mixed Metadata and Chunks",
			input: []ChunkedPayload{
				{
					Metadata: []byte{1, 2},
				},
				{
					Metadata:    []byte{3},
					CodeIndices: []uint16{0},
					Chunks:      [][]byte{{4}},
				},
				{
					CodeIndices: []uint16{1, 2},
					Chunks:      [][]byte{{5}, {6}},
				},
				{
					CodeIndices: []uint16{3},
					Chunks:      [][]byte{{7, 8}},
				},
			},
			wantMetadata: []byte{1, 2, 3},
			wantBytecode: [][]byte{
				{4},
				{5},
				{6},
				{7, 8},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMetadata, gotBytecode := AssembleChunks(tt.input)
			if !reflect.DeepEqual(gotMetadata, tt.wantMetadata) {
				t.Errorf("AssembleChunks() gotMetadata = %v, want %v", gotMetadata, tt.wantMetadata)
			}
			if !reflect.DeepEqual(gotBytecode, tt.wantBytecode) {
				t.Errorf("AssembleChunks() gotBytecode = %v, want %v", gotBytecode, tt.wantBytecode)
			}
		})
	}
}
