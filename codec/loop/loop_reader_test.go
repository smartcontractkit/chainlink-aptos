package loop

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/types"
)

type fakeContractReader struct {
	types.UnimplementedContractReader
	mu          sync.Mutex
	bindCalls   int
	unbindCalls int
}

func (f *fakeContractReader) Bind(_ context.Context, bindings []types.BoundContract) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bindCalls++
	return nil
}

func (f *fakeContractReader) Unbind(_ context.Context, bindings []types.BoundContract) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unbindCalls++
	return nil
}

func TestLoopChainReaderConcurrentMapAccess(t *testing.T) {
	t.Parallel()

	cr := &fakeContractReader{}
	reader := NewLoopChainReader(logger.Test(t), cr).(*loopChainReader)
	ctx := context.Background()

	err := reader.Bind(ctx, []types.BoundContract{
		{Name: "router", Address: "0x1"},
		{Name: "offramp", Address: "0x2"},
	})
	if err != nil {
		t.Fatalf("bind seed contracts: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()

			name := fmt.Sprintf("contract-%d", i%8)
			for j := 0; j < 250; j++ {
				_ = reader.Bind(ctx, []types.BoundContract{
					{Name: name, Address: fmt.Sprintf("0x%x", j)},
				})

				_ = reader.getBindings()
				_ = reader.hasModuleAddress(name)

				_ = reader.Unbind(ctx, []types.BoundContract{{Name: name}})
			}
		}()
	}

	wg.Wait()
}
