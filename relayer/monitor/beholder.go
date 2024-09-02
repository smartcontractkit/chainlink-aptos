package monitor

import (
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/runtime/protoimpl"
)

type BeholderClient struct {
	lggr logger.Logger
}

func NewBeholderClient(lggr logger.Logger) *BeholderClient {
	return &BeholderClient{lggr}
}

func (c *BeholderClient) Emit(m proto.Message) error {
	_, err := proto.Marshal(m)
	if err != nil {
		return err
	}

	protoName := protoimpl.X.MessageTypeOf(m).Descriptor().FullName()
	protoStr := protoimpl.X.MessageStringOf(m)
	c.lggr.Infow("[Beholder.emit]", "name", protoName, "message", protoStr)

	return nil
}
