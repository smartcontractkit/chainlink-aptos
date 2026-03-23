package logpoller

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/aptos-labs/aptos-go-sdk"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	commonutils "github.com/smartcontractkit/chainlink-common/pkg/utils"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/config"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/db"
	"github.com/smartcontractkit/chainlink-aptos/relayer/types"
)

type moduleInfo struct {
	name         string
	address      aptos.AccountAddress
	eventConfigs map[string]*config.ChainReaderEvent
	refCount     int
}

type AptosLogPoller struct {
	lggr      logger.Logger
	dbStore   *db.DBStore
	config    *Config
	getClient func() (aptos.AptosRpcClient, error)
	chainInfo types.ChainInfo

	mu      sync.RWMutex
	modules map[string]*moduleInfo

	// cache
	resourceCache            *cache.Cache
	blockCache               *cache.Cache
	eventAccountAddressCache *cache.Cache
	cacheCleanupInterval     time.Duration

	starter        commonutils.StartStopOnce
	eventCtxCancel context.CancelFunc
	txCtxCancel    context.CancelFunc
}

func NewLogPoller(lggr logger.Logger, chainInfo types.ChainInfo, getClient func() (aptos.AptosRpcClient, error), ds sqlutil.DataSource, cfg *Config) (*AptosLogPoller, error) {
	if cfg == nil {
		tmp := DefaultConfigSet
		cfg = &tmp
	}

	dbStore := db.NewDBStore(ds, lggr)

	defaultTTL := 15 * time.Minute
	cleanupInterval := 30 * time.Minute

	return &AptosLogPoller{
		lggr:      logger.Named(lggr, "AptosLogPoller"),
		dbStore:   dbStore,
		config:    cfg,
		getClient: getClient,
		chainInfo: chainInfo,

		modules: make(map[string]*moduleInfo),

		resourceCache:            cache.New(defaultTTL, cleanupInterval),
		blockCache:               cache.New(defaultTTL, cleanupInterval),
		eventAccountAddressCache: cache.New(defaultTTL, cleanupInterval),
		cacheCleanupInterval:     cleanupInterval,
	}, nil
}

func (l *AptosLogPoller) Start(ctx context.Context) error {
	return l.starter.StartOnce(l.Name(), func() error {
		if l.dbStore != nil {
			var syncEventCtx context.Context
			syncEventCtx, l.eventCtxCancel = context.WithCancel(context.Background())
			go l.startEventPolling(syncEventCtx)

			if *l.config.TXPollerDisabled {
				l.lggr.Info("Skipping transaction polling as TXPollerDisabled is set to true")
				return nil
			}

			var syncTxCtx context.Context
			syncTxCtx, l.txCtxCancel = context.WithCancel(context.Background())
			go l.startTxPolling(syncTxCtx)
		}

		return nil
	})
}

func (l *AptosLogPoller) Close() error {
	return l.starter.StopOnce(l.Name(), func() error {
		if l.eventCtxCancel != nil {
			l.eventCtxCancel()
		}

		if l.txCtxCancel != nil {
			l.txCtxCancel()
		}

		return nil
	})
}

func (l *AptosLogPoller) RegisterModule(ctx context.Context, moduleKey string, address aptos.AccountAddress, name string, eventConfigs map[string]*config.ChainReaderEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	info, exists := l.modules[moduleKey]
	if exists {
		if !bytes.Equal(info.address[:], address[:]) {
			return fmt.Errorf("module %s already registered with different address", moduleKey)
		}

		info.refCount++
		l.lggr.Debugw("Incrementing ref count for module", "moduleKey", moduleKey, "newRefCount", info.refCount)
		return nil
	}

	l.lggr.Infow("Registering new module", "moduleKey", moduleKey, "address", address.String())
	l.modules[moduleKey] = &moduleInfo{
		name:         name,
		address:      address,
		eventConfigs: eventConfigs,
		refCount:     1,
	}

	return nil
}

func (l *AptosLogPoller) UnregisterModule(ctx context.Context, moduleKey string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	info, exists := l.modules[moduleKey]
	if !exists {
		return fmt.Errorf("module %s not registered", moduleKey)
	}

	info.refCount--
	l.lggr.Debugw("Decremented ref count for module", "moduleKey", moduleKey, "newRefCount", info.refCount)

	if info.refCount <= 0 {
		l.lggr.Infow("Removing module from logpoller", "moduleKey", moduleKey)
		delete(l.modules, moduleKey)
	}

	return nil
}

func (l *AptosLogPoller) Name() string {
	return l.lggr.Name()
}

func (l *AptosLogPoller) Ready() error {
	return l.starter.Ready()
}

func (l *AptosLogPoller) HealthReport() map[string]error {
	return map[string]error{l.Name(): l.starter.Healthy()}
}

func (l *AptosLogPoller) getEventAccountAddress(cacheKey string) (aptos.AccountAddress, bool) {
	if value, found := l.eventAccountAddressCache.Get(cacheKey); found {
		return value.(aptos.AccountAddress), true
	}
	return aptos.AccountAddress{}, false
}

func (l *AptosLogPoller) setEventAccountAddress(cacheKey string, address aptos.AccountAddress) {
	l.eventAccountAddressCache.Set(cacheKey, address, cache.NoExpiration)
	l.lggr.Debugw("Cached event account address", "key", cacheKey, "address", address.String())
}

func (l *AptosLogPoller) getEventConfig(moduleKey, eventKey string) (aptos.AccountAddress, string, *config.ChainReaderEvent, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	moduleInfo, exists := l.modules[moduleKey]
	if !exists {
		return aptos.AccountAddress{}, "", nil, fmt.Errorf("module %s not registered", moduleKey)
	}

	eventConfig, exists := moduleInfo.eventConfigs[eventKey]
	if !exists {
		return aptos.AccountAddress{}, "", nil, fmt.Errorf("event %s not configured for module %s", eventKey, moduleKey)
	}

	eventAccountAddress, err := l.computeEventAccountAddress(moduleInfo.address, eventConfig)
	if err != nil {
		return aptos.AccountAddress{}, "", nil, fmt.Errorf("failed to compute event account address: %w", err)
	}

	eventHandle := moduleInfo.address.String() + "::" + moduleInfo.name + "::" + eventConfig.EventHandleStructName
	return eventAccountAddress, eventHandle, eventConfig, nil
}

func (l *AptosLogPoller) GetChainInfo() types.ChainInfo {
	return l.chainInfo
}
