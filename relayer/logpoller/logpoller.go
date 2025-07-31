package logpoller

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	commonutils "github.com/smartcontractkit/chainlink-common/pkg/utils"

	"github.com/smartcontractkit/chainlink-aptos/relayer/cache"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/config"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/db"
)

type moduleInfo struct {
	name         string
	address      aptos.AccountAddress
	eventConfigs map[string]*config.ChainReaderEvent
	refCount     int
}

type AptosLogPoller struct {
	lggr    logger.Logger
	dbStore *db.DBStore
	config  *Config
	client  aptos.AptosRpcClient

	mu      sync.RWMutex
	modules map[string]*moduleInfo

	// cache
	resourceCache            *cache.Cache[cache.AccountResourceCacheKey, map[string]any]
	blockCache               *cache.Cache[uint64, *api.Block]
	eventAccountAddressCache *cache.Cache[string, aptos.AccountAddress]
	cacheCleanupInterval     time.Duration

	starter             commonutils.StartStopOnce
	eventCtxCancel      context.CancelFunc
	txCtxCancel         context.CancelFunc
	cachePurgeCtxCancel context.CancelFunc
}

func NewLogPoller(lggr logger.Logger, getClient func() (aptos.AptosRpcClient, error), ds sqlutil.DataSource, cfg *Config) (*AptosLogPoller, error) {
	client, err := getClient()
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		cfg = &DefaultConfigSet
	}

	dbStore := db.NewDBStore(ds, lggr)

	return &AptosLogPoller{
		lggr:    logger.Named(lggr, "AptosLogPoller"),
		dbStore: dbStore,
		config:  cfg,
		client:  client,

		modules: make(map[string]*moduleInfo),

		resourceCache:            cache.NewCache[cache.AccountResourceCacheKey, map[string]any](15*time.Minute, lggr),
		blockCache:               cache.NewCache[uint64, *api.Block](15*time.Minute, lggr),
		eventAccountAddressCache: cache.NewCache[string, aptos.AccountAddress](15*time.Minute, lggr),
		cacheCleanupInterval:     30 * time.Minute,
	}, nil
}

func (l *AptosLogPoller) Start(ctx context.Context) error {
	return l.starter.StartOnce(l.Name(), func() error {
		if l.dbStore != nil {
			var syncEventCtx context.Context
			syncEventCtx, l.eventCtxCancel = context.WithCancel(context.Background())
			go l.startEventPolling(syncEventCtx)

			var syncTxCtx context.Context
			syncTxCtx, l.txCtxCancel = context.WithCancel(context.Background())
			go l.startTxPolling(syncTxCtx)

			var cachePurgeCtx context.Context
			cachePurgeCtx, l.cachePurgeCtxCancel = context.WithCancel(context.Background())
			go l.startCachePurging(cachePurgeCtx)
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

		if l.cachePurgeCtxCancel != nil {
			l.cachePurgeCtxCancel()
		}

		return nil
	})
}

func (l *AptosLogPoller) startCachePurging(ctx context.Context) {
	l.lggr.Infow("Cache purging goroutine started")
	defer l.lggr.Infow("Cache purging goroutine exited")

	ticker := time.NewTicker(l.cacheCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			resourcesPurged := l.resourceCache.Purge()
			blocksPurged := l.blockCache.Purge()
			eventAddressesesPurged := l.eventAccountAddressCache.Purge()

			if resourcesPurged > 0 || blocksPurged > 0 || eventAddressesesPurged > 0 {
				l.lggr.Debugw("Purged expired cache entries",
					"resources", resourcesPurged,
					"blocks", blocksPurged,
					"eventAddresses", eventAddressesesPurged)
			}

		case <-ctx.Done():
			l.lggr.Infow("Cache purging stopped")
			return
		}
	}
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
	return l.eventAccountAddressCache.Get(cacheKey)
}

func (l *AptosLogPoller) setEventAccountAddress(cacheKey string, address aptos.AccountAddress) {
	l.eventAccountAddressCache.SetPermanent(cacheKey, address)
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
