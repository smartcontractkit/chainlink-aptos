package main

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPluginRelayerCloseCurrent(t *testing.T) {
	relay := &testCloser{}
	emitter := &testCloser{}
	p := &pluginRelayer{
		current: &activeRelayer{
			relay:   relay,
			emitter: emitter,
		},
	}

	require.NoError(t, p.closeCurrent())
	require.Nil(t, p.current)
	require.Equal(t, 1, relay.closed)
	require.Equal(t, 1, emitter.closed)
}

func TestPluginRelayerCloseCurrentClearsCurrentOnError(t *testing.T) {
	expectedErr := errors.New("close failed")
	relay := &testCloser{err: expectedErr}
	emitter := &testCloser{}
	p := &pluginRelayer{
		current: &activeRelayer{
			relay:   relay,
			emitter: emitter,
		},
	}

	err := p.closeCurrent()
	require.ErrorIs(t, err, expectedErr)
	require.Nil(t, p.current)
	require.Equal(t, 1, relay.closed)
	require.Equal(t, 1, emitter.closed)
}

type testCloser struct {
	closed int
	err    error
}

func (t *testCloser) Close() error {
	t.closed++
	return t.err
}
