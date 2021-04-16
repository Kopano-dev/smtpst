/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package utils

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestBroadcaster(t *testing.T) {
	b := NewBroadcaster()
	go b.Start(nil)

	var workers sync.WaitGroup
	var receive sync.WaitGroup

	total := 10

	workerFunc := func(idx int, messageCh chan interface{}) {
		defer workers.Done()
		count := 0
		for message := range messageCh {
			t.Logf("worker %d got message: %v\n", idx, message)
			if message.(string) != fmt.Sprintf("message: %d", count) {
				t.Errorf("worker %d message mismatch: %s, expected %d", idx, message, count)
			}
			count++
			if count == total {
				receive.Done()
			}
		}
		if count < total {
			t.Errorf("worker %d did not receive all messages: %d < %d", idx, count, total)
		}
	}
	for idx := 0; idx < 3; idx++ {
		messageCh := b.Subscribe()
		workers.Add(1)
		receive.Add(1)
		go workerFunc(idx, messageCh)
	}

	doneCh := make(chan struct{})
	go func() {
		// Start publishing.
		for idx := 0; idx < total; idx++ {
			b.Broadcast(fmt.Sprintf("message: %d", idx))
		}
		// Stop after everything was received
		receive.Wait()
		b.Stop()
		// Wait for workers to close properly.
		workers.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
		// All good.
	case <-time.After(10 * time.Second):
		t.Fatalf("timeout waiting for all workers to exit")
	}
}
