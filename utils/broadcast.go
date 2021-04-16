/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package utils

import (
	"context"
)

// A Broadcaster is a implementation of channels where clients can subscribe
// and unsubscribe to messages. Messages published to the Broadcaster are sent
// to all subcribers.
type Broadcaster struct {
	bufferSize int
	stopped    AtomicBool

	publishCh     chan interface{}
	subscribeCh   chan chan interface{}
	unsubscribeCh chan chan interface{}
	stopCh        chan struct{}
}

func NewBroadcaster() *Broadcaster {
	return &Broadcaster{
		bufferSize: 10,

		publishCh:     make(chan interface{}, 1),
		subscribeCh:   make(chan chan interface{}, 1),
		unsubscribeCh: make(chan chan interface{}, 1),
		stopCh:        make(chan struct{}),
	}
}

func (b *Broadcaster) SetBufferSize(bufferSize int) {
	b.bufferSize = bufferSize
}

func (b *Broadcaster) Start(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}

	subscribers := make(map[chan interface{}]struct{})

	// Single Go routine pumping messages, subscriptions and unsubscriptions.
	for {
		select {

		case messageCh := <-b.subscribeCh:
			// Register subscriber.
			subscribers[messageCh] = struct{}{}

		case messageCh := <-b.unsubscribeCh:
			// Remove subscriber.
			delete(subscribers, messageCh)

		case msg := <-b.publishCh:
			for messageCh := range subscribers {
				// Non blocking send to all subscribers.
				select {
				case messageCh <- msg:
				default:
				}
			}

		case <-b.stopCh:
			// We are done, close all subscribers.
			for messageCh := range subscribers {
				close(messageCh)
			}
			return

		case <-ctx.Done():
			b.Stop()
		}
	}
}

func (b *Broadcaster) Stop() {
	if b.stopped.CompareFalseAndSetTrue() {
		close(b.stopCh)
	}
}

func (b *Broadcaster) Subscribe() chan interface{} {
	messageCh := make(chan interface{}, b.bufferSize)
	b.subscribeCh <- messageCh
	return messageCh
}

func (b *Broadcaster) SubscribeChannel(messageCh chan interface{}) {
	b.subscribeCh <- messageCh
}

func (b *Broadcaster) Unsubscribe(messageCh chan interface{}) {
	b.unsubscribeCh <- messageCh
	close(messageCh)
}

func (b *Broadcaster) Broadcast(msg interface{}) {
	b.publishCh <- msg
}
