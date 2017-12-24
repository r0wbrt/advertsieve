/* Copyright 2017 Robert Christian Taylor. All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package contentpolicy

import "testing"

func TestConstructACQueue(t *testing.T) {
	var queue *abpACFilterQueue = newAbpACFilterQueue()
	if queue == nil {
		t.Errorf("Returned pointer to queue should not have been nil")
	}
}

func TestInsertQueueIsNotEmpty(t *testing.T) {
	var queue *abpACFilterQueue = newAbpACFilterQueue()
	var filterNode *abpACFilterNode = newACFilterNode()

	queue.abpACFilterQueueInsert(filterNode)

	if queue.abpACFilterQueueEmpty() {
		t.Errorf("A node was inserted into the queue, and that node was not consumed so the queue should not be empty")
	}
}

func TestNewlyCreatedQueueIsEmpty(t *testing.T) {
	var queue *abpACFilterQueue = newAbpACFilterQueue()

	if !queue.abpACFilterQueueEmpty() {
		t.Errorf("A newly created queue should be empty")
	}

	if queue.abpACFilterQueueGet() != nil {
		t.Errorf("Calling get on an empty queue should return a nil pointer")
	}
}

func TestQueueHasFifoOrdering(t *testing.T) {
	var queue *abpACFilterQueue = newAbpACFilterQueue()

	var filterNode1 *abpACFilterNode = newACFilterNode()
	filterNode1.children[rune('a')] = nil

	var filterNode2 *abpACFilterNode = newACFilterNode()
	filterNode2.children[rune('b')] = nil

	var filterNode3 *abpACFilterNode = newACFilterNode()
	filterNode3.children[rune('c')] = nil

	queue.abpACFilterQueueInsert(filterNode2)
	queue.abpACFilterQueueInsert(filterNode1)

	node := queue.abpACFilterQueueGet()
	_, ok := node.children[rune('b')]
	if !ok {
		t.Errorf("Queue did not have expected FIFO order")
	}

	if queue.abpACFilterQueueEmpty() {
		t.Errorf("Queue should not be empty. Should have one element as one element has been removed")
	}

	queue.abpACFilterQueueInsert(filterNode3)

	node = queue.abpACFilterQueueGet()
	_, ok = node.children[rune('a')]
	if !ok {
		t.Errorf("Queue did not have expected FIFO order")
	}

	if queue.abpACFilterQueueEmpty() {
		t.Errorf("Queue should not be empty. Should have one element as one element has been removed")
	}

	node = queue.abpACFilterQueueGet()
	_, ok = node.children[rune('c')]
	if !ok {
		t.Errorf("Queue did not have expected FIFO order")
	}

	if !queue.abpACFilterQueueEmpty() {
		t.Errorf("Queue should be empty.")
	}
}
