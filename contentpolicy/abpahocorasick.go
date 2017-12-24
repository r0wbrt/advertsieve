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

import "errors"

//*****************************************************************************
//
//		       Aho-Corasick String Keyword Matching Algorithm
//
//*****************************************************************************

//Alfred V. Aho and Margaret J. Corasick. 1975. Efficient string matching: an
//aid to bibliographic search. Commun. ACM 18, 6 (June 1975),
//333-340. DOI=http://dx.doi.org/10.1145/360825.360855

//https://pdfs.semanticscholar.org/3547/ac839d02f6efe3f6f76a8289738a22528442.pdf

type abpACFilterTrie struct {

	//Root node of the search tree
	root *abpACFilterNode

	//The tree must be compiled before use
	compiled bool
}

//A node in the ACFilter trie
type abpACFilterNode struct {

	//Indicates if this is a root node
	rootNode bool

	//A map from rune to child
	children map[rune]*abpACFilterNode

	//Node to go to on failure
	failureNode *abpACFilterNode

	//Rules associated with this node
	rules []*abpFilterEntry
}

func newACFilterTrie() *abpACFilterTrie {
	trie := new(abpACFilterTrie)
	trie.root = newACFilterNode()
	trie.root.rootNode = true
	return trie
}

func newACFilterNode() (node *abpACFilterNode) {
	node = new(abpACFilterNode)
	node.children = make(map[rune]*abpACFilterNode)
	return
}

func (trie *abpACFilterTrie) abpACFilterAdd(path []rune, entry *abpFilterEntry) error {

	if trie.compiled {
		return errors.New("Can not add new nodes after the Aho-Corasick has been compiled.")
	}

	abpACRecursiveFilterInsert(path, trie.root, entry)

	return nil
}

//Using recursion, this function insets a rule into the tree
func abpACRecursiveFilterInsert(name []rune, node *abpACFilterNode, entry *abpFilterEntry) {

	//When len = 1 (or less then 1 to handle the less the case) the location
	//we want to store this node has been found
	if len(name) <= 0 {
		node.rules = append(node.rules, entry)
		return
	} else {

		//Otherwise, continue deeper into the tree. Adding new entries to the
		//children map as needed.

		pos := name[0] //Get the next rune to determine what child to go to.

		//Create the child, if it does not exist
		child, ok := node.children[pos]
		if !ok {
			child = newACFilterNode()
			node.children[pos] = child
		}

		//Go to the next node
		abpACRecursiveFilterInsert(name[1:], child, entry)
		return
	}
}

type iabpRuleEvaluator interface {
	evaluateABRule(*abpFilterEntry) bool
}

func (trie *abpACFilterTrie) abpACFilterFind(path []rune, evaluator iabpRuleEvaluator) (pathFound bool, err error) {

	pathFound = false

	if !trie.compiled {
		err = errors.New("The Aho-Corasick tree must be compiled before used.")
		return
	}

	//Start at the root node
	currentNode := trie.root
	var ai rune

	//Continue looping while there are still characters in the string.
	for len(path) != 0 {

		//Get the character to evaluate
		ai = path[0]

		//Run the GOTO function on this character. If this character has no
		//associated state transition, the GOTO function will return null
		//indicating a failure. In that case, keep looping on the failure function
		//until we find a node that does not have a failing goto function.
		nextNode := abpACFilterGoto(currentNode, ai)
		if nextNode == nil {

			failNode := currentNode
			for nextNode == nil {
				failNode = abpACFilterFailure(failNode)
				nextNode = abpACFilterGoto(failNode, ai)
			}
		}

		currentNode = nextNode

		//evaluate all the outputs
		for i := 0; i < len(currentNode.rules); i++ {
			result := evaluator.evaluateABRule(currentNode.rules[i])
			if result {
				pathFound = true
				return
			}
		}

		path = path[1:]
	}

	return
}

func abpACFilterGoto(node *abpACFilterNode, character rune) *abpACFilterNode {
	child, ok := node.children[character]
	if !ok {

		//The root node has no failures. Its failure function is undefined as
		//all GOTO's on the root either go somewhere else or back to the root.
		if node.rootNode {
			return node
		} else {
			return nil
		}
	}

	return child
}

func abpACFilterFailure(node *abpACFilterNode) *abpACFilterNode {

	//Failure is undefined on the root, so panic if this is called on the root
	//node.
	if node.rootNode {
		panic("Failure function should never be called on the root. It is undefined.")
	}
	return node.failureNode
}

func (trie *abpACFilterTrie) abpACFilterCompile() {

	//Already compiled so quit
	if trie.compiled {
		return
	}

	//Mark the trie as compiled
	trie.compiled = true

	nodeQueue := newAbpACFilterQueue()

	//First, the failure function of all nodes
	//direct children of the root is the root.
	for _, v := range trie.root.children {
		v.failureNode = trie.root
		nodeQueue.abpACFilterQueueInsert(v)
	}

	//Next compute the failure function for all children
	//that are children of the children of the root.
	for !nodeQueue.abpACFilterQueueEmpty() {
		r := nodeQueue.abpACFilterQueueGet()

		//Loop over children computing their fail function and adding them to
		//the queue for grandchildren processing
		for a, child := range r.children {
			nodeQueue.abpACFilterQueueInsert(child)
			abpACFilterComputeFailureFunc(r, a, child)
			abpACFilterUpdateOutput(child)
		}
	}
}

func abpACFilterComputeFailureFunc(r *abpACFilterNode, a rune, child *abpACFilterNode) {

	var gotoNode *abpACFilterNode

	for gotoNode == nil {
		r = abpACFilterFailure(r)
		gotoNode = abpACFilterGoto(r, a)
	}

	child.failureNode = gotoNode
}

func abpACFilterUpdateOutput(node *abpACFilterNode) {

	failNode := abpACFilterFailure(node)

	for i := 0; i < len(failNode.rules); i++ {
		node.rules = append(node.rules, failNode.rules[i])
	}
}

//*****************************************************************************
//
//		                   FIFO Queue
//
//*****************************************************************************

type abpACFilterQueueNode struct {
	node *abpACFilterNode
	next *abpACFilterQueueNode
}

type abpACFilterQueue struct {
	first *abpACFilterQueueNode
	last  *abpACFilterQueueNode
}

func newAbpACFilterQueue() (queue *abpACFilterQueue) {
	queue = new(abpACFilterQueue)
	return
}

func (queue *abpACFilterQueue) abpACFilterQueueInsert(node *abpACFilterNode) {

	queueNode := new(abpACFilterQueueNode)

	queueNode.node = node

	if queue.last != nil {
		queue.last.next = queueNode
		queue.last = queueNode
	} else {
		queue.first = queueNode
		queue.last = queueNode
	}

	return
}
func (queue *abpACFilterQueue) abpACFilterQueueGet() (node *abpACFilterNode) {

	if queue.first == nil {
		node = nil
		return
	}

	queueNode := queue.first

	node = queueNode.node

	queue.first = queueNode.next

	if queue.first == nil {
		queue.last = nil
	}

	return
}

func (queue *abpACFilterQueue) abpACFilterQueueEmpty() bool {

	return (queue.first == nil)
}
