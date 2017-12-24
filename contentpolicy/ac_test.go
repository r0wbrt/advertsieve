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

func TestConstructACTrie(t *testing.T) {
	var acTrie *abpACFilterTrie = newACFilterTrie()
	if acTrie == nil {
		t.Errorf("Creating a new AC Filter trie should not return a null pointer")
	}
}

func TestCompileEmptyACTrie(t *testing.T) {
	var acTrie *abpACFilterTrie = newACFilterTrie()
	acTrie.abpACFilterCompile()
}

func TestCompileNonEmptyACTrie(t *testing.T) {
	var acTrie *abpACFilterTrie = newACFilterTrie()
	var filterEntry *abpFilterEntry = new(abpFilterEntry)
	filterEntry.uid = 777
	var err error = acTrie.abpACFilterAdd([]rune("helloWorld"), filterEntry)

	if err != nil {
		t.Errorf(err.Error())
	}

	acTrie.abpACFilterCompile()
}

type acSearchTestHarness struct {
	rulesFound   []int64
	shortCircuit bool
	calls        int
}

func (harness *acSearchTestHarness) evaluateABRule(rule *abpFilterEntry) bool {

	harness.rulesFound = append(harness.rulesFound, rule.uid)
	harness.calls += 1

	return harness.shortCircuit
}

func TestFindingKeywordInSingleACTrie(t *testing.T) {
	var acTrie *abpACFilterTrie = newACFilterTrie()
	var filterEntry *abpFilterEntry = new(abpFilterEntry)
	filterEntry.uid = 777
	var err error = acTrie.abpACFilterAdd([]rune("helloWorld"), filterEntry)

	if err != nil {
		t.Errorf(err.Error())
	}

	acTrie.abpACFilterCompile()

	var testHarness acSearchTestHarness

	var pathFound bool

	pathFound, err = acTrie.abpACFilterFind([]rune("www.helloWorld.com/kkl"), &testHarness)

	if pathFound {
		t.Errorf("AC Filter find should have returned false")
	}

	if err != nil {
		t.Errorf(err.Error())
	}

	if len(testHarness.rulesFound) < 1 {
		t.Errorf("At least one keyword should have been matched")
	}

	for i := 0; len(testHarness.rulesFound) > i; i++ {
		if testHarness.rulesFound[i] != filterEntry.uid {
			t.Errorf("Unexpected filter was matched")
		}
	}
}

func addKeyword(keyword string, uid int64, acTrie *abpACFilterTrie, t *testing.T) {

	var filterEntry *abpFilterEntry = new(abpFilterEntry)
	filterEntry.uid = uid

	var err error = acTrie.abpACFilterAdd([]rune(keyword), filterEntry)

	if err != nil {
		t.Fatal(err.Error())
	}
}

func expectedKeywordsMatched(keywords []int64, harness *acSearchTestHarness, t *testing.T) {

	if len(harness.rulesFound) < len(keywords) {
		t.Fatalf("Only %d keywords found when %d were expected to be found", len(harness.rulesFound), len(keywords))
	}

	for i := 0; len(harness.rulesFound) > i; i++ {

		var keywordFound bool = false
		for j := 0; len(keywords) > j; j++ {
			if harness.rulesFound[i] == keywords[j] {
				keywordFound = true
				break
			}
		}

		if !keywordFound {
			t.Fatalf("Unexpected filter %d was matched", harness.rulesFound[i])
		}
	}
}

func TestFindingMultipleKeywordsInACTrie1(t *testing.T) {
	var acTrie *abpACFilterTrie = newACFilterTrie()

	addKeyword("she", 0, acTrie, t)
	addKeyword("he", 1, acTrie, t)
	addKeyword("them", 2, acTrie, t)
	addKeyword("his", 3, acTrie, t)

	acTrie.abpACFilterCompile()

	var testHarness acSearchTestHarness

	var pathFound bool
	var err error

	pathFound, err = acTrie.abpACFilterFind([]rune("she was"), &testHarness)

	if pathFound {
		t.Errorf("AC Filter find should have returned false")
	}

	if err != nil {
		t.Errorf(err.Error())
	}

	expectedKeywordsMatched([]int64{0, 1}, &testHarness, t)
}

func TestFindingMultipleKeywordsInACTrie2(t *testing.T) {
	var acTrie *abpACFilterTrie = newACFilterTrie()

	addKeyword("she", 0, acTrie, t)
	addKeyword("he", 1, acTrie, t)
	addKeyword("them", 2, acTrie, t)
	addKeyword("his", 3, acTrie, t)

	acTrie.abpACFilterCompile()

	var testHarness acSearchTestHarness

	var pathFound bool
	var err error

	pathFound, err = acTrie.abpACFilterFind([]rune("No match"), &testHarness)

	if pathFound {
		t.Errorf("AC Filter find should have returned false")
	}

	if err != nil {
		t.Errorf(err.Error())
	}

	expectedKeywordsMatched([]int64{}, &testHarness, t)
}

func TestShortCircuitTrueNoMatchInACTrie(t *testing.T) {
	var acTrie *abpACFilterTrie = newACFilterTrie()

	addKeyword("she", 0, acTrie, t)
	addKeyword("he", 1, acTrie, t)
	addKeyword("them", 2, acTrie, t)
	addKeyword("his", 3, acTrie, t)

	acTrie.abpACFilterCompile()

	var testHarness acSearchTestHarness
	testHarness.shortCircuit = true

	var pathFound bool
	var err error

	pathFound, err = acTrie.abpACFilterFind([]rune("No match"), &testHarness)

	if pathFound {
		t.Errorf("AC Filter find should have returned false")
	}

	if err != nil {
		t.Errorf(err.Error())
	}

	expectedKeywordsMatched([]int64{}, &testHarness, t)
}

func TestShortCircuitTrueMatchInACTrie(t *testing.T) {
	var acTrie *abpACFilterTrie = newACFilterTrie()

	addKeyword("she", 0, acTrie, t)
	addKeyword("he", 1, acTrie, t)
	addKeyword("them", 2, acTrie, t)
	addKeyword("his", 3, acTrie, t)

	acTrie.abpACFilterCompile()

	var testHarness acSearchTestHarness
	testHarness.shortCircuit = true

	var pathFound bool
	var err error

	pathFound, err = acTrie.abpACFilterFind([]rune("Those dogs ate them"), &testHarness)

	if !pathFound {
		t.Errorf("AC Filter find should have returned true")
	}

	if err != nil {
		t.Errorf(err.Error())
	}
}
