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

import (
	"errors"
	"regexp"
	"strings"
)

const (
	ContentNullField  = 0
	ContentTypeScript = 1<<iota - 1
	ContentTypeImage
	ContentTypeStylesheet
	ContentTypeXMLHTTPRequest
	ContentTypeWebSocket
	ContentTypeOther
)

type abpFilterEntry struct {

	//Regular expression representing this rule.
	regex *regexp.Regexp

	//List of hosts that this filter should apply to and be excluded from.
	hosts *HostAccessControl

	//True if the apply to hosts is empty
	applyToHostsEmpty bool

	//Bit field of types to apply this filter to.
	typesToApplyTo int64

	//Bit field of types to exclude from this filter
	typesToExclude int64

	//Apply to Third Party only (mod third-party)
	applyToThirdPartyOnly bool

	//Apply to First Party only (mod ~third-party)
	applyToFirstPartyOnly bool

	//When true, case matching is enabled
	matchCase bool

	//Unique ID to prevent this rule from getting ran more then once. Important
	//for Aho-Corasick automa since once a match is found, the regex is ran
	//over the entire string. By the nature of the algorithm, the same
	//keyword could be found multiple times causing the regex to also get
	//executed more then once which is undesirable.
	uid int64
}

type PathAccessControl struct {
	//All filters that block which could not be mapped into one of the
	//general string matching algorithms
	nonMappedBlockFilters []*abpFilterEntry

	//All filters that apply as an exception that could not be mapped into one
	//of the general string matching algorithms
	nonMappedExceptionFilters []*abpFilterEntry

	//All block filters stored in an Aho-Corasick automa
	blockFilters *abpACFilterTrie

	//All exception filters stored in an Aho-Corasick automa
	exceptionFilters *abpACFilterTrie

	//Next Id to assign when a new rule is added
	currentIndex int64

	//Has this instance been compiled?
	compiled bool
}

//Creates a new Ad Block Plus filter
func NewPathAccessControl() (filter *PathAccessControl) {
	filter = new(PathAccessControl)
	filter.blockFilters = newACFilterTrie()
	filter.exceptionFilters = newACFilterTrie()
	filter.currentIndex = 0
	return
}

//*****************************************************************************
//
//		                 Filter Running Code
//
//*****************************************************************************

type abpRuleEvaluator struct {

	//A map of rules already evaluated
	rulesEvaluated map[int64]bool

	//The path to match against
	path string

	//The host of the request
	host string

	//request type
	requestType int64

	//Is this a third party request?
	isThirdPartyRequest bool
}

func (abpFilter *PathAccessControl) EvaluateRequest(host string, path string, thirdParty bool, requestType int64) (blockPath bool, err error) {

	var evaluator abpRuleEvaluator

	evaluator.rulesEvaluated = make(map[int64]bool)
	evaluator.path = path
	evaluator.host = host
	evaluator.requestType = requestType
	evaluator.isThirdPartyRequest = thirdParty

	//First run exception filters that are not mapped
	for i := 0; i < len(abpFilter.nonMappedExceptionFilters); i++ {
		if evaluator.evaluateABRule(abpFilter.nonMappedExceptionFilters[i]) {
			return
		}
	}

	//Run the exception filters in the AC trie
	result, err := abpFilter.exceptionFilters.abpACFilterFind([]rune(strings.ToUpper(path)), &evaluator)

	if err != nil {
		return
	}

	if result {
		return
	}

	//Next run block filters that are not mapped
	for i := 0; i < len(abpFilter.nonMappedBlockFilters); i++ {
		if evaluator.evaluateABRule(abpFilter.nonMappedBlockFilters[i]) {
			blockPath = true
			return
		}
	}

	//Run the block filters in the AC trie
	result, err = abpFilter.blockFilters.abpACFilterFind([]rune(strings.ToUpper(path)), &evaluator)

	if err != nil {
		return
	}

	if result {
		blockPath = true
		return
	}

	return
}

func (pathInfo *abpRuleEvaluator) evaluateABRule(filterEntry *abpFilterEntry) bool {

	//Do not run the same rule more then once
	_, ok := pathInfo.rulesEvaluated[filterEntry.uid]
	if ok {
		return false
	} else {
		pathInfo.rulesEvaluated[filterEntry.uid] = true
	}

	//First check to see if this filter entry even applies to the current request.
	//Check if this filter applies to first party requests
	if filterEntry.applyToFirstPartyOnly && pathInfo.isThirdPartyRequest {
		return false
	}

	//Check if this filter appliesto third party requests
	if filterEntry.applyToThirdPartyOnly && !pathInfo.isThirdPartyRequest {
		return false
	}

	//If anding types to exclude with the current request type produces a
	//non-zero value, this implies that there is an overlap so this filter
	//should not be run on this request.
	if filterEntry.typesToExclude&pathInfo.requestType != ContentNullField {
		return false
	}

	//If mods are set, AND the current request and if the resulting field is null
	//then this filter should not run on this request.
	if filterEntry.typesToApplyTo != ContentNullField && filterEntry.typesToApplyTo&pathInfo.requestType == ContentNullField {
		return false
	}

	//Check to see if this filter should be applied onto this domain
	hostCheckResult := filterEntry.hosts.checkHostStatus(pathInfo.host)

	if hostCheckResult == 1 {
		return false
	} else if !filterEntry.applyToHostsEmpty && hostCheckResult != -1 {
		return false
	}

	//Finally perform the regex comparison and return that result
	return filterEntry.regex.MatchString(pathInfo.path)
}

//*****************************************************************************
//
//		                 Filter Construction Code
//
//*****************************************************************************

//Adds a new filter def to the ad blocker. Note, calling this function after
//calling Compile will return an error.
func (abpFilter *PathAccessControl) AddFilter(def string) (err error) {

	var isExceptionFilter bool = false

	//TODO - Allow live insertions and removals
	if abpFilter.compiled {
		err = errors.New("Can not modify the filter after it has been compiled.")
		return
	}

	pattern, options, isExceptionFilter, ok, err := normalizeFilterDef(def)

	if err != nil || !ok {
		return
	}

	filterEntry := new(abpFilterEntry)
	filterEntry.uid = abpFilter.currentIndex
	filterEntry.applyToHostsEmpty = true
	filterEntry.hosts = NewHostAccessControl()
	abpFilter.currentIndex += 1

	//Load Options into the filter
	if !filterEntry.parseOptions(options, isExceptionFilter) {
		return
	}

	//Next parse the actual filter path and store is in the correct data
	//structure
	err = abpFilter.parseFilter(pattern, filterEntry, isExceptionFilter)

	return
}

//Compiles the internal structures used to do filtering.
func (abpFilter *PathAccessControl) Compile() {
	abpFilter.exceptionFilters.abpACFilterCompile()
	abpFilter.blockFilters.abpACFilterCompile()
	abpFilter.compiled = true
}

func normalizeFilterDef(s string) (pattern, options string, isExceptionFilter bool, ok bool, err error) {

	//Remove leading and tailing white space since it semantically
	//has not meaning.
	s = strings.TrimSpace(s)

	//Remove empty strings
	if s == "" {
		ok = false
		return
	}

	//Remove filter entries which are actually just comments.
	if s[0] == '!' || s[0] == '[' {
		ok = false
		return
	}

	//CSS filters are not supported so treat them like comments and filter them
	//out.
	if strings.Contains(s, "##") || strings.Contains(s, "#@#") {
		ok = false
		return
	}

	if len(s) > 2 && s[:2] == "@@" {
		isExceptionFilter = true
		s = s[2:]
	}

	//Break the filter def into two pieces. The first half is the actual
	//filter path, and the second part is the filter options.
	dollarSignIndex := strings.LastIndex(s, "$")

	pattern = s
	options = ""

	if dollarSignIndex != -1 {
		pattern = s[:dollarSignIndex]

		if dollarSignIndex < len(s) {
			options = s[dollarSignIndex+1:]
		}
	}

	ok = true

	return
}

func (filterEntry *abpFilterEntry) parseOptions(options string, isExceptionFilter bool) bool {
	//If an unhandled modifier is found and the filter is a block filter, that
	//rule is thrown out. Rules which can not be completely and correctly
	//executed by this blocker are not loaded.
	//
	//For exception filters, modifiers that are not recognized are ignored.
	//The intention is to ensure nothing that should not be blocked gets
	//blocked.

	mods := strings.Split(options, ",")
	for i := 0; i < len(mods); i++ {
		mod := mods[i]

		if len(mod) <= 0 {
			continue
		}

		if len(mod) > len("domain") && "domain" == mod[:len("domain")] {

			err := filterEntry.addDomains(mod)
			if err != nil {
				return false
			}

			continue
		}

		//Regular filters first. The ones that can not be made into exception
		//modifiers (Have ~ in front of them)

		switch mod {
		case "match-case":
			filterEntry.matchCase = true
			continue
		default:
			if !isExceptionFilter {
				return false
			} else {
				continue
			}
		}

		var isNegateModifer bool = false

		//Type filters go here.
		field := filterEntry.typesToApplyTo

		if mod[0] == '~' {
			isNegateModifer = true
			mod = mod[1:]

			field = filterEntry.typesToExclude
		}

		switch mod {
		case "third-party":
			if isNegateModifer {
				filterEntry.applyToFirstPartyOnly = true
			} else {
				filterEntry.applyToThirdPartyOnly = true
			}
		case "script":
			field = field | ContentTypeScript
		case "image":
			field = field | ContentTypeImage
		case "stylesheet":
			field = field | ContentTypeStylesheet
		case "xmlhttprequest":
			field = field | ContentTypeXMLHTTPRequest
		case "websocket":
			field = field | ContentTypeWebSocket
		case "other":
			field = field | ContentTypeOther
		default:

			if !isExceptionFilter {
				return false
			}
		}

		if isNegateModifer {
			filterEntry.typesToExclude = field
		} else {
			filterEntry.typesToApplyTo = field
		}

	}

	return true

}

func (filterEntry *abpFilterEntry) addDomains(s string) error {

	indexOfEqual := strings.Index(s, "=")

	if indexOfEqual <= -1 || indexOfEqual+1 >= len(s) {

		return errors.New("Domain modifier is ill formatted")
	}

	s = s[indexOfEqual+1:]

	domains := strings.Split(s, "|")

	for i := 0; i < len(domains); i++ {
		domain := domains[i]
		isExclude := false

		if domain[0] == '~' {

			if len(domain) > 1 {
				continue
			}

			isExclude = true
			domain = domain[1:]
		}

		if isExclude {
			filterEntry.hosts.AddException(domain)
		} else {
			filterEntry.hosts.AddBlockedHost(domain)
			filterEntry.applyToHostsEmpty = false
		}
	}

	return nil
}

func (abpFilter *PathAccessControl) parseFilter(s string, filterEntry *abpFilterEntry, isExceptionFilter bool) (err error) {

	var isRegexFilter bool
	isRegexFilter, err = filterEntry.compileRegex(s)
	if err != nil {
		return
	}

	//RegExp domain filters
	if isRegexFilter || !abpFilter.tryAddToTrie(filterEntry, isExceptionFilter, s) {

		if isExceptionFilter {
			abpFilter.nonMappedExceptionFilters = append(abpFilter.nonMappedExceptionFilters, filterEntry)
		} else {
			abpFilter.nonMappedBlockFilters = append(abpFilter.nonMappedBlockFilters, filterEntry)
		}
	}

	return

}

func (filter *abpFilterEntry) compileRegex(s string) (isRegexFilter bool, err error) {

	matchCase := filter.matchCase

	if len(s) > 1 && s[0] == '/' && s[len(s)-1] == '/' {
		filter.regex, err = regexp.Compile(s[1 : len(s)-1])
		isRegexFilter = true
	} else {

		lockToStart := false
		lockToEnd := false

		if len(s) > 2 && strings.HasPrefix(s, "||") {
			lockToStart = true
			s = s[2:]
		}

		if len(s) > 1 && strings.HasSuffix(s, "|") {
			lockToEnd = true
			s = s[:len(s)-1]
		}

		specialCharacters := []string{"\\", ".", "$", "+", "?", "{", "}", "[", "]", "(", ")", "|"}

		for i := 0; i < len(specialCharacters); i++ {
			s = strings.Replace(s, specialCharacters[i], "\\"+specialCharacters[i], -1)
		}

		s = strings.Replace(s, "*", ".*?", -1)
		s = strings.Replace(s, "^", "($|[\\/?&=;@+!'(),])", -1)

		if lockToStart {
			s = "^" + s
		}

		if lockToEnd {
			s = s + "$"
		}

		if !matchCase {
			s = "(?i)" + s
		}

		filter.regex, err = regexp.Compile(s)
	}

	return
}

func (abpFilter *PathAccessControl) tryAddToTrie(filterEntry *abpFilterEntry, isExceptionFilter bool, path string) bool {

	//Slice the path up until either *, or ^ is encountered. If neither is
	//encountered, then the whole string is inserted into the matching
	//algorithm.
	asteriskIndex := strings.Index(path, "*")
	carrotIndex := strings.Index(path, "^")
	pathToStore := path

	if carrotIndex != -1 || asteriskIndex != -1 {

		var indexToSliceAt int

		if carrotIndex == -1 {
			indexToSliceAt = asteriskIndex
		} else if asteriskIndex == -1 {
			indexToSliceAt = carrotIndex
		} else {

			if asteriskIndex < carrotIndex {
				indexToSliceAt = asteriskIndex
			} else {
				indexToSliceAt = carrotIndex
			}

		}

		if indexToSliceAt <= 0 {
			return false
		}

		pathToStore = pathToStore[:indexToSliceAt]
	}

	//Replace start and end matchers with < and >.
	pathToStore = strings.Replace(pathToStore, "||", "<", -1)
	pathToStore = strings.Replace(pathToStore, "|", ">", -1)
	pathToStore = strings.ToUpper(pathToStore)

	var err error
	var acTrie *abpACFilterTrie

	if isExceptionFilter {
		acTrie = abpFilter.exceptionFilters
	} else {
		acTrie = abpFilter.blockFilters
	}

	err = acTrie.abpACFilterAdd([]rune(pathToStore), filterEntry)

	if err != nil {
		return false
	}

	return true
}
