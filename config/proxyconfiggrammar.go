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

package config

import (
	"errors"
	"strconv"
)

type Lexeme func(input []rune) (interface{}, []rune, error)

type ConfigStatement struct {
	Name string

	AllowMultiple bool

	Syntax []Lexeme
}

var ListenStatement ConfigStatement = ConfigStatement{
	Name:          "listen",
	AllowMultiple: true,
	Syntax:        []Lexeme{ServerTypeLexeme, StringLexeme},
}

var HttpsCertStatement ConfigStatement = ConfigStatement{
	Name:          "httpscert",
	AllowMultiple: false,
	Syntax:        []Lexeme{StringLexeme, StringLexeme},
}

var HostACLStatement ConfigStatement = ConfigStatement{
	Name:          "hostacl",
	AllowMultiple: true,
	Syntax:        []Lexeme{StringLexeme},
}

var PathACLStatement ConfigStatement = ConfigStatement{
	Name:          "pathacl",
	AllowMultiple: true,
	Syntax:        []Lexeme{StringLexeme},
}

var AllowLocalhostStatement ConfigStatement = ConfigStatement{
	Name:          "allowlocalhost",
	AllowMultiple: false,
	Syntax:        []Lexeme{OnOffLexeme},
}

var LoopDetectionStatement ConfigStatement = ConfigStatement{
	Name:          "loopdetection",
	AllowMultiple: false,
	Syntax:        []Lexeme{OnOffLexeme},
}

var HttpsProxyStatement ConfigStatement = ConfigStatement{
	Name:          "httpsproxy",
	AllowMultiple: false,
	Syntax:        []Lexeme{OnOffLexeme},
}

var HttpProxyStatement ConfigStatement = ConfigStatement{
	Name:          "httpproxy",
	AllowMultiple: false,
	Syntax:        []Lexeme{OnOffLexeme},
}

var RedirectProxyStatement ConfigStatement = ConfigStatement{
	Name:          "redirectproxy",
	AllowMultiple: false,
	Syntax:        []Lexeme{OnOffLexeme},
}

var StaticSiteStatement ConfigStatement = ConfigStatement{
	Name:          "staticsite",
	AllowMultiple: true,
	Syntax:        []Lexeme{StringLexeme, StringLexeme},
}

var StaticSiteHttpsCert ConfigStatement = ConfigStatement{
	Name:          "staticsitecert",
	AllowMultiple: true,
	Syntax:        []Lexeme{StringLexeme, StringLexeme, StringLexeme},
}

var ServerHostnameStatement ConfigStatement = ConfigStatement{
	Name:          "hostname",
	AllowMultiple: false,
	Syntax:        []Lexeme{StringLexeme},
}

func IPLexeme(input []rune) (ip interface{}, unconsumedInput []rune, err error) {
	ip, unconsumedInput, err = ConsumeIP(input)

	return
}

func PortLexeme(input []rune) (port interface{}, unconsumedInput []rune, err error) {
	var portParsed int

	portParsed, unconsumedInput, err = ConsumeInt(input)

	if err != nil {
		return
	}

	if portParsed < 0 || portParsed > 65535 {
		err = errors.New("Port must be between 0 and 65535")
	}

	port = portParsed

	return
}

const (
	ServerTypeHttp     = 1
	ServerTypeHttps    = 2
)

var ServerTypeMap map[string]int = map[string]int{"http": ServerTypeHttp, "https": ServerTypeHttps}

func ServerTypeLexeme(input []rune) (serverType interface{}, unconsumedInput []rune, err error) {

	serverType, unconsumedInput, err = ConsumeEnum(ServerTypeMap, input)

	return
}

var OnOffMap map[string]int = map[string]int{"on": 1, "off": 0}

func OnOffLexeme(input []rune) (onOff interface{}, unconsumedInput []rune, err error) {

	var onOffType int

	onOffType, unconsumedInput, err = ConsumeEnum(OnOffMap, input)

	onOff = (onOffType == 1)

	return
}

func StringLexeme(input []rune) (stringLiteral interface{}, unconsumedInput []rune, err error) {
	stringLiteral, unconsumedInput, err = ConsumeString(input)
	return
}

type SyntaxStatement struct {
	ParsedResult [][]interface{}
}

func (statement *ConfigStatement) ParseCommand(grammar *Grammar, input []rune, seenBefore bool, lastOutput interface{}) (output interface{}, err error) {

	if seenBefore && !statement.AllowMultiple {
		err = errors.New("Statement " + statement.Name + " can not appear multiple times")
		return
	}

	var resultAgg *SyntaxStatement

	if !seenBefore {
		resultAgg = new(SyntaxStatement)
	} else {
		resultAgg = lastOutput.(*SyntaxStatement)
	}

	output = resultAgg

	var resultEntry []interface{}

	for i := 0; i < len(statement.Syntax); i++ {

		input, err = ConsumeWhiteSpace(input, true)
		if err != nil {
			return
		}

		var syntaxOutput interface{}

		syntaxOutput, input, err = statement.Syntax[i](input)
		if err != nil {
			return
		}

		resultEntry = append(resultEntry, syntaxOutput)
	}

	if len(statement.Syntax) != len(resultEntry) {
		err = errors.New("Statement has incomplete syntax. Expected " + strconv.Itoa(len(statement.Syntax)) + " but instead got " + strconv.Itoa(len(resultEntry)))
		return
	}

	resultAgg.ParsedResult = append(resultAgg.ParsedResult, resultEntry)

	return
}

func GetProxyGrammar() (grammar *Grammar) {
	grammar = new(Grammar)
	grammar.CommentIdentifiers = append(grammar.CommentIdentifiers, rune('#'))
	grammar.Tokens = make(map[string]func(*Grammar, []rune, bool, interface{}) (interface{}, error))

	proxyTokens := []ConfigStatement{
		ListenStatement,
		HttpsCertStatement,
		HostACLStatement,
		PathACLStatement,
		AllowLocalhostStatement,
		LoopDetectionStatement,
		StaticSiteStatement,
		StaticSiteHttpsCert,
		HttpsProxyStatement,
		HttpProxyStatement,
		RedirectProxyStatement,
		ServerHostnameStatement,
	}

	for i := 0; i < len(proxyTokens); i++ {
		grammar.Tokens[proxyTokens[i].Name] = proxyTokens[i].ParseCommand
	}

	return
}
