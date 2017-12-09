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
	"bufio"
	"errors"
	"io"
	"net"
	"strconv"
)

type Grammar struct {
	CommentIdentifiers []rune
	Tokens             map[string]func(*Grammar, []rune, bool, interface{}) (interface{}, error)
}

const (
	MaxLineLength = 4096
)

func (grammar *Grammar) Parse(r io.Reader) (result map[string]interface{}, err error) {

	var commandEncounteredMap map[string]bool = make(map[string]bool)
	result = make(map[string]interface{})

	var reader *bufio.Reader = bufio.NewReaderSize(r, MaxLineLength)

	var line []byte
	var isPrefix bool

	for {
		line, isPrefix, err = reader.ReadLine()

		if err != nil {
			if err == io.EOF {
				err = nil
				break
			} else {
				return
			}
		}

		if isPrefix {
			err = errors.New("Config Line was too long. Max line length is 4096 bytes.")
			return
		}

		lineRune := []rune(string(line))

		//Consume any leading white space if it exists.
		lineRune, err = ConsumeWhiteSpace(lineRune, false)

		if err != nil {
			return
		}

		//If the whole string is white space, move on.
		if len(line) <= 0 {
			continue
		}

		//Check if next char is a comment, if it is then move onto next line.
		if IsCommentCharacter(grammar.CommentIdentifiers, lineRune[0]) {
			continue
		}

		//Extract the command
		var command []rune
		command, lineRune, err = ConsumeLiteral(lineRune)

		if err != nil {
			return
		}

		//Get the handler for the supplied command
		var ok bool
		var handler func(*Grammar, []rune, bool, interface{}) (interface{}, error)

		handler, ok = grammar.Tokens[string(command)]

		if !ok {
			err = errors.New("Unrecognized command " + string(command))
			return
		}

		//Keep track of encountered commands, setting the encountered flag to
		//true when each command is encountered.
		_, ok = commandEncounteredMap[string(command)]
		if !ok {
			commandEncounteredMap[string(command)] = true
		}

		//Load the previous commands result
		v, _ := result[string(command)]

		//Run the handler and then restore the result.
		v, err = handler(grammar, lineRune, ok, v)

		if err != nil {
			return
		}

		result[string(command)] = v
	}

	return
}

func EndTokenParser(grammar *Grammar, input []rune) error {

	for {

		if len(input) <= 0 {
			break
		}

		c := input[0]

		if !IsWhiteSpace(c) {
			if !IsCommentCharacter(grammar.CommentIdentifiers, c) {
				return errors.New("Unexpected Character")
			}
		}

		input = input[1:]
	}

	return nil

}

func IsCommentCharacter(chars []rune, char rune) bool {
	for i := 0; i < len(chars); i++ {
		if chars[i] == char {
			return true
		}
	}

	return false
}

func ConsumeEnum(enumMap map[string]int, input []rune) (enumInt int, unconsumedInput []rune, err error) {

	var literal []rune

	literal, unconsumedInput, err = ConsumeLiteral(input)

	if err != nil {
		return
	}

	enumInt, ok := enumMap[string(literal)]

	if !ok {
		err = errors.New("Unrecognized enum value" + string(literal))
	}

	return
}

func ConsumeString(input []rune) (field []rune, unconsumedInput []rune, err error) {
	var inQuotationMode bool = false
	var properEnd bool = false

	if input[0] != rune('"') {
		err = errors.New("Expected Quotation mark, did not get one.")
		return
	}

	input = input[1:]

	for {

		if len(input) <= 0 {
			break
		}

		c := input[0]

		if inQuotationMode {

			if c == rune('"') {
				field = append(field, rune(c))
			} else if IsWhiteSpace(c) {
				properEnd = true
			} else {
				err = errors.New("Expected \" or white space.")
				return
			}

		} else {

			if c == rune('"') {
				inQuotationMode = true
			} else {
				field = append(field, rune(c))
			}

		}

		if properEnd {
			break
		}

		input = input[1:]
	}

	if !properEnd && !inQuotationMode {
		err = errors.New("Expected closing \"")
		return
	}

	unconsumedInput = input

	return

}

func ConsumeLiteral(input []rune) (literal []rune, unconsumedInput []rune, err error) {

	for {
		if len(input) <= 0 {
			break
		}

		c := input[0]

		if IsWhiteSpace(c) {
			break
		}

		input = input[1:]
		literal = append(literal, rune(c))
	}

	unconsumedInput = input

	if len(literal) <= 0 {
		err = errors.New("Expected literal")
	}

	return
}

func ConsumeInt(input []rune) (parsedInt int, unconsumedInput []rune, err error) {
	var literal []rune

	literal, unconsumedInput, err = ConsumeLiteral(input)

	if err != nil {
		return
	}

	parsedInt, err = strconv.Atoi(string(literal))

	return
}

func ConsumeIP(input []rune) (ip net.IP, unconsumedInput []rune, err error) {
	var literal []rune

	literal, unconsumedInput, err = ConsumeLiteral(input)

	if err != nil {
		return
	}

	ip = net.ParseIP(string(literal))
	if ip == nil {
		err = errors.New("IP address is invalid")
	}

	return
}

func IsWhiteSpace(c rune) bool {
	return c == rune('\t') || c == rune(' ')
}

func ConsumeWhiteSpace(input []rune, requireWhitespace bool) (unconsumedInput []rune, err error) {

	var whitespaceEncountered bool = false

	for {
		if len(input) <= 0 {
			break
		}

		c := input[0]

		if !IsWhiteSpace(c) {
			break
		}

		whitespaceEncountered = true

		input = input[1:]
	}

	unconsumedInput = input

	if !whitespaceEncountered && requireWhitespace {
		err = errors.New("Expected white space")
	}

	return
}
