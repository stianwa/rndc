package rndc

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	msgTypeString = iota
	msgTypeBinary
	msgTypeTable
	msgTypeList
)

// Debug turns on debugging of packet parsing
var Debug = false

type typeString string
type typeBinary string
type typeTable map[string]any
type typeList []any

func parsePacket(b []byte, key *Key) (any, error) {
	debug("parsePacket", b)

	if len(b) < 8 {
		return nil, fmt.Errorf("too few bytes")
	}

	pktLen := binary.BigEndian.Uint32(b)
	b = b[4:]

	if len(b) != int(pktLen) {
		return nil, fmt.Errorf("bad packet length: header=%d body=%d", pktLen, len(b))
	}

	version := binary.BigEndian.Uint32(b)
	if version != 1 {
		return nil, fmt.Errorf("unknown message version: %d", version)
	}
	b = b[4:]

	a, err := parseMainTable(b, key)
	if err != nil {
		return nil, err
	}

	return a, nil
}

func parseMainTable(b []byte, key *Key) (any, error) {
	debug("parseMainTable", b)

	table := make(typeTable)
	for len(b) != 0 {
		keyname, newb, err := parseKey(b)
		if err != nil {
			return nil, err
		}
		b = newb

		if keyname == "" && len(b) == 0 {
			break
		}

		val, newb, err := parseValue(b)
		if err != nil {
			return nil, err
		}
		b = newb
		table[keyname] = val

		if keyname == "_auth" {
			if err := signCheck(b, key, val); err != nil {
				return nil, err
			}
		}

	}

	return table, nil
}

func parseTable(b []byte) (any, error) {
	debug("parseTable", b)

	table := make(typeTable)
	for len(b) != 0 {
		key, newb, err := parseKey(b)
		if err != nil {
			return nil, err
		}
		b = newb

		if key == "" && len(b) == 0 {
			break
		}

		val, newb, err := parseValue(b)
		if err != nil {
			return nil, err
		}
		b = newb
		table[key] = val
	}

	return table, nil
}

func parseList(b []byte) (any, error) {
	debug("parseList", b)

	var list typeList
	for len(b) != 0 {
		val, newb, err := parseValue(b)
		if err != nil {
			return nil, err
		}
		b = newb
		list = append(list, val)
	}

	return list, nil
}

func parseKey(b []byte) (string, []byte, error) {
	debug("parseKey", b)

	if len(b) == 0 {
		return "", nil, fmt.Errorf("parse key: not enough data: %d", len(b))
	}

	if len(b) == 1 && b[0] == 0 {
		return "", b[1:], nil
	}

	blen := int(b[0])
	b = b[1:]

	if len(b) < blen {
		return "", nil, fmt.Errorf("parse key: not enough data: want %d, got %d", blen, len(b))
	}

	return string(b[0:blen]), b[blen:], nil
}

func parseValue(b []byte) (any, []byte, error) {
	debug("parseValue", b)

	msgType, block, newb, err := parseType(b)
	if err != nil {
		return nil, nil, err
	}

	switch msgType {
	case msgTypeBinary:
		return typeBinary(block), newb, nil
	case msgTypeTable:
		a, err := parseTable(block)
		if err != nil {
			return nil, nil, err
		}
		return a, newb, nil
	case msgTypeList:
		a, err := parseList(block)
		if err != nil {
			return nil, nil, err
		}
		return a, newb, nil
	case -1:
		return nil, nil, nil
	}

	return nil, nil, fmt.Errorf("parseValue: type %d is unknown", msgType)
}

func parseType(b []byte) (int, []byte, []byte, error) {
	debug("parseType", b)

	if len(b) < 5 {
		if len(b) > 0 && b[0] == 0 {
			return -1, nil, nil, nil
		}
		return 0, nil, nil, fmt.Errorf("type: not enough header bytes: %d ouf of 5", len(b))
	}

	msgType := int(b[0])
	blen := int(binary.BigEndian.Uint32(b[1:]))
	b = b[5:]
	for len(b) < blen {
		b = append(b, 0)
	}

	return msgType, b[0:blen], b[blen:], nil
}

func signCheck(b []byte, key *Key, auth any) error {
	signed, err := sign(b, key)
	if err != nil {
		return err
	}

	authTable, ok := auth.(typeTable)
	if !ok {
		return fmt.Errorf("auth section is not a table")
	}

	keyName := "hsha"
	if strings.Contains(key.Algorithm, "md5") {
		keyName = "hmd5"
	}

	sum, ok := authTable[keyName]
	if !ok {
		return fmt.Errorf("_auth is missing key %s", keyName)
	}

	msgSigned, ok := sum.(typeBinary)
	if !ok {
		return fmt.Errorf("failed byte assertion of sum")
	}

	if !bytes.Equal(signed, []byte(msgSigned)) {
		return fmt.Errorf("hmac verification of packet failed")
	}

	return nil
}

func debug(name string, b []byte) {
	if Debug {
		fmt.Printf("%s:\n%s\n", name, hex.Dump(b))
	}
}
