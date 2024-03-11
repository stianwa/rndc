package rndc

import (
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const rndcKeyBlockRe = `^key\s+(?P<keyname>[^\{\s]*)\s+\{(?P<block>[^}]+)\}`

// LoadKeyMap loads all keys found in file returning a map with
// keyname as key and *Key as value.
func LoadKeyMap(name string) (map[string]*Key, error) {
	return loadKeyMap(name, false)
}

// LoadKey loads the first key found in file.
func LoadKey(name string) (*Key, error) {
	m, err := loadKeyMap(name, true)
	if err != nil {
		return nil, err
	}

	for _, v := range m {
		return v, nil
	}

	return nil, fmt.Errorf("no keys in file")
}

func loadKeyMap(name string, firstOnly bool) (map[string]*Key, error) {
	content, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}

	re, err := regexp.Compile(rndcKeyBlockRe)
	if err != nil {
		return nil, err
	}

	matches := re.FindAllStringSubmatch(string(content), -1)
	if err != nil {
		return nil, err
	}

	if matches == nil {
		return nil, fmt.Errorf("no key block found in file")
	}

	keynameIdx := re.SubexpIndex("keyname")
	if keynameIdx == -1 {
		return nil, fmt.Errorf("no capture index for keyname")
	}

	blockIdx := re.SubexpIndex("block")
	if blockIdx == -1 {
		return nil, fmt.Errorf("no capture index for block")
	}

	m := make(map[string]*Key)
	for _, match := range matches {
		key, err := parseInnerKeyBlock(match[blockIdx])
		if err != nil {
			return nil, err
		}

		m[strings.Trim(match[keynameIdx], "\"'")] = key
		if firstOnly {
			return m, nil
		}
	}

	return m, nil
}

func parseInnerKeyBlock(block string) (*Key, error) {
	key := &Key{}
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ";"))

		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}

		value := strings.Trim(fields[1], "\"'")

		switch fields[0] {
		case "algorithm":
			if key.Algorithm != "" {
				return nil, fmt.Errorf("algorithm specified multiple times")
			}
			key.Algorithm = value
		case "secret":
			if key.Secret != nil {
				return nil, fmt.Errorf("secret specified multiple times")
			}
			b, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("secret base64 decode: %v", err)
			}
			key.Secret = b
		}
	}

	if key.Algorithm == "" {
		return nil, fmt.Errorf("missing algorithm")
	}
	if key.Secret == nil {
		return nil, fmt.Errorf("missing secret")
	}
	return key, nil
}
