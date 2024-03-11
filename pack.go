package rndc

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"
	"time"
)

var hmacShaPrefix = map[string]byte{
	"hmac-sha1":   161,
	"hmac-sha224": 162,
	"hmac-sha256": 163,
	"hmac-sha384": 164,
	"hmac-sha512": 165,
}

type kv struct {
	Key   string
	Value []byte
}

func keyVal(key string, value []byte) kv {
	return kv{Key: key, Value: value}
}

func requestPacket(command string, serial uint32, nonce string, key *Key) ([]byte, error) {
	now := time.Now()

	var block []byte
	if nonce != "" {
		block = packTableEntries(
			keyVal("_ctrl", packTable(
				keyVal("_tim", packBinary(fmt.Sprintf("%d", now.Unix()))),
				keyVal("_exp", packBinary(fmt.Sprintf("%d", now.Add(time.Second*time.Duration(60)).Unix()))),
				keyVal("_ser", packBinary(fmt.Sprintf("%d", serial))),
				keyVal("_nonce", packBinary(nonce)))),
			keyVal("_data", packTable(
				keyVal("type", packBinary(command)))))
	} else {
		block = packTableEntries(
			keyVal("_ctrl", packTable(
				keyVal("_tim", packBinary(fmt.Sprintf("%d", now.Unix()))),
				keyVal("_exp", packBinary(fmt.Sprintf("%d", now.Add(time.Second*time.Duration(60)).Unix()))),
				keyVal("_ser", packBinary(fmt.Sprintf("%d", serial))))),
			keyVal("_data", packTable(
				keyVal("type", packBinary(command)))))
	}

	signature, err := sign(block, key)
	if err != nil {
		return nil, err
	}
	signBlock := packTableEntries(
		keyVal("_auth",
			packTable(keyVal("hsha", packBinary(signature)))))

	return append(signBlock[:], block...), nil

}

func sign(b []byte, key *Key) ([]byte, error) {
	switch key.Algorithm {
	case "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512":
		prefixByte, gotPrefix := hmacShaPrefix[key.Algorithm]
		ret := make([]byte, 89)
		if !gotPrefix {
			return nil, fmt.Errorf("failed to lookup hmac prefix for: %s", key.Algorithm)
		}
		ret[0] = prefixByte
		var h hash.Hash
		if strings.HasSuffix(key.Algorithm, "sha224") {
			h = hmac.New(sha256.New224, key.Secret)
		} else if strings.HasSuffix(key.Algorithm, "sha256") {
			h = hmac.New(sha256.New, key.Secret)
		} else if strings.HasSuffix(key.Algorithm, "sha384") {
			h = hmac.New(sha512.New384, key.Secret)
		} else if strings.HasSuffix(key.Algorithm, "sha512") {
			h = hmac.New(sha512.New, key.Secret)
		} else {
			return nil, fmt.Errorf("no hmac handler for %s", key.Algorithm)
		}

		h.Write(b)
		copy(ret[1:], []byte(base64.StdEncoding.EncodeToString([]byte(h.Sum(nil)))))
		return ret, nil
	case "hmac-md5":
		ret := make([]byte, 22)
		h := hmac.New(md5.New, key.Secret)
		h.Write(b)
		copy(ret[:], []byte(strings.TrimSuffix(base64.StdEncoding.EncodeToString([]byte(h.Sum(nil))), "=")))
		return ret, nil
	default:
		return nil, fmt.Errorf("unsupported hmac: %s", key.Algorithm)
	}
}

func packBinary(a any) []byte {
	var b []byte
	switch v := a.(type) {
	case string:
		b = []byte(v)
	case []byte:
		b = v
	}

	header := make([]byte, 5)
	header[0] = msgTypeBinary

	binary.BigEndian.PutUint32(header[1:], uint32(len(b)))
	return append(header, b...)
}

func packTableEntries(kvs ...kv) []byte {
	var ret []byte
	for _, kv := range kvs {
		key := []byte(kv.Key)
		ret = append(ret[:], byte(len(key)))
		ret = append(ret[:], key...)
		ret = append(ret[:], kv.Value...)
	}

	return ret
}

func packTable(kvs ...kv) []byte {
	header := make([]byte, 5)
	header[0] = msgTypeTable

	ret := packTableEntries(kvs...)

	binary.BigEndian.PutUint32(header[1:], uint32(len(ret)))

	return append(header, ret...)
}

func packList(values ...[]byte) []byte {
	header := make([]byte, 5)
	header[0] = msgTypeList
	var ret []byte
	for _, value := range values {
		ret = append(ret[:], value...)
	}

	binary.BigEndian.PutUint32(header[1:], uint32(len(ret)))

	return append(header, ret...)
}

func packWire(b []byte) []byte {
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header, uint32(len(b)+4))
	binary.BigEndian.PutUint32(header[4:], uint32(1))

	return append(header, b...)
}
