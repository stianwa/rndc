package rndc

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

const tstEnv = "TEST_LIVE_RNDC_KEY_FILE"

func TestLoadKey(t *testing.T) {
	_, err := LoadKey("./tests/rndc.key")
	if err != nil {
		t.Fatalf("failed to load key: %v", err)
	}
}

func TestParseInitRequest(t *testing.T) {
	testPacket(t, "initRequest")
}

func TestParseInitResponse(t *testing.T) {
	testPacket(t, "initResponse")
}

func TestParseCommandStatusRequest(t *testing.T) {
	testPacket(t, "commandStatusRequest")
}

func TestParseCommandStatusResponse(t *testing.T) {
	testPacket(t, "commandStatusResponse")
}

func testPacket(t *testing.T, name string) {
	tst, exp, ok := lookupTestData(name)
	if !ok {
		t.Fatalf("failed lookup test data for %s", name)
	}

	key, err := LoadKey("tests/rndc.key")
	if err != nil {
		t.Fatalf("failed to get Key: %v", err)
	}

	res, err := parsePacket(tst, key)
	if err != nil {
		t.Fatalf("failed to parse %s: %v", name, err)
	}

	j, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("failed to make JSON %s: %v", name, err)
	}
	if string(j) != string(exp) {
		t.Fatalf("failed to parse %s: got %s expected %s", name, string(j), string(exp))
	}
}

func TestPackAndParse(t *testing.T) {
	serial, err := random()
	if err != nil {
		t.Fatalf("failed to get random: %v", err)
	}

	key, err := LoadKey("tests/rndc.key")
	if err != nil {
		t.Fatalf("failed to get Key: %v", err)
	}

	ip, err := requestPacket("null", serial, "", key)
	if err != nil {
		t.Fatalf("failed to initPacket:: %v", err)
	}

	if _, err := parsePacket(packWire(ip), key); err != nil {
		t.Fatalf("failed to parse wire packet: %v", err)
	}

}

func TestNewLive(t *testing.T) {
	keyFile := os.Getenv(tstEnv)
	if keyFile == "" {
		t.Skip("skipping live test. To enable, set environment variable TEST_LIVE_RNDC_KEY_FILE to a path of an actual key file")
	}

	key, err := LoadKey(keyFile)
	if err != nil {
		t.Fatalf("failed to get Key: %v", err)
	}

	c, err := New(key)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	defer c.Close()

	resp, err := c.Request("notify example.com")
	if err != nil {
		t.Fatalf("failed to request status: %v", err)
	}
	fmt.Println(resp)

	resp2, err := c.Request("status")
	if err != nil {
		t.Fatalf("failed to request status: %v", err)
	}

	fmt.Println(resp2)
}

func lookupTestData(name string) ([]byte, []byte, bool) {
	tst, ok := testData[name]
	if !ok {
		return nil, nil, false
	}
	exp, ok := testData[name+"Expect"]
	if !ok {
		return nil, nil, false
	}

	return tst, exp, true
}
