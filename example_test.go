package rndc

import (
	"fmt"
	"log"
)

func ExampleNew() {
	key, err := LoadKey("/etc/rndc.key")
	if err != nil {
		log.Fatalf("failed to load key: %v", err)
	}

	client, err := New(key)
	if err != nil {
		log.Fatalf("failed to initialize client: %v", err)
	}

	defer client.Close()

	resp, err := client.Request("status")
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}

	if resp.Result != 0 {
		log.Fatalf("request failed: %s", resp)
	}

	fmt.Println(resp.Text)

	resp2, err := client.Request("reload")
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}

	fmt.Println(resp2)
}
