# rndc
[![Go Reference](https://pkg.go.dev/badge/github.com/stianwa/rndc.svg)](https://pkg.go.dev/github.com/stianwa/rndc) [![Go Report Card](https://goreportcard.com/badge/github.com/stianwa/rndc)](https://goreportcard.com/report/github.com/stianwa/rndc)

Package rndc implements methods and functions for communicating with the
BIND name server via RNDC (Remote Name Daemon Control).

Installation
------------

The recommended way to install rndc

```
go get github.com/stianwa/rndc
```

Examples
--------

```go

package main
 
import (
       "github.com/stianwa/rndc"
       "fmt"
)

func main() {
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
```

State
-------
The rndc module is currently under development. Do not use for production.


License
-------

GPLv3, see [LICENSE.md](LICENSE.md)
