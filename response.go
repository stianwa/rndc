package rndc

import (
	"fmt"
	"strconv"
	"time"
)

// Response represents the response from an RNDC request.
type Response struct {
	ErrorMessage string // Error message from server. Details are usually stored in the Text field
	Result       int    // Result code, 0 means OK
	Text         string // The response text
	Type         string // The request type
}

func (r *Response) String() string {
	msg := "OK"
	if r.Result != 0 {
		msg = r.ErrorMessage
	}
	return fmt.Sprintf("%s: [%d]%s: %s", r.Type, r.Result, msg, r.Text)
}

type ctrl struct {
	Time         time.Time
	Expire       time.Time
	RPL          int
	RemoteSerial uint32
	Nonce        string
}

func getData(p any) (*Response, error) {
	table, ok := p.(typeTable)
	if !ok {
		return nil, fmt.Errorf("response body is not a table")
	}

	dataType, ok := table["_data"]
	if !ok {
		return nil, fmt.Errorf("response body has no _data section")
	}
	dataTable, ok := dataType.(typeTable)
	if !ok {
		return nil, fmt.Errorf("_data is not a table")
	}

	m := tableToStringMap(dataTable)

	response := &Response{
		ErrorMessage: m["err"],
		Text:         m["text"],
		Type:         m["type"],
	}

	result, ok := m["result"]
	if ok {
		i, err := strconv.Atoi(result)
		if err != nil {
			return nil, fmt.Errorf("converting response_data result to int: %v", err)
		}
		response.Result = i
	} else {
		return nil, fmt.Errorf("no result in response _data")
	}

	if response.Type == "" {
		return nil, fmt.Errorf("no type  in response _data")
	}

	return response, nil
}

func tableToStringMap(table typeTable) map[string]string {
	m := make(map[string]string)
	for k, rawV := range table {
		v, ok := rawV.(typeBinary)
		if !ok {
			continue
		}
		m[k] = string(v)
	}

	return m
}

func getCtrl(p any) (*ctrl, error) {
	table, ok := p.(typeTable)
	if !ok {
		return nil, fmt.Errorf("response body is not a table")
	}

	ctrlType, ok := table["_ctrl"]
	if !ok {
		return nil, fmt.Errorf("response body has no _ctrl")
	}
	ctrlTable, ok := ctrlType.(typeTable)
	if !ok {
		return nil, fmt.Errorf("_ctrl is not a table")
	}

	m, err := getMap(ctrlTable, "_nonce", "_exp", "_tim", "_rpl", "_ser")
	if err != nil {
		return nil, err
	}

	timint, err := strconv.ParseInt(m["_tim"], 10, 64)
	if err != nil {
		return nil, err
	}
	expint, err := strconv.ParseInt(m["_exp"], 10, 64)
	if err != nil {
		return nil, err
	}

	remser, err := strconv.ParseInt(m["_ser"], 10, 64)
	if err != nil {
		return nil, err
	}

	rpl, err := strconv.ParseInt(m["_rpl"], 10, 64)
	if err != nil {
		return nil, err
	}

	return &ctrl{
		RemoteSerial: uint32(remser),
		Nonce:        m["_nonce"],
		RPL:          int(rpl),
		Time:         time.Unix(timint, 0),
		Expire:       time.Unix(expint, 0),
	}, nil
}

func getMap(table typeTable, names ...string) (map[string]string, error) {
	m := make(map[string]string)
	for _, name := range names {
		value, ok := table[name]
		if !ok {
			if name == "_nonce" {
				continue
			}
			return nil, fmt.Errorf("couldn't lookup %s", name)
		}

		b, ok := value.(typeBinary)
		if !ok {
			return nil, fmt.Errorf("value of %s is not a binary", name)
		}

		m[name] = string(b)
	}
	return m, nil
}
