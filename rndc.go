// Package rndc implements functions and methods for communicating with the BIND name server.
package rndc

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// Client represents a client session
type Client struct {
	Host         string // host to connect, default localhost
	Port         uint16 // port to connect, default 953
	Key          *Key   // Authentication key
	serial       uint32
	remoteSerial uint32
	nonce        string
	conn         net.Conn
}

// Key represents the RNDC authentication key
type Key struct {
	Algorithm string // Supported algorithms are: hmac-md5, hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512
	Secret    []byte // Secret key
}

// New creates a new client and initializes the communication.
func New(key *Key) (*Client, error) {
	c := &Client{Key: key}

	if err := c.Connect(); err != nil {
		return nil, err
	}

	return c, nil
}

// Connect connects to the server and receives a nounce
func (c *Client) Connect() error {
	if c.conn != nil {
		return fmt.Errorf("already connected")
	}

	c.defaults()
	if err := c.sanityCheck(); err != nil {
		return err
	}

	serial, err := random()
	if err != nil {
		return err
	}
	c.serial = serial

	conn, err := net.Dial("tcp", c.Host+fmt.Sprintf(":%d", c.Port))

	if err != nil {
		return err
	}
	c.conn = conn

	closeConn := true
	defer func() {
		if closeConn {
			c.Close()
		}
	}()

	resp, err := c.Request("null")
	if err != nil {
		return err
	}

	if resp.Result != 0 {
		return fmt.Errorf("initial response: error code %d: %s", resp.Result, resp.ErrorMessage)
	}

	closeConn = false
	return nil
}

// Request makes a request to the server and returns a response or an error.
func (c *Client) Request(command string) (*Response, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	c.serial++

	rp, err := requestPacket(command, c.serial, c.nonce, c.Key)
	if err != nil {
		return nil, err
	}

	if err := c.send(packWire(rp)); err != nil {
		return nil, err
	}

	resp, err := c.read()
	if err != nil {
		return nil, err
	}

	p, err := parsePacket(resp, c.Key)
	if err != nil {
		return nil, err
	}

	ctrl, err := getCtrl(p)
	if err != nil {
		return nil, err
	}

	if ctrl.RemoteSerial == 0 {
		return nil, fmt.Errorf("no serial from response")
	}

	if c.remoteSerial != 0 && ctrl.RemoteSerial != c.remoteSerial+1 {
		return nil, fmt.Errorf("remote serial leap: %d -> %d", c.remoteSerial, ctrl.RemoteSerial)
	}
	c.remoteSerial = ctrl.RemoteSerial

	if ctrl.Nonce == "" {
		return nil, fmt.Errorf("no nonce from response")
	}
	if c.nonce == "" {
		c.nonce = ctrl.Nonce
	}
	if c.nonce != ctrl.Nonce {
		return nil, fmt.Errorf("response nonce mismatch: %s -> %s", c.nonce, ctrl.Nonce)
	}

	now := time.Now()
	if now.Before(ctrl.Time) || now.After(ctrl.Expire) {
		return nil, fmt.Errorf("response not within time window")
	}

	return getData(p)
}

// Close closes the connection
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

func (c *Client) defaults() {
	if c.Host == "" {
		c.Host = "localhost"
	}

	if c.Port == 0 {
		c.Port = 953
	}
}

func (c *Client) sanityCheck() error {
	if c.Key == nil {
		return fmt.Errorf("authentication key not specified")
	}

	if c.Key.Algorithm == "" {
		return fmt.Errorf("missing key algorithm")
	}

	if c.Key.Secret == nil || len(c.Key.Secret) == 0 {
		return fmt.Errorf("missing key secret")
	}

	return nil
}

func (c *Client) send(b []byte) error {
	n, err := c.conn.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return fmt.Errorf("wrote %d out of %d bytes", n, len(b))
	}

	return nil
}

func (c *Client) read() ([]byte, error) {
	resp := make([]byte, 16384)
	n, err := c.conn.Read(resp)
	if err != nil {
		if err != io.EOF {
			return nil, err
		}
	}

	return resp[0:n], nil
}

func random() (uint32, error) {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint32(b), nil
}
