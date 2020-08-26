package tools

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"strconv"
)

// MessageHex returns Hexadecimal string of a byte slice passed as a parameter
func MessageHex(b []byte) string {
	if len(b) == 0 {
		return "[]"
	}
	buffer := make([]byte, len(b)*6+2)
	p := 0
	copy(buffer[p:], []byte("[ "))
	p += 2
	for i := 0; i < len(b); i++ {
		copy(buffer[p:], []byte(fmt.Sprintf("0x%02x", b[i])))
		p += 4
		if i < len(b)-1 {
			copy(buffer[p:], []byte(", "))
			p += 2
		}
	}
	copy(buffer[p:], []byte(" ]"))

	return string(buffer)
}

// HostAddrValidator parser host address passed as a string, and make sure it follows X.X.X.X:YYZZ format
func HostAddrValidator(addr string) error {
	host, port, _ := net.SplitHostPort(addr)
	if host == "" || port == "" {
		return fmt.Errorf("host or port cannot be ''")
	}
	// Try to resolve if the hostname was used in the address
	if ip, err := net.LookupIP(host); err != nil || ip == nil {
		// Check if IP address was used in address instead of a host name
		if net.ParseIP(host) == nil {
			return fmt.Errorf("fail to parse host part of address")
		}
	}
	np, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("fail to parse port with error: %w", err)
	}
	if np == 0 || np > math.MaxUint16 {
		return fmt.Errorf("the value of port is invalid")
	}
	return nil
}

// URLAddrValidation validates that passed addrress has valid URL formating.
func URLAddrValidation(addr string) error {
	endpoint, err := url.Parse(addr)
	if err != nil {
		return err
	}
	host, port, _ := net.SplitHostPort(endpoint.Host)
	if host == "" || port == "" {
		return fmt.Errorf("host or port cannot be ''")
	}
	// Try to resolve if the hostname was used in the address
	if ip, err := net.LookupIP(host); err != nil || ip == nil {
		// Check if IP address was used in address instead of a host name
		if net.ParseIP(host) == nil {
			return fmt.Errorf("fail to parse host part of address")
		}
	}
	np, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("fail to parse port with error: %w", err)
	}
	if np == 0 || np > math.MaxUint16 {
		return fmt.Errorf("the value of port is invalid")
	}
	return nil
}
