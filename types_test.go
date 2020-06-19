package dswg

import (
	"net"
	"testing"
	"github.com/vishvananda/netlink"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)


func TestParseIPValid(t *testing.T) {
	assert := assert.New(t)
	
	ip, err := ParseIP("10.66.94.20")
	
	assert.Nil(err)
	assert.Equal(byte(10), ip.IP[12])
	assert.Equal(byte(66), ip.IP[13])
	assert.Equal(byte(94), ip.IP[14])
	assert.Equal(byte(20), ip.IP[15])
}

func TestParseIPInvalid(t *testing.T) {
	assert := assert.New(t)

	_, err := ParseIP("x")
	
	assert.NotNil(err)
}

func TestIPScanValid(t *testing.T) {
	assert := assert.New(t)

	ip := IP{}
	err := ip.Scan("::1")
	
	assert.Nil(err)
	assert.Equal(ip.IP, net.ParseIP("::1"))
}

func TestIPScanInvalid(t *testing.T) {
	assert := assert.New(t)

	ip := IP{}
	err := ip.Scan("10..2")
	
	assert.NotNil(err)
}

func TestIPValue(t *testing.T) {
	assert := assert.New(t)

	ip, err := ParseIP("10.66.94.20")
	assert.Nil(err)
	
	value, err := ip.Value() 
	assert.Nil(err)
	assert.Equal(value.(string), "10.66.94.20")
}

func TestIPUnmarshalJSONValid(t *testing.T) {
	assert := assert.New(t)

	ip := IP{}
	err := ip.UnmarshalJSON([]byte("\"::1\""))
	
	assert.Nil(err)
	assert.Equal(ip.IP, net.ParseIP("::1"))
}

func TestIPUnmarshalJSONInvalid(t *testing.T) {
	assert := assert.New(t)

	ip := IP{}
	err := ip.UnmarshalJSON([]byte("10..2"))
	
	assert.NotNil(err)
}

func TestIPMarshalJSON(t *testing.T) {
	assert := assert.New(t)

	ip, err := ParseIP("10.66.94.20")
	assert.Nil(err)
	
	value, err := ip.MarshalJSON() 
	assert.Nil(err)
	assert.Equal(string(value), "\"10.66.94.20\"")
}

func TestParseIPNetValid(t *testing.T) {
	assert := assert.New(t)
	
	ip, err := ParseIPNet("10.66.94.20/24")
	
	assert.Nil(err)
	assert.Equal(byte(10), ip.IPNet.IP[12])
	assert.Equal(byte(66), ip.IPNet.IP[13])
	assert.Equal(byte(94), ip.IPNet.IP[14])
	assert.Equal(byte(20), ip.IPNet.IP[15])

	assert.Equal(byte(255), ip.IPNet.Mask[0])
	assert.Equal(byte(255), ip.IPNet.Mask[1])
	assert.Equal(byte(255), ip.IPNet.Mask[2])
	assert.Equal(byte(0), ip.IPNet.Mask[3])
}

func TestParseIPNetInvalid(t *testing.T) {
	assert := assert.New(t)

	_, err := ParseIPNet("x")
	
	assert.NotNil(err)
}

func TestIPNetScanValid(t *testing.T) {
	assert := assert.New(t)

	ip := IPNet{}
	err := ip.Scan("::1/128")
	
	expected, _ := netlink.ParseIPNet("::1/128")

	assert.Nil(err)
	assert.Equal(ip.IPNet, *expected)
}

func TestIPNetScanInvalid(t *testing.T) {
	assert := assert.New(t)

	ip := IPNet{}
	err := ip.Scan("::1") // not / at the end for mask
	
	assert.NotNil(err)
}

func TestIPNetValue(t *testing.T) {
	assert := assert.New(t)

	ip, err := ParseIPNet("::1/128")
	assert.Nil(err)
	
	value, err := ip.Value() 
	assert.Nil(err)
	assert.Equal(value.(string), "::1/128")
}

func TestIPNetUnmarshalJSONValid(t *testing.T) {
	assert := assert.New(t)

	ip := IPNet{}
	err := ip.UnmarshalJSON([]byte("\"::1/128\""))
	
	expected, _ := netlink.ParseIPNet("::1/128")

	assert.Nil(err)
	assert.Equal(ip.IPNet, *expected)
}

func TestIPNetUnmarshalJSONInvalid(t *testing.T) {
	assert := assert.New(t)

	ip := IPNet{}
	err := ip.UnmarshalJSON([]byte("::1")) // not / at the end for mask
	
	assert.NotNil(err)
}

func TestIPNetMarshalJSON(t *testing.T) {
	assert := assert.New(t)

	ip, err := ParseIPNet("::1/128")
	assert.Nil(err)
	
	value, err := ip.MarshalJSON() 
	assert.Nil(err)
	assert.Equal(string(value), "\"::1/128\"")
}

func TestParseKeyValid(t *testing.T) {
	assert := assert.New(t)
	
	key, err := ParseKey("GK3G63/XzfzGbpeMVAKgurB8hH+R3GXtwNv15owGoXc=")
	expectedPrivateKey := "69+X6VtL071Q1D0SJgiOjZdUraMeZIPpyQFBHuznKgY="

	assert.Nil(err)
	assert.Equal(key.PublicKey().String(), expectedPrivateKey)
}

func TestParseKeyInvalid(t *testing.T) {
	assert := assert.New(t)

	_, err := ParseKey("x")
	
	assert.NotNil(err)
}

func TestKeyScanValid(t *testing.T) {
	assert := assert.New(t)

	key := Key{}
	err := key.Scan("GK3G63/XzfzGbpeMVAKgurB8hH+R3GXtwNv15owGoXc=")
	assert.Nil(err)

	expectedKey, err := wgtypes.ParseKey("GK3G63/XzfzGbpeMVAKgurB8hH+R3GXtwNv15owGoXc=")

	assert.Nil(err)
	assert.Equal(key.Key, expectedKey)
}

func TestKeyScanInvalid(t *testing.T) {
	assert := assert.New(t)

	key := Key{}
	err := key.Scan("x")
	
	assert.NotNil(err)
}

func TestKeyValue(t *testing.T) {
	assert := assert.New(t)

	key, err := ParseKey("GK3G63/XzfzGbpeMVAKgurB8hH+R3GXtwNv15owGoXc=")
	assert.Nil(err)
	
	value, err := key.Value() 
	assert.Nil(err)
	assert.Equal(value.(string), "GK3G63/XzfzGbpeMVAKgurB8hH+R3GXtwNv15owGoXc=")
}

func TestKeyUnmarshalJSONValid(t *testing.T) {
	assert := assert.New(t)

	key := Key{}
	err := key.UnmarshalJSON([]byte("\"GK3G63/XzfzGbpeMVAKgurB8hH+R3GXtwNv15owGoXc=\""))
	assert.Nil(err)

	expectedKey, err := wgtypes.ParseKey("GK3G63/XzfzGbpeMVAKgurB8hH+R3GXtwNv15owGoXc=")

	assert.Nil(err)
	assert.Equal(key.Key, expectedKey)
}

func TestKeyUnmarshalJSONInvalid(t *testing.T) {
	assert := assert.New(t)

	key := Key{}
	err := key.UnmarshalJSON([]byte("\"x\""))
	
	assert.NotNil(err)
}

func TestKeyMarshalJSON(t *testing.T) {
	assert := assert.New(t)

	key, err := ParseKey("GK3G63/XzfzGbpeMVAKgurB8hH+R3GXtwNv15owGoXc=")
	assert.Nil(err)
	
	value, err := key.MarshalJSON() 
	assert.Nil(err)
	assert.Equal(string(value), "\"GK3G63/XzfzGbpeMVAKgurB8hH+R3GXtwNv15owGoXc=\"")
}

func TestParseUDPAddrValid(t *testing.T) {
	assert := assert.New(t)
	
	udp, err := ParseUDP("192.168.0.200:42069")

	assert.Nil(err)
	assert.Equal(udp.UDPAddr.Port, 42069)
	assert.Equal(byte(192), udp.UDPAddr.IP[12])
	assert.Equal(byte(168), udp.UDPAddr.IP[13])
	assert.Equal(byte(0), udp.UDPAddr.IP[14])
	assert.Equal(byte(200), udp.UDPAddr.IP[15])
}

func TestParseUDPAddrInvalid(t *testing.T) {
	assert := assert.New(t)

	_, err := ParseUDP("192.168.0.200:c")

	assert.NotNil(err)
}

func TestUDPAddrScanValid(t *testing.T) {
	assert := assert.New(t)

	udp := UDPAddr{}
	err := udp.Scan("192.168.0.69:89")
	assert.Nil(err)
	
	udpExpected, err := net.ResolveUDPAddr("udp", "192.168.0.69:89")

	assert.Equal(udp.UDPAddr, *udpExpected)
}

func TestUDPAddrScanInvalid(t *testing.T) {
	assert := assert.New(t)

	udp := UDPAddr{}
	err := udp.Scan("192.168.0.69")
	assert.NotNil(err)
}

func TestUDPAddrValue(t *testing.T) {
	assert := assert.New(t)

	udp, err := ParseUDP("10.66.0.1:420")
	assert.Nil(err)
	
	value, err := udp.Value() 
	assert.Nil(err)
	assert.Equal(value.(string), "10.66.0.1:420")
}

func TestUDPAddrUnmarshalJSONValid(t *testing.T) {
	assert := assert.New(t)

	udp := UDPAddr{}
	err := udp.UnmarshalJSON([]byte("\"192.168.0.69:89\""))
	assert.Nil(err)

	udpExpected, err := net.ResolveUDPAddr("udp", "192.168.0.69:89")

	assert.Equal(udp.UDPAddr, *udpExpected)
}

func TestUDPAddrUnmarshalJSONInvalid(t *testing.T) {
	assert := assert.New(t)

	udp := UDPAddr{}
	err := udp.UnmarshalJSON([]byte("\"192.168.0.69"))
	assert.NotNil(err)
}

func TestUDPAddrMarshalJSON(t *testing.T) {
	assert := assert.New(t)

	udp, err := ParseUDP("10.66.0.1:420")
	assert.Nil(err)
	
	value, err := udp.MarshalJSON() 
	assert.Nil(err)
	assert.Equal(string(value), "\"10.66.0.1:420\"")
}
