package dswg

import (
	"net"
	"errors"
	"database/sql"
	"encoding/json"
	"database/sql/driver"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)


type IP struct {
	net.IP
}

func ParseIP(ip string) (*IP, error) {
	addr := net.ParseIP(ip)
	if len(addr) == 0 {
		return nil, errors.New("Invalid IP format")
	}
	return &IP{addr}, nil
}

func (ip *IP) Scan(value interface{}) error {
	var nullStr sql.NullString
	err := nullStr.Scan(value)
	if err != nil {
		return err
	}

	parsed, err := ParseIP(nullStr.String)
	if err != nil {
		return err
	}
	*ip = *parsed
	return nil
}

func (ip IP) Value() (driver.Value, error) {
	return driver.Value(ip.String()), nil
}

func (ip *IP) UnmarshalJSON(b []byte) error {
	var ipStr string
	if err := json.Unmarshal(b, &ipStr); err != nil {
		return err
	}

	parsed, err := ParseIP(ipStr)
	if err != nil {
		return err
	}
	*ip = *parsed

	return nil
}

func (ip IP) MarshalJSON() ([]byte, error) {
	return json.Marshal(ip.String())
}

type IPNet struct {
	net.IPNet
}

func ParseIPNet(cidr string) (*IPNet, error) {
	ipNet, err := netlink.ParseIPNet(cidr)
	if err != nil {
		return nil, err
	}
	return &IPNet{*ipNet}, nil
}

func (ip *IPNet) Scan(value interface{}) error {
	var nullStr sql.NullString
	err := nullStr.Scan(value)
	if err != nil {
		return err
	}

	ipNet, err := netlink.ParseIPNet(nullStr.String)
	if err != nil {
		return err
	}
	ip.IPNet = *ipNet
	return nil
}

func (ip IPNet) Value() (driver.Value, error) {
	return driver.Value(ip.String()), nil
}

func (ip *IPNet) UnmarshalJSON(b []byte) error {
	var ipStr string
	if err := json.Unmarshal(b, &ipStr); err != nil {
		return err
	}

	ipNet, err := netlink.ParseIPNet(ipStr)
	if err != nil {
		return err
	}
	ip.IPNet = *ipNet

	return nil
}

func (ip IPNet) MarshalJSON() ([]byte, error) {
	return json.Marshal(ip.String())
}

type Key struct {
	wgtypes.Key
}

func ParseKey(keyStr string) (*Key, error) {
	key, err := wgtypes.ParseKey(keyStr)
	if err != nil {
		return nil, err
	}
	return &Key{key}, nil
}

func (k *Key) Scan(value interface{}) error {
	var nullStr sql.NullString
	err := nullStr.Scan(value)
	if err != nil {
		return err
	}
	if !nullStr.Valid {
		return errors.New("PrivateKey cannot be empty")
	}

	key, err := wgtypes.ParseKey(nullStr.String)
	if err != nil {
		return err
	}
	k.Key = key

	return nil
}

func (k Key) Value() (driver.Value, error) {
	return driver.Value(k.String()), nil
}

func (k *Key) UnmarshalJSON(b []byte) error {
	var keyStr string
	if err := json.Unmarshal(b, &keyStr); err != nil {
		return err
	}

	key, err := wgtypes.ParseKey(keyStr)
	if err != nil {
		return err
	}
	k.Key = key

	return nil
}

func (k Key) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

type UDPAddr struct {
	net.UDPAddr
}

func ParseUDP(addrStr string) (*UDPAddr, error) {
	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return nil, err
	}

	return &UDPAddr{*addr}, nil
}

func (udp *UDPAddr) Scan(value interface{}) error {
	var nullStr sql.NullString
	err := nullStr.Scan(value)
	if err != nil {
		return err
	}

	addr, err := net.ResolveUDPAddr("udp", nullStr.String)
	if err != nil {
		return err
	}

	udp.UDPAddr = *addr

	return nil
}

func (udp UDPAddr) Value() (driver.Value, error) {
	return driver.Value(udp.String()), nil
}

func (udp *UDPAddr) UnmarshalJSON(b []byte) error {
	var udpStr string
	if err := json.Unmarshal(b, &udpStr); err != nil {
		return err
	}

	parsed, err := ParseUDP(udpStr)
	if err != nil {
		return err
	}
	*udp = *parsed

	return nil
}

func (udp UDPAddr) MarshalJSON() ([]byte, error) {
	return json.Marshal(udp.String())
}

type Link struct {
	Name				string	`db:"name" json:"name"`
	MTU					int		`db:"mtu" json:"mtu"`
	Enable				bool	`db:"enable" json:"enable"`
	PrivateKey			Key		`db:"private_key" json:"private_key"`
	ListenPort			int		`db:"port" json:"port"`
	FirewallMark		int		`db:"fwmark" json:"fwmark"`
	AddressIPv4			*IPNet	`db:"ipv4_cidr" json:"ipv4_cidr"`
	AddressIPv6			*IPNet	`db:"ipv6_cidr" json:"ipv6_cidr"`
	DefaultAllowedIPs	[]IPNet `json:"allowed_ips"`
	DefaultDNS1			*IP		`db:"default_dns1" json:"default_dns1"`
	DefaultDNS2			*IP		`db:"default_dns2" json:"default_dns2"`
	PostUp				[]string`json:"post_up"`
	PostDown			[]string`json:"post_down"`
	Forward				bool	`db:"forward" json:"forward"`
}

func (link Link) Attrs() *netlink.LinkAttrs {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = link.Name
	return &attrs
}

func (link Link) Type() string {
	return "wireguard"
}


// FUTURE FEATURE: Add postup & postdown cmds for peers
type Peer struct {
	Name				string		`db:"name"`
	Enable				bool		`db:"enable"`
	PublicKey			Key			`db:"public_key"`
	PresharedKey		*Key		`db:"preshared_key"`
	Endpoint			*UDPAddr	`db:"endpoint"`
	AllowedIPs			[]IPNet
	PersistentKeepalive	int64		`db:"keepalive"`
	DNS1				*IP			`db:"dns1"`
	DNS2				*IP			`db:"dns2"`
}
