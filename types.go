package dswg

import (
	"net"
	"errors"
	"database/sql"
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

type Link struct {
	Name				string	`db:"name"`
	MTU					int		`db:"mtu"`
	Enable				bool	`db:"enable"`
	PrivateKey			Key		`db:"private_key"`
	ListenPort			int		`db:"port"`
	FirewallMark		int		`db:"fwmark"`
	AddressIPv4			*IPNet	`db:"ipv4_cidr"`
	AddressIPv6			*IPNet	`db:"ipv6_cidr"`
	DefaultAllowedIPs	[]IPNet
	DefaultDNS1			*IP		`db:"default_dns1"`
	DefaultDNS2			*IP		`db:"default_dns2"`
	PostUp				[]string
	PostDown			[]string
	Forward				bool	`db:"forward"`
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
	PersistentKeepalive	int			`db:"keepalive"`
	DNS1				*IP			`db:"dns1"`
	DNS2				*IP			`db:"dns2"`
}
