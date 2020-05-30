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

func ParseIP(ip string) IP {
	return IP{net.ParseIP(ip)}
}

func (ip *IP) Scan(value interface{}) error {
	var nullStr sql.NullString
	err := nullStr.Scan(value)
	if err != nil {
		return err
	}

	ip.IP = net.ParseIP(nullStr.String)
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
