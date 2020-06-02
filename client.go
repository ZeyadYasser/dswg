package dswg


import (
	"fmt"
	"net"
	"errors"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Client struct {
	db	DB
	wg	wgctrl.Client
}


// Adds link to database.
// If link.Enable is set we try to activate the link
func (c *Client) AddLink(link Link) error {
	if ln, _ := c.db.GetLink(link.Name); ln != nil {
		return fmt.Errorf("Link name \"%v\" already exists in database", link.Name)
	}

	if ln, _ := netlink.LinkByName(link.Name); ln != nil {
		return fmt.Errorf(
			"Link name already exists in the kernel, " +
			"please delete it first using `ip link delete %v`", link.Name)
	}

	if err := validLink(link); err != nil {
		return err
	}

	err := c.db.AddLink(link)
	if err != nil {
		return err
	}

	if link.Enable {
		err := c.ActivateLink(link.Name)
		if err != nil {
			return err
		}
	}

	return nil
}

// Removes the link from the kernel and the database with all its peers.
// The link must exist in the database.
func (c *Client) RemoveLink(name string) error {
	link, err := c.db.GetLink(name)
	if err != nil {
		return err
	}

	if isLoaded(name) {
		err = netlink.LinkDel(*link)
		if err != nil {
			return err
		}
	}

	// link cascades its deletion to its peers
	err = c.db.RemoveLink(name)
	if err != nil {
		return err
	}

	return nil
}

// Activates link and applies wireguard configurations (including adding peers).
// If link is not loaded in the kernel, it gets loaded first.
// The link must exist in the database.
func (c *Client) ActivateLink(name string) error {
	link, err := c.db.GetLink(name)
	if err != nil {
		return err
	}

	if !isLoaded(name) {
		err := netlink.LinkAdd(link)
		if err != nil {
			return err
		}
	}

	err = c.setLinkSystemConfig(link.Name, *link)
	if err != nil {
		return err
	}

	// TODO: add peers here

	err = netlink.LinkSetUp(*link)
	if err != nil {
		return err
	}
	
	// TODO: Execute PostUp commands here
	return nil
}

// Deactivates link.
// Equivalent to `ip link set {name} down`.
// The link must exist in the database.
func (c *Client) DeactivateLink(name string) error {
	link, err := c.db.GetLink(name)
	if err != nil {
		return err
	}

	err = netlink.LinkSetDown(*link)
	if err != nil {
		return err
	}

	return nil
}

// Updates link in database and updates link system
// configurations, if it is loaded in the kernel.
func (c *Client) UpdateLink(name string, link Link) error {
	if err := validLink(link); err != nil {
		return err
	}

	err := c.db.UpdateLink(name, link)
	if err != nil {
		return err
	}

	if isLoaded(name) {
		err := c.setLinkSystemConfig(name, link)
		if err != nil {
			return err
		}
	}

	return nil
}

// Update link configuration in the kernel, including wireguard configuration.
// Link must exist in the kernel.
// NOTE: This function does not add peers or affect the database
func (c *Client) setLinkSystemConfig(name string, link Link) error {
	if err := validLink(link); err != nil {
		return err
	}

	netInterface, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("Couldn't find link %v in the kernel", link.Name)
	}

	if netInterface.Type() != "wireguard" {
		return errors.New("Link must be of type wireguard")
	}

	interfaceUp := (netInterface.Attrs().Flags & net.FlagUp) != 0
	if interfaceUp {
		// Interface must be down when changes are applied
		err := netlink.LinkSetDown(netInterface)
		if err != nil {
			return err
		}
	}

	// Override wireguard configuration
	devConfig := wgtypes.Config{
		PrivateKey: &link.PrivateKey.Key,
		ListenPort: &link.ListenPort,
		FirewallMark: &link.FirewallMark,
	}
	err = c.wg.ConfigureDevice(name, devConfig)
	if err != nil {
		return err
	}

	// TODO: Isolate in a separate function ex. updateLinkAddr(link)
	// Delete older addreses associated with the link
	addrList, err := netlink.AddrList(netInterface, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for _, addr := range addrList {
		err := netlink.AddrDel(netInterface, &addr)
		if err != nil {
			return err
		}
	}

	// Add link addresses
	if link.AddressIPv4 != nil {
		addr := &netlink.Addr{
			IPNet: &link.AddressIPv4.IPNet,
		}
		err := netlink.AddrAdd(netInterface, addr)
		if err != nil {
			return err
		}
	}

	if link.AddressIPv6 != nil {
		addr := &netlink.Addr{
			IPNet: &link.AddressIPv6.IPNet,
		}
		err := netlink.AddrAdd(netInterface, addr)
		if err != nil {
			return err
		}
	}
	
	err = netlink.LinkSetMTU(netInterface, link.MTU)
	if err != nil {
		return err
	}

	err = netlink.LinkSetName(netInterface, link.Name)
	if err != nil {
		return err
	}

	// Restore link state if it was up
	if interfaceUp {
		err := netlink.LinkSetUp(netInterface)
		if err != nil {
			return err
		}
	}

	return nil
}

func validLink(link Link) error {
	if len(link.Name) == 0 {
		return errors.New("Link name cannot be empty")
	}

	if link.AddressIPv4 == nil && link.AddressIPv6 == nil {
		return errors.New("Link must be assigned at least one address address")
	}

	return nil
}

// Indicates whether the link is added to the kernel or not.
func isLoaded(name string) bool {
	netInterface, _ := netlink.LinkByName(name)
	return netInterface != nil
}

func NewClient(db DB) (*Client, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	client := &Client{
		db: db,
		wg: *wg,
	}

	return client, nil
}