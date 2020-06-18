package dswg


import (
	"fmt"
	"net"
	"time"
	"errors"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Client struct {
	db	DB
	wg	*wgctrl.Client
	ns	*netlink.Handle
}


// Adds link to database.
// If link.Enable is set we try to activate the link
func (c *Client) AddLink(link Link) error {
	if ln, _ := c.db.GetLink(link.Name); ln != nil {
		return fmt.Errorf("Link name \"%v\" already exists in database", link.Name)
	}

	if ln, _ := c.ns.LinkByName(link.Name); ln != nil {
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

	if c.isLoaded(name) {
		err = c.ns.LinkDel(*link)
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

	if !c.isLoaded(name) {
		err := c.ns.LinkAdd(link)
		if err != nil {
			return err
		}
	}

	link.Enable = true
	err = c.setLinkSystemConfig(link.Name, *link)
	if err != nil {
		return err
	}

	// TODO: Execute PostUp commands here

	err = c.db.UpdateLink(link.Name, *link)
	if err != nil {
		return err
	}

	peers, err := c.db.GetLinkPeers(link.Name)
	if err != nil {
		return err
	}

	for _, peer := range peers {
		if peer.Enable {
			err := c.ActivatePeer(link.Name, peer.Name)
			if err != nil {
				return err
			}
		}
	}

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

	if c.isLoaded(name) {
		err = c.ns.LinkSetDown(*link)
		if err != nil {
			return err
		}
	}

	link.Enable = false
	err = c.db.UpdateLink(link.Name, *link)
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

	if c.isLoaded(name) {
		err := c.setLinkSystemConfig(name, link)
		if err != nil {
			return err
		}
	}
	
	if !c.isLoaded(name) && link.Enable {
		err := c.ActivateLink(link.Name)
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

	netInterface, err := c.ns.LinkByName(name)
	if err != nil {
		return fmt.Errorf("Couldn't find link %v in the kernel", link.Name)
	}

	if netInterface.Type() != "wireguard" {
		return errors.New("Link must be of type wireguard")
	}

	// Interface must be down when changes are applied
	err = c.ns.LinkSetDown(netInterface)
	if err != nil {
		return err
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
	addrList, err := c.ns.AddrList(netInterface, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for _, addr := range addrList {
		err := c.ns.AddrDel(netInterface, &addr)
		if err != nil {
			return err
		}
	}

	// Add link addresses
	if link.AddressIPv4 != nil {
		addr := &netlink.Addr{
			IPNet: &link.AddressIPv4.IPNet,
		}
		err := c.ns.AddrAdd(netInterface, addr)
		if err != nil {
			return err
		}
	}

	if link.AddressIPv6 != nil {
		addr := &netlink.Addr{
			IPNet: &link.AddressIPv6.IPNet,
		}
		err := c.ns.AddrAdd(netInterface, addr)
		if err != nil {
			return err
		}
	}
	
	err = c.ns.LinkSetMTU(netInterface, link.MTU)
	if err != nil {
		return err
	}

	err = c.ns.LinkSetName(netInterface, link.Name)
	if err != nil {
		return err
	}

	if link.Enable {
		err := c.ns.LinkSetUp(netInterface)
		if err != nil {
			return err
		}
	}

	return nil
}

// Adds Peer to database.
// If peer.Enable is set and the link is loaded we try to activate the peer.
func (c *Client) AddPeer(linkName string, peer Peer) error {
	if p, _ := c.db.GetPeer(linkName, peer.Name); p != nil {
		return fmt.Errorf("Peer name \"%v\" already exists in database", peer.Name)
	}

	if err := validPeer(peer); err != nil {
		return err
	}

	err := c.db.AddPeer(linkName, peer)
	if err != nil {
		return err
	}

	if c.isLoaded(linkName) && peer.Enable {
		err = c.ActivatePeer(linkName, peer.Name)
		if err != nil {
			return err
		}
	}

	return nil
}

// Removes the peer from wireguard if link is loaded and removes it from the database.
// The peer must exist in the database.
func (c *Client) RemovePeer(linkName, peerName string) error {
	if c.isLoaded(linkName) {
		err := c.DeactivatePeer(linkName, peerName)
		if err != nil {
			return err
		}
	}

	err := c.db.RemovePeer(linkName, peerName)
	if err != nil {
		return err
	}

	return nil
}

// Activates peer, applies wireguard configurations and add IPs to routing table.
// If link is not loaded in the kernel, it returns an error.
// The peer must exist in the database.
func (c *Client) ActivatePeer(linkName, peerName string) error {
	if !c.isLoaded(linkName) {
		return fmt.Errorf("Couldn't find wireguard link %v in the kernel", linkName)
	}

	peer, err := c.db.GetPeer(linkName, peerName)
	if err != nil {
		return err
	}

	var preshared *wgtypes.Key
	if peer.PresharedKey != nil {
		preshared = &peer.PresharedKey.Key
	}
	keepalive := time.Duration(peer.PersistentKeepalive)
	allowedIPs := make([]net.IPNet, len(peer.AllowedIPs))
	for i := range peer.AllowedIPs {
		allowedIPs[i] = peer.AllowedIPs[i].IPNet
	}
	peerConfig := wgtypes.PeerConfig{
		PublicKey: peer.PublicKey.Key,
		PresharedKey: preshared,
		Endpoint: &peer.Endpoint.UDPAddr,
		PersistentKeepaliveInterval: &keepalive,
		ReplaceAllowedIPs: true,
		AllowedIPs: allowedIPs,
	}

	devConfig := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	err = c.wg.ConfigureDevice(linkName, devConfig)
	if err != nil {
		return err
	}

	netInterface, err := c.ns.LinkByName(linkName)
	if err != nil {
		return err
	}
	for _, ip := range allowedIPs {
		route := &netlink.Route{
			LinkIndex: netInterface.Attrs().Index,
			Scope: netlink.SCOPE_LINK,
			Dst: &ip,
		}

		err := c.ns.RouteAdd(route)
		if err != nil {
			return err
		}
	}

	peer.Enable = true
	err = c.db.UpdatePeer(linkName, peerName, *peer)
	if err != nil {
		return err
	}

	return nil
}

// Deactivates peer, removes peer from wireguard device and removes IPs from routing table.
// If link is not loaded in the kernel, it returns an error.
// The peer must exist in the database.
func (c *Client) DeactivatePeer(linkName, peerName string) error {
	if !c.isLoaded(linkName) {
		return fmt.Errorf("Couldn't find wireguard link %v in the kernel", linkName)
	}

	peer, err := c.db.GetPeer(linkName, peerName)
	if err != nil {
		return err
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey: peer.PublicKey.Key,
		Remove: true,
	}

	devConfig := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	err = c.wg.ConfigureDevice(linkName, devConfig)
	if err != nil {
		return err
	}

	// Remove allowed IPs from routing table
	netInterface, err := c.ns.LinkByName(linkName)
	if err != nil {
		return err
	}
	for _, ip := range peer.AllowedIPs {
		route := &netlink.Route{
			LinkIndex: netInterface.Attrs().Index,
			Scope: netlink.SCOPE_LINK,
			Dst: &ip.IPNet,
		}

		// Fails silently, if peer does not exist.
		// This is because DeactivePeer() could be called on peers that are not loaded.
		// TODO : Log failed route deletions.
		c.ns.RouteDel(route)
	}

	peer.Enable = false
	err = c.db.UpdatePeer(linkName, peerName, *peer)
	if err != nil {
		return err
	}

	return nil
}

// Updates peer in database and updates wireguard configurations.
// If peer.Enable is set and link is loaded, the peer is activated.
func (c *Client) UpdatePeer(linkName, peerName string, peer Peer) error {
	if err := validPeer(peer); err != nil {
		return err
	}

	if c.isLoaded(linkName) {
		err := c.DeactivatePeer(linkName, peerName)
		if err != nil {
			return err
		}
	}
	
	err := c.db.UpdatePeer(linkName, peerName, peer)
	if err != nil {
		return err
	}

	if c.isLoaded(linkName) && peer.Enable {
		err = c.ActivatePeer(linkName, peer.Name)
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

func validPeer(peer Peer) error {
	if len(peer.Name) == 0 {
		return errors.New("Peer name cannot be empty")
	}

	return nil
}

// Indicates whether the link is added to the kernel or not.
func (c *Client) isLoaded(name string) bool {
	netInterface, _ := c.ns.LinkByName(name)
	return netInterface != nil && netInterface.Type() == "wireguard"
}

func (c *Client) Close() error {
	if c.db != nil {
		err := c.db.Close()
		if err != nil {
			return err
		}
	}

	if c.wg != nil {
		err := c.wg.Close()
		if err != nil {
			return err
		}
	}

	if c.ns != nil {
		c.ns.Delete()
	}

	return nil
}

func NewClient(db DB) (*Client, error) {
	// Use current network namespace
	handle, err := netlink.NewHandle()
	if err != nil {
		return nil, err
	}

	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	client := &Client{
		db: db,
		wg: wg,
		ns: handle,
	}

	return client, nil
}