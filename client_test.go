package dswg

import (
	"net"
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netns"
)

// TODO: Use better error types, and update tests to assert for those types

// Tests that modify the network are preceded by creating
// a new network namespace to avoid corrupting the current
// machine network configuration 
// 		netns, _ := netns.New()
// 		defer netns.Close()

func TestNewClientValid(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	db, _ := OpenSqliteDB(":memory:")
	defer db.Close()

	client, err := NewClient(db)
	assert.Nil(err)
	assert.NotNil(client)
	assert.NotNil(client.db)
	assert.NotNil(client.wg)
	assert.NotNil(client.ns)
	err = client.Close()
	assert.Nil(err)
}

func TestClientAddLinkValidNotEnabled(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()
	
	testlink := baseLink()
	testlink.Enable = false
	
	err := client.AddLink(testlink)
	assert.Nil(err)

	netInterface, _ := client.ns.LinkByName(testlink.Name)
	assert.Nil(netInterface)

	dblink, err := client.db.GetLink(testlink.Name)
	assert.Nil(err)
	assert.Equal(testlink, *dblink)
}

func TestClientAddLinkValidEnabled(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()
	
	testlink := baseLink()
	testlink.Enable = true
	
	err := client.AddLink(testlink)
	assert.Nil(err)

	netInterface, _ := client.ns.LinkByName(testlink.Name)
	assert.NotNil(netInterface)
	assert.Equal(netInterface.Type(), "wireguard")
	assert.Equal(netInterface.Attrs().Flags & net.FlagUp, net.FlagUp)
}

func TestClientAddLinkDuplicateDBName(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()
	
	testlink := baseLink()
	err := client.db.AddLink(testlink)
	assert.Nil(err)

	err = client.AddLink(testlink)
	assert.NotNil(err)
}

func TestClientAddLinkExistInKernel(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()
	
	testlink := baseLink()
	err := client.ns.LinkAdd(testlink)
	assert.Nil(err)

	err = client.AddLink(testlink)
	assert.NotNil(err)
}

func TestClientAddLinkEmptyName(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()
	
	testlink := baseLink()
	testlink.Enable = false
	testlink.Name = ""

	err := client.AddLink(testlink)
	assert.NotNil(err)
}

func TestClientAddLinkNoIPs(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = false
	testlink.AddressIPv4 = nil
	testlink.AddressIPv6 = nil

	err := client.AddLink(testlink)
	assert.NotNil(err)
}

func TestClientRemoveLinkLoaded(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()
	
	testlink := baseLink()
	testlink.Enable = true
	
	err := client.AddLink(testlink)
	assert.Nil(err)

	netInterface, _ := client.ns.LinkByName(testlink.Name)
	assert.NotNil(netInterface)
	assert.Equal(netInterface.Type(), "wireguard")

	err = client.RemoveLink(testlink.Name)
	assert.Nil(err)

	// Assert that link is removed from the kernel
	netInterface, _ = client.ns.LinkByName(testlink.Name)
	assert.Nil(netInterface)

	dblink, err := client.db.GetLink(testlink.Name)
	assert.NotNil(err)
	assert.Nil(dblink)
}

func TestClientRemoveLinkPeers(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()
	
	testlink := baseLink()
	testpeer := basePeer()

	err := client.db.AddLink(testlink)
	assert.Nil(err)

	err = client.db.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	err = client.RemoveLink(testlink.Name)
	assert.Nil(err)

	dbpeer, err := client.db.GetPeer(testlink.Name, testpeer.Name)
	assert.NotNil(err)
	assert.Nil(dbpeer)
}

func TestClientRemoveLinkNotExist(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	err := client.RemoveLink("non-existo-linko")
	assert.NotNil(err)
}

func TestClientActivateLinkNotExist(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	err := client.ActivateLink("no-existo")
	assert.NotNil(err)
}

func TestClientActivateLinkNotLoaded(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()
	
	testlink := baseLink()
	testlink.Enable = false

	err := client.AddLink(testlink)
	assert.Nil(err)

	netInterface, _ := client.ns.LinkByName(testlink.Name)
	assert.Nil(netInterface)

	err = client.ActivateLink(testlink.Name)
	assert.Nil(err)

	netInterface, _ = client.ns.LinkByName(testlink.Name)
	assert.NotNil(netInterface)
	assert.Equal(netInterface.Type(), "wireguard")
	assert.Equal(netInterface.Attrs().Flags & net.FlagUp, net.FlagUp)
	
	dblink, err := client.db.GetLink(testlink.Name)
	assert.Nil(err)
	assert.True(dblink.Enable)

	wglink, err := client.wg.Device(testlink.Name)
	assert.Nil(err)
	assert.Equal(testlink.Name, wglink.Name)
	assert.Equal(testlink.PrivateKey.Key, wglink.PrivateKey)
	assert.Equal(testlink.ListenPort, wglink.ListenPort)
	assert.Equal(testlink.FirewallMark, wglink.FirewallMark)
}

func TestClientActivateLinkPeersActivated(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()
	
	testlink := baseLink()
	testlink.Enable = false

	err := client.AddLink(testlink)
	assert.Nil(err)

	testpeer1 := basePeer()
	testpeer1.Name = "peer1"
	randkey, _ := ParseKey("RND1ngJZ2jf+sREdOi/b0D8rTGMbcjgSA854Jn2KbzQ=")
	testpeer1.PublicKey = *randkey
	err = client.db.AddPeer(testlink.Name, testpeer1)
	assert.Nil(err)
	
	testpeer2 := basePeer()
	testpeer2.Name = "peer2"
	randkey, _ = ParseKey("RND2ngJZ2jf+sREdOi/b0D8rTGMbcjgSA854Jn2KbzQ=")
	testpeer2.PublicKey = *randkey
	err = client.db.AddPeer(testlink.Name, testpeer2)
	assert.Nil(err)

	err = client.ActivateLink(testlink.Name)
	assert.Nil(err)

	wglink, err := client.wg.Device(testlink.Name)
	assert.Nil(err)
	assert.Equal(len(wglink.Peers), 2)

	wgpeers := make(map[string]bool)
	for _, peer := range wglink.Peers {
		wgpeers[peer.PublicKey.String()] = true
	}

	assert.True(wgpeers[testpeer1.PublicKey.String()])
	assert.True(wgpeers[testpeer2.PublicKey.String()])
}

// TODO: Test executed commands when link is activated

func TestClientDeactivateLinkNotExist(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	err := client.DeactivateLink("no-existo")
	assert.NotNil(err)
}

func TestClientDeactivateLinkActivated(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = true

	err := client.AddLink(testlink)
	assert.Nil(err)

	err = client.DeactivateLink(testlink.Name)
	assert.Nil(err)

	netInterface, _ := client.ns.LinkByName(testlink.Name)
	assert.NotNil(netInterface)
	assert.NotEqual(netInterface.Attrs().Flags & net.FlagUp, net.FlagUp)

	dblink, err := client.db.GetLink(testlink.Name)
	assert.Nil(err)
	assert.False(dblink.Enable)
}

func TestClientDeactivateLinkNotLoaded(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = false

	err := client.AddLink(testlink)
	assert.Nil(err)

	err = client.DeactivateLink(testlink.Name)
	assert.Nil(err)
}

func TestClientUpdateLinkValidEnabled(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink1 := baseLink()
	testlink1.Enable = false
	testlink1.Name = "link1"

	testlink2 := baseLink()
	testlink2.Enable = true
	testlink2.Name = "link2"

	err := client.AddLink(testlink1)
	assert.Nil(err)

	err = client.UpdateLink(testlink1.Name, testlink2)
	assert.Nil(err)

	dblink, err := client.db.GetLink(testlink2.Name)
	assert.Nil(err)
	assert.Equal(testlink2, *dblink)

	netInterface, _ := client.ns.LinkByName(testlink2.Name)
	assert.NotNil(netInterface)
	assert.Equal(netInterface.Type(), "wireguard")
	assert.Equal(netInterface.Attrs().Flags & net.FlagUp, net.FlagUp)
}

func TestClientUpdateLinkValidLoaded(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink1 := baseLink()
	testlink1.Enable = true
	testlink1.Name = "link1"

	testlink2 := baseLink()
	testlink2.Name = "link2"
	testlink2.Enable = false

	err := client.AddLink(testlink1)
	assert.Nil(err)

	err = client.UpdateLink(testlink1.Name, testlink2)
	assert.Nil(err)

	dblink, err := client.db.GetLink(testlink2.Name)
	assert.Nil(err)
	assert.Equal(testlink2, *dblink)

	netInterface, _ := client.ns.LinkByName(testlink2.Name)
	assert.NotNil(netInterface)
	assert.NotEqual(netInterface.Attrs().Flags & net.FlagUp, net.FlagUp)
}

func TestClientUpdateLinkInvalid(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink1 := baseLink()
	testlink1.Enable = false
	testlink1.Name = "link1"

	testlink2 := baseLink()
	testlink2.AddressIPv4 = nil
	testlink2.AddressIPv6 = nil
	testlink2.Name = "link2"

	err := client.AddLink(testlink1)
	assert.Nil(err)

	err = client.UpdateLink(testlink1.Name, testlink2)
	assert.NotNil(err)
}

func TestClientAddPeerDuplicateName(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = false
	err := client.AddLink(testlink)
	assert.Nil(err)

	testpeer := basePeer()
	err = client.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	// Change public key
	key, _ := ParseKey("CHG+ngJZ2jf+sREdOi/b0D8rTGMbcjgSA854Jn2KbzQ=")
	testpeer.PublicKey = *key
	err = client.AddPeer(testlink.Name, testpeer)
	assert.NotNil(err)
}

func TestClientAddPeerDuplicatePublicKey(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = false
	err := client.AddLink(testlink)
	assert.Nil(err)

	testpeer := basePeer()
	err = client.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	// Change name
	testpeer.Name = "new-name"
	err = client.AddPeer(testlink.Name, testpeer)
	assert.NotNil(err)
}

func TestClientAddPeerEmptyName(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = false
	err := client.AddLink(testlink)
	assert.Nil(err)

	testpeer := basePeer()
	testpeer.Name = ""
	err = client.AddPeer(testlink.Name, testpeer)
	assert.NotNil(err)
}

func TestClientAddPeerValid(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = false
	err := client.AddLink(testlink)
	assert.Nil(err)

	testpeer := basePeer()
	testpeer.Enable = false
	err = client.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	dbpeer, err := client.db.GetPeer(testlink.Name, testpeer.Name)
	assert.Nil(err)
	assert.Equal(testpeer, *dbpeer)
}

func TestClientAddPeerEnabledLinkLoaded(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = true
	err := client.AddLink(testlink)
	assert.Nil(err)

	testpeer := basePeer()
	testpeer.Enable = true
	err = client.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	dbpeer, err := client.db.GetPeer(testlink.Name, testpeer.Name)
	assert.Nil(err)
	assert.Equal(testpeer, *dbpeer)

	wglink, err := client.wg.Device(testlink.Name)
	assert.Nil(err)
	wgpeer := wglink.Peers[0]
	assert.Equal(testpeer.PublicKey.Key, wgpeer.PublicKey)
	assert.Equal(testpeer.PresharedKey.Key, wgpeer.PresharedKey)
	assert.Equal(testpeer.Endpoint.UDPAddr.Port, wgpeer.Endpoint.Port)
	assert.Equal(testpeer.PersistentKeepalive, int64(wgpeer.PersistentKeepaliveInterval))

	wgallowed := make(map[string]bool)
	for _, ip := range wgpeer.AllowedIPs {
		wgallowed[ip.String()] = true
	}
	
	for _, ip := range testpeer.AllowedIPs {
		assert.True(wgallowed[ip.String()])
	}
}

func TestClientRemovePeerValid(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = false
	err := client.AddLink(testlink)
	assert.Nil(err)

	testpeer := basePeer()
	err = client.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	dbpeer, err := client.db.GetPeer(testlink.Name, testpeer.Name)
	assert.Nil(err)
	assert.Equal(testpeer, *dbpeer)

	err = client.RemovePeer(testlink.Name, testpeer.Name)
	assert.Nil(err)

	dbpeer, err = client.db.GetPeer(testlink.Name, testpeer.Name)
	assert.NotNil(err)
	assert.Nil(dbpeer)
}

func TestClientRemovePeerEnabledLinkLoaded(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = true
	err := client.AddLink(testlink)
	assert.Nil(err)

	testpeer := basePeer()
	testpeer.Enable = true
	err = client.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	dbpeer, err := client.db.GetPeer(testlink.Name, testpeer.Name)
	assert.Nil(err)
	assert.Equal(testpeer, *dbpeer)

	wglink, err := client.wg.Device(testlink.Name)
	assert.Nil(err)
	assert.Equal(len(wglink.Peers), 1)

	err = client.RemovePeer(testlink.Name, testpeer.Name)
	assert.Nil(err)

	wglink, err = client.wg.Device(testlink.Name)
	assert.Nil(err)
	assert.Equal(len(wglink.Peers), 0)
}

func TestClientRemovePeerNotExist(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = false
	err := client.AddLink(testlink)
	assert.Nil(err)

	err = client.RemovePeer(testlink.Name, "no-peero")
	assert.NotNil(err)
}

func TestClientActivatePeerLinkNotLoaded(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = false
	err := client.AddLink(testlink)
	assert.Nil(err)

	testpeer := basePeer()
	testpeer.Enable = false
	err = client.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	err = client.ActivatePeer(testlink.Name, testpeer.Name)
	assert.NotNil(err)
}

func TestClientActivatePeerNotExist(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = false
	err := client.AddLink(testlink)
	assert.Nil(err)

	err = client.ActivatePeer(testlink.Name, "no-peer")
	assert.NotNil(err)
}

func TestClientActivatePeerValid(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = true
	err := client.AddLink(testlink)
	assert.Nil(err)

	testpeer := basePeer()
	testpeer.Enable = false
	err = client.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	wglink, _ := client.wg.Device(testlink.Name)
	assert.Equal(len(wglink.Peers), 0)

	err = client.ActivatePeer(testlink.Name, testpeer.Name)
	assert.Nil(err)

	dbpeer, _ := client.db.GetPeer(testlink.Name, testpeer.Name)
	assert.True(dbpeer.Enable)

	wglink, _ = client.wg.Device(testlink.Name)
	assert.Equal(len(wglink.Peers), 1)
}

func TestClientDeactivatePeerLinkNotLoaded(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = false
	err := client.AddLink(testlink)
	assert.Nil(err)

	testpeer := basePeer()
	testpeer.Enable = false
	err = client.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	err = client.DeactivatePeer(testlink.Name, testpeer.Name)
	assert.NotNil(err)
}

func TestClientDeactivatePeerNotExist(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = false
	err := client.AddLink(testlink)
	assert.Nil(err)

	err = client.DeactivatePeer(testlink.Name, "no-peer")
	assert.NotNil(err)
}

func TestClientDeactivatePeerValid(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = true
	err := client.AddLink(testlink)
	assert.Nil(err)

	testpeer := basePeer()
	testpeer.Enable = true
	err = client.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	wglink, _ := client.wg.Device(testlink.Name)
	assert.Equal(len(wglink.Peers), 1)

	err = client.DeactivatePeer(testlink.Name, testpeer.Name)
	assert.Nil(err)

	dbpeer, _ := client.db.GetPeer(testlink.Name, testpeer.Name)
	assert.False(dbpeer.Enable)

	wglink, _ = client.wg.Device(testlink.Name)
	assert.Equal(len(wglink.Peers), 0)
}

func TestClientUpdatePeerInvalid(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = false
	err := client.AddLink(testlink)
	assert.Nil(err)

	testpeer1 := basePeer()
	testpeer1.Enable = false
	err = client.AddPeer(testlink.Name, testpeer1)
	assert.Nil(err)

	testpeer2 := basePeer()
	testpeer2.Name = ""
	err = client.UpdatePeer(testlink.Name, testpeer1.Name, testpeer2)
	assert.NotNil(err)

	dbpeer, _ := client.db.GetPeer(testlink.Name, testpeer1.Name)
	assert.Equal(testpeer1, *dbpeer)
}

func TestClientUpdatePeerDuplicateName(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = false
	err := client.AddLink(testlink)
	assert.Nil(err)

	testpeer1 := basePeer()
	testpeer1.Enable = false
	testpeer1.Name = "peer1"
	err = client.AddPeer(testlink.Name, testpeer1)
	assert.Nil(err)

	testpeer2 := basePeer()
	testpeer2.Name = "peer2"
	testpeer1.Enable = false
	// Change public key
	key, _ := ParseKey("CHG+ngJZ2jf+sREdOi/b0D8rTGMbcjgSA854Jn2KbzQ=")
	testpeer2.PublicKey = *key
	err = client.AddPeer(testlink.Name, testpeer2)
	assert.Nil(err)

	err = client.UpdatePeer(testlink.Name, testpeer1.Name, testpeer2)
	assert.NotNil(err)

	dbpeer, _ := client.db.GetPeer(testlink.Name, testpeer1.Name)
	assert.Equal(testpeer1, *dbpeer)

	dbpeer, _ = client.db.GetPeer(testlink.Name, testpeer2.Name)
	assert.Equal(testpeer2, *dbpeer)
}

func TestClientUpdatePeerLinkLoadedEnable(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = true
	err := client.AddLink(testlink)
	assert.Nil(err)

	testpeer := basePeer()
	testpeer.Enable = false
	err = client.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	wglink, _ := client.wg.Device(testlink.Name)
	assert.Equal(len(wglink.Peers), 0)

	testpeer.Enable = true
	err = client.UpdatePeer(testlink.Name, testpeer.Name, testpeer)
	assert.Nil(err)

	dbpeer, _ := client.db.GetPeer(testlink.Name, testpeer.Name)
	assert.Equal(testpeer, *dbpeer)

	wglink, _ = client.wg.Device(testlink.Name)
	assert.Equal(len(wglink.Peers), 1)
}

func TestClientUpdatePeerLinkNotLoaded(t *testing.T) {
	assert := assert.New(t)

	// Create a new network namespace 
	netns, _ := netns.New()
	defer netns.Close()

	client := baseClient()
	defer client.Close()

	testlink := baseLink()
	testlink.Enable = false
	err := client.AddLink(testlink)
	assert.Nil(err)

	testpeer := basePeer()
	testpeer.Enable = false
	err = client.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	err = client.UpdatePeer(testlink.Name, testpeer.Name, testpeer)
	assert.Nil(err)

	dbpeer, _ := client.db.GetPeer(testlink.Name, testpeer.Name)
	assert.Equal(testpeer, *dbpeer)
}