package dswg

import (
	"net"
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netns"
)

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

// TODO: Test activated peers and executed commands when link is activated

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