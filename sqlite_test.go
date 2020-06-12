package dswg

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestOpenDBValid(t *testing.T) {
	assert := assert.New(t)

	db, err := OpenSqliteDB("/tmp/db.sqlite")
	assert.Nil(err)
	assert.NotNil(db)

	err = db.Close()
	assert.Nil(err)
}

func TestDBAddLinkValid(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	testlink := baseLink()
	testlink.Name = "wg-linko"

	err := db.AddLink(testlink)
	assert.Nil(err)

	dblink, err := db.GetLink("wg-linko")
	assert.Nil(err)
	assert.Equal(testlink, *dblink)
}

func TestDBAddLinkDuplicate(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	testlink := baseLink()

	err := db.AddLink(testlink)
	assert.Nil(err)

	err = db.AddLink(testlink)
	assert.NotNil(err)
}

func TestDBGetLinkNotExist(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	link, err := db.GetLink("linko")
	assert.NotNil(err)
	assert.Nil(link)
}

func TestDBUpdateLinkValid(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	testlink := baseLink()
	testlink.Name = "testo-linko1"

	err := db.AddLink(testlink)
	assert.Nil(err)

	testlink.Name = "testo-linko2"
	testlink.ListenPort = 9999

	err = db.UpdateLink("testo-linko1", testlink)
	assert.Nil(err)
	dblink, err := db.GetLink("testo-linko2")
	assert.Nil(err)
	assert.Equal(testlink, *dblink)
}

func TestDBUpdateLinkNotExist(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	testlink := baseLink()

	err := db.UpdateLink("testo-linko1", testlink)
	assert.NotNil(err)
}

func TestDBUpdateLinkDuplicateName(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	testlink1 := baseLink()
	testlink1.Name = "testo-linko1"
	testlink2 := baseLink()
	testlink2.Name = "testo-linko2"

	err := db.AddLink(testlink1)
	assert.Nil(err)
	err = db.AddLink(testlink2)
	assert.Nil(err)

	err = db.UpdateLink("testo-linko1", testlink2)
	assert.NotNil(err)

	// Assert that the invalid DB transaction did not apply
	dblink1, err := db.GetLink("testo-linko1")
	assert.Nil(err)
	assert.Equal(testlink1, *dblink1)

	dblink2, err := db.GetLink("testo-linko2")
	assert.Nil(err)
	assert.Equal(testlink2, *dblink2)
}

func TestDBRemoveLinkValid(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	testlink := baseLink()

	err := db.AddLink(testlink)
	assert.Nil(err)
	err = db.RemoveLink(testlink.Name)
	assert.Nil(err)
	dblink, err := db.GetLink(testlink.Name)
	assert.NotNil(err)
	assert.Nil(dblink)
}

func TestDBRemoveLinkNotExist(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	err := db.RemoveLink("non-existo")
	assert.NotNil(err)
}

func TestDBAddPeerValid(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	testpeer := basePeer()
	testlink := baseLink()
	err := db.AddLink(testlink)
	assert.Nil(err)
	
	err = db.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	dbpeer, err := db.GetPeer(testlink.Name, testpeer.Name)
	assert.Nil(err)
	assert.Equal(testpeer, *dbpeer)
}

func TestDBAddPeerDuplicateName(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	testlink := baseLink()
	testpeer := basePeer()
	err := db.AddLink(testlink)
	assert.Nil(err)
	
	err = db.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	// Make sure keys are different to test duplicate names
	randkey, _ := ParseKey("RANDngJZ2jf+sREdOi/b0D8rTGMbcjgSA854Jn2KbzQ=")
	testpeer.PublicKey = *randkey

	err = db.AddPeer(testlink.Name, testpeer)
	assert.NotNil(err)
}

func TestDBAddPeerDuplicateKey(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	testlink := baseLink()
	err := db.AddLink(testlink)
	assert.Nil(err)
	testpeer := basePeer()

	err = db.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	// Make sure names are different to test duplicate keys
	testpeer.Name = "RANDO-NAME"

	err = db.AddPeer(testlink.Name, testpeer)
	assert.NotNil(err)
}

func TestDBAddPeerNonExistingLink(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	testpeer := basePeer()
	
	err := db.AddPeer("wg0", testpeer)
	assert.NotNil(err)
}

func TestDBGetPeerNotExist(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	testlink := baseLink()
	err := db.AddLink(testlink)
	assert.Nil(err)
	
	dbpeer, err := db.GetPeer(testlink.Name, "peer0")
	assert.NotNil(err)
	assert.Nil(dbpeer)
}

func TestDBUpdatePeerValid(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	testpeer := basePeer()
	testpeer.Name = "peero-1"
	testlink := baseLink()
	err := db.AddLink(testlink)
	assert.Nil(err)

	err = db.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	testpeer.Name = "peero-2"
	err = db.UpdatePeer(testlink.Name, "peero-1", testpeer)
	assert.Nil(err)
	dbpeer, err := db.GetPeer(testlink.Name, "peero-2")
	assert.Nil(err)
	assert.Equal(testpeer, *dbpeer)
}

func TestDBUpdatePeerNotExist(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	testlink := baseLink()
	err := db.AddLink(testlink)
	assert.Nil(err)

	err = db.UpdatePeer(testlink.Name, "peero-1", basePeer())
	assert.NotNil(err)
}

func TestDBUpdatePeerDuplicateName(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	testpeer1 := basePeer()
	testpeer1.Name = "peero-1"
	testpeer2 := basePeer()
	testpeer2.Name = "peero-2"
	randkey, _ := ParseKey("RANDngJZ2jf+sREdOi/b0D8rTGMbcjgSA854Jn2KbzQ=")
	testpeer2.PublicKey = *randkey
	
	testlink := baseLink()
	err := db.AddLink(testlink)
	assert.Nil(err)

	err = db.AddPeer(testlink.Name, testpeer1)
	assert.Nil(err)
	err = db.AddPeer(testlink.Name, testpeer2)
	assert.Nil(err)

	err = db.UpdatePeer(testlink.Name, "peero-1", testpeer2)
	assert.NotNil(err)
	
	dbpeer1, err := db.GetPeer(testlink.Name, "peero-1")
	assert.Nil(err)
	assert.Equal(testpeer1, *dbpeer1)
	
	dbpeer2, err := db.GetPeer(testlink.Name, "peero-2")
	assert.Nil(err)
	assert.Equal(testpeer2, *dbpeer2)
}

func TestDBRemovePeerValid(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	testpeer := basePeer()
	testlink := baseLink()
	err := db.AddLink(testlink)
	assert.Nil(err)
	
	err = db.AddPeer(testlink.Name, testpeer)
	assert.Nil(err)

	err = db.RemovePeer(testlink.Name, testpeer.Name)
	assert.Nil(err)
	
	dbpeer, err := db.GetPeer(testlink.Name, testpeer.Name)
	assert.NotNil(err)
	assert.Nil(dbpeer)
}

func TestDBRemovePeerNotExist(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	testlink := baseLink()
	err := db.AddLink(testlink)
	assert.Nil(err)

	err = db.RemovePeer(testlink.Name, "peer-0")
	assert.NotNil(err)
}

func TestDBRemovePeerLinkNotExist(t *testing.T) {
	assert := assert.New(t)

	db := setupDB()
	defer db.Close()

	err := db.RemovePeer("link-0", "peer-0")
	assert.NotNil(err)
}