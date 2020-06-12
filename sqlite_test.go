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