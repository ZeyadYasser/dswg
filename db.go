package dswg

type DB interface {
	AddLink(link Link) error
	GetLink(name string) (*Link, error)
	UpdateLink(name string, link Link) error
	RemoveLink(name string) error

	AddPeer(linkName string, peer Peer) error
	GetPeer(linkName, peerName string) (*Peer, error)
	UpdatePeer(linkName, peerName string, peer Peer) error
	RemovePeer(linkName, peerName string) error

	Close()	error
}