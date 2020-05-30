package dswg

type DB interface {
	AddLink(link Link) error
	GetLink(name string) (*Link, error)
	UpdateLink(name string, link Link) error
	RemoveLink(name string) error

	Close()	error
}