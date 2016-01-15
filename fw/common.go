/*
Package fw implements an interface to several firewall backends.
*/
package fw

type Blocker interface {
	Block(addr string) error
	Flush() error
	Release(addr string) error
	Init() error
}
