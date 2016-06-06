package fw

type NullBlocker struct{}

func NewNullBlocker() NullBlocker {
	return NullBlocker{}
}

func (NullBlocker) Block(addr string) error {
	return nil
}

func (NullBlocker) Flush() error {
	return nil
}

func (NullBlocker) Release(addr string) error {
	return nil
}

func (NullBlocker) Init() error {
	return nil
}
