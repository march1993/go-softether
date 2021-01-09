package mayaqua

import "math/rand"

// GetError get error
func (p *Pack) GetError() uint32 {
	return p.GetInt("error")
}

// CreateDummyValue create dummy value
func (p *Pack) CreateDummyValue() {
	size := rand.Uint32() % HTTP_PACK_RAND_SIZE_MAX
	buf := make([]byte, size)
	rand.Read(buf)
	p.AddData("pencore", buf)
}
