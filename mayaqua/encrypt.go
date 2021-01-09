package mayaqua

const (
	MD5_SIZE    = uint32(16)
	SHA1_SIZE   = uint32(20)
	SHA256_SIZE = uint32(32)
	SHA384_SIZE = uint32(48)
	SHA512_SIZE = uint32(64)
)

// Sha1Sum sha1 sum array
type Sha1Sum = [SHA1_SIZE]byte

// Sha0Context sha-0 context
type Sha0Context struct {
	count uint64
	buf   [64]byte
	state [8]uint32
}

// Init sha0 init
func (c *Sha0Context) Init() {
	c.state[0] = 0x67452301
	c.state[1] = 0xEFCDAB89
	c.state[2] = 0x98BADCFE
	c.state[3] = 0x10325476
	c.state[4] = 0xC3D2E1F0
	c.count = 0
}

func rol(bits int, value uint32) uint32 {
	return (((value) << (bits)) | ((value) >> (32 - (bits))))
}

// Transform sha0 transform
func (c *Sha0Context) Transform() {
	W := [80]uint32{}

	p := 0
	t := 0

	for ; t < 16; t++ {
		tmp := uint32(c.buf[p+0]) << 24
		tmp |= uint32(c.buf[p+1]) << 16
		tmp |= uint32(c.buf[p+2]) << 8
		tmp |= uint32(c.buf[p+3]) << 0
		W[t] = tmp
		p += 4
	}

	for ; t < 80; t++ {
		W[t] = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]
	}

	A, B, C, D, E := c.state[0], c.state[1], c.state[2], c.state[3], c.state[4]

	for t = 0; t < 80; t++ {
		tmp := rol(5, A) + E + W[t]
		if t < 20 {
			tmp += (D ^ (B & (C ^ D))) + 0x5A827999
		} else if t < 40 {
			tmp += (B ^ C ^ D) + 0x6ED9EBA1
		} else if t < 60 {
			tmp += ((B & C) | (D & (B | C))) + 0x8F1BBCDC
		} else {
			tmp += (B ^ C ^ D) + 0xCA62C1D6
		}

		E = D
		D = C
		C = rol(30, B)
		B = A
		A = tmp
	}

	c.state[0] += A
	c.state[1] += B
	c.state[2] += C
	c.state[3] += D
	c.state[4] += E
}

// Update sha0 update
func (c *Sha0Context) Update(data []byte) {
	i := int(c.count & 63)

	l := len(data)
	c.count += uint64(l)

	for _, d := range data {
		c.buf[i] = d
		i++
		if i == 64 {
			c.Transform()
			i = 0
		}
	}
}

// Final sha0 final
func (c *Sha0Context) Final() {
	cnt := c.count * 8

	c.Update([]byte{0x80})
	for c.count&63 != 56 {
		c.Update([]byte{0x0})
	}

	for i := 0; i < 8; i++ {
		tmp := uint8(cnt >> ((7 - i) * 8))
		c.Update([]byte{tmp})
	}

	p := 0
	for i := 0; i < 5; i++ {
		tmp := c.state[i]
		c.buf[p+0] = uint8(tmp >> 24)
		c.buf[p+1] = uint8(tmp >> 16)
		c.buf[p+2] = uint8(tmp >> 8)
		c.buf[p+3] = uint8(tmp >> 0)
		p += 4
	}
}

// Sha0 calc sha-0
func Sha0(data []byte) Sha1Sum {
	ctx := Sha0Context{}
	ctx.Init()
	ctx.Update(data)
	ctx.Final()
	ret := Sha1Sum{}
	copy(ret[:], ctx.buf[0:SHA1_SIZE])
	return ret
}
