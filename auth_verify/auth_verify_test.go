package auth_verify

import (
	"testing"
	"crypto/rsa"
	"crypto"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type TestSuite struct {}

var _ = Suite(&TestSuite{})

func (s *TestSuite) TestParseCommaKeyValue(c *C) {
	var (
		err error
		keyExists bool
		result map[string]string
	)

	result, err = ParseCommaKeyValue("key=value,key2=value2")
	c.Check(result, HasLen, 2)
	c.Check(err, IsNil)

	_, keyExists = result["key"]
	c.Check(keyExists, Equals, true)

	_, keyExists = result["key2"]
	c.Check(keyExists, Equals, true)

	result, err = ParseCommaKeyValue("key=value,key=value2")
	c.Check(result, HasLen, 1)
	c.Check(err, IsNil)

	_, keyExists = result["key"]
	c.Check(keyExists, Equals, true)

	_, keyExists = result["key2"]
	c.Check(keyExists, Equals, false)
}

func (s *TestSuite) TestReadPublicKey(c *C) {
	var (
		err error
		iface crypto.PublicKey
		key *rsa.PublicKey
	)

	key, err = ReadPublicKey("./", "test.key")
	c.Check(key, Implements, &iface)
	c.Check(err, IsNil)

	key, err = ReadPublicKey("./", "not-exist.key")
	c.Check(key, IsNil)
	c.Check(err.Error(), Matches, "(Failed to read public key).*?")
}
