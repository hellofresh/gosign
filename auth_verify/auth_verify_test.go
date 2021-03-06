package auth_verify

import (
	"crypto"
	"crypto/rsa"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type TestSuite struct{}

var _ = Suite(&TestSuite{})

func (s *TestSuite) TestParseCommaKeyValue(c *C) {
	var (
		err       error
		keyExists bool
		result    map[string]string
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

	// Check incorrect format =
	result, err = ParseCommaKeyValue("key=value,key2")
	c.Check(result, IsNil)
	c.Check(err.Error(), Matches, "(The key,value string is formated incorrect).*?")

	// Check incorrect format ,
	result, err = ParseCommaKeyValue("key=value,key2=value2,")
	c.Check(result, IsNil)
	c.Check(err.Error(), Matches, "(The comma string is formated incorrect).*?")
}

func (s *TestSuite) TestReadPublicKey(c *C) {
	var (
		err   error
		iface crypto.PublicKey
		key   *rsa.PublicKey
	)

	key, err = ReadPublicKey("./", "test.key")
	c.Check(key, Implements, &iface)
	c.Check(err, IsNil)

	key, err = ReadPublicKey("./", "not-exist.key")
	c.Check(key, IsNil)
	c.Check(err.Error(), Matches, "(Failed to read public key).*?")
}

func (s *TestSuite) TestgetTimeFromHeader(c *C) {
	var (
		err   error
		dates []string = []string{
			"Friday, 15-Apr-16 10:27:35 CEST",
			"Fri, 15 Apr 2016 10:27:35 CEST",
			"Fri, 15 Apr 2016 10:27:35 +0200",
			"15 Apr 16 10:27 CEST",
			"15 Apr 16 10:27 +0200",
		}
	)

	for _, date := range dates {
		_, err = getTimeFromHeader(date)

		c.Check(err, IsNil)
	}
}
