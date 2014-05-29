package macaroons

import (
	"testing"

	gc "github.com/cmars/check"
)

func Test(t *testing.T) { gc.TestingT(t) }

type Suite struct{}

var _ = gc.Suite(&Suite{})

func (s *Suite) TestHelloMacaroons(c *gc.C) {
	m, err := New("test", "hunter2", "AzureDiamond")
	c.Assert(err, gc.IsNil)
	defer m.Close()
	c.Assert(m, gc.NotNil)

	err = m.Validate()
	c.Assert(err, gc.IsNil)

	out, err := m.Serialize()
	c.Assert(err, gc.IsNil)
	c.Check(out, gc.Not(gc.Equals), "")
}

func (s *Suite) TestCaveatsChangeThings(c *gc.C) {
	m, err := New("test", "hunter2", "AzureDiamond")
	c.Assert(err, gc.IsNil)
	defer m.Close()

	var last string
	for _, predicate := range []string{"foo", "bar", "baz", "quux"} {
		err = m.WithFirstPartyCaveat(predicate)
		c.Assert(err, gc.IsNil)
		next, err := m.Serialize()
		c.Assert(err, gc.IsNil)

		c.Assert(next, gc.Not(gc.Equals), "")
		c.Assert(last, gc.Not(gc.Equals), next)
		last = next
	}

	for _, tp := range []struct {
		loc, key, id string
	}{
		{"axton", "commando", "turret"},
		{"maya", "siren", "phaselock"},
		{"salvador", "gunzerker", "dual-wield"},
		{"zero", "a number", "hologram"},
	} {
		err = m.WithThirdPartyCaveat(tp.loc, tp.key, tp.id)
		c.Assert(err, gc.IsNil)
		next, err := m.Serialize()
		c.Assert(err, gc.IsNil)

		c.Assert(next, gc.Not(gc.Equals), "")
		c.Assert(last, gc.Not(gc.Equals), next)
		last = next
	}
}
