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
	defer m.Destroy()
	c.Assert(m, gc.NotNil)

	c.Check(m.Location(), gc.Equals, "test")
	c.Check(m.Id(), gc.Equals, "AzureDiamond")

	err = m.WithFirstPartyCaveat("hello = world")
	c.Assert(err, gc.IsNil)

	err = m.Validate()
	c.Assert(err, gc.IsNil)

	out, err := m.Marshal()
	c.Assert(err, gc.IsNil)

	m2, err := Unmarshal(out)
	c.Assert(err, gc.IsNil)
	defer m2.Destroy()
	c.Check(m2.Signature(), gc.Equals, m.Signature())
	c.Check(m2.Location(), gc.Equals, "test")
	c.Check(m2.Id(), gc.Equals, "AzureDiamond")

	err = m2.Validate()
	c.Assert(err, gc.IsNil)
}

func (s *Suite) TestCaveatsChangeThings(c *gc.C) {
	m, err := New("pandora", "catch a ride", "scooter")
	c.Assert(err, gc.IsNil)
	defer m.Destroy()

	var last string
	for _, predicate := range []string{"roland", "mordecai", "lilith", "brick"} {
		err = m.WithFirstPartyCaveat(predicate)
		c.Assert(err, gc.IsNil)
		next, err := m.Marshal()
		c.Assert(err, gc.IsNil)

		c.Assert(next, gc.Not(gc.HasLen), 0)
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
		next, err := m.Marshal()
		c.Assert(err, gc.IsNil)

		c.Assert(next, gc.Not(gc.Equals), "")
		c.Assert(last, gc.Not(gc.Equals), next)
		last = next
	}
}

func (s *Suite) TestInspect(c *gc.C) {
	m, err := New("ingsoc", "under the spreading chestnut tree", "wsmith")
	c.Assert(err, gc.IsNil)
	defer m.Destroy()

	desc, err := m.Inspect()
	c.Assert(err, gc.IsNil)
	c.Check(desc, gc.Equals, `location ingsoc
identifier wsmith
signature d5c974d83f28c451f7955af20fd13c97296f0344f762bf7b89d91b31f2abdb30`)

	m.WithFirstPartyCaveat("war = peace")
	m.WithFirstPartyCaveat("slavery = freedom")
	m.WithFirstPartyCaveat("ignorance = strength")
	desc, err = m.Inspect()
	c.Check(desc, gc.Equals, `location ingsoc
identifier wsmith
cid war = peace
cid slavery = freedom
cid ignorance = strength
signature ef6e75301b1cafde6e87a1d44adab81b6492f5c11d51026c4a5be9beda1a07be`)
}
