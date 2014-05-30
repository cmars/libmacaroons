package macaroons

import (
	"strings"
	"time"

	gc "gopkg.in/check.v1"
)

func (s *Suite) TestVerifyExact(c *gc.C) {
	usernameRule := "username = tk421"
	locationRule := "location = cargo-bay-11"
	secret := "not a moon"

	m, err := NewMacaroon("death star", secret, "tk421@deathstar")
	c.Assert(err, gc.IsNil)
	defer m.Destroy()
	c.Assert(m, gc.NotNil)

	// no caveats, ok
	func() {
		v1 := NewVerifier()
		defer v1.Destroy()
		err = v1.Verify(m, "let the wookie win")
		c.Assert(err, gc.IsNil)
	}()

	// wrong secret, err
	func() {
		v2 := NewVerifier()
		defer v2.Destroy()
		err = v2.Verify(m, "han shot first")
		c.Assert(err, gc.NotNil)
	}()

	// fail username caveat, err
	func() {
		m1, err := m.Copy()
		c.Assert(err, gc.IsNil)
		defer m1.Destroy()
		m1.WithFirstPartyCaveat("username = r2d2")

		v := NewVerifier()
		defer v.Destroy()
		v.SatisfyExact(usernameRule)
		v.SatisfyExact(locationRule)
		err = v.Verify(m1, secret)
		c.Assert(err, gc.NotNil, gc.Commentf("%+v", err)) // TK-421 is not at his post
	}()

	// fail location caveat, err
	func() {
		m2, err := m.Copy()
		c.Assert(err, gc.IsNil)
		defer m2.Destroy()
		m2.WithFirstPartyCaveat("username = tk421")
		m2.WithFirstPartyCaveat("location = detention-level-aa23")

		v := NewVerifier()
		v.SatisfyExact(usernameRule)
		v.SatisfyExact(locationRule)
		err = v.Verify(m2, secret)
		c.Assert(err, gc.NotNil) // TK-421 is not at his post
	}()

	// satisfy both caveats, ok
	func() {
		m3, err := m.Copy()
		c.Assert(err, gc.IsNil)
		defer m3.Destroy()
		m3.WithFirstPartyCaveat("username = tk421")
		m3.WithFirstPartyCaveat("location = cargo-bay-11")

		v := NewVerifier()
		v.SatisfyExact(usernameRule)
		v.SatisfyExact(locationRule)
		err = v.Verify(m3, secret)
		c.Assert(err, gc.IsNil, gc.Commentf("%+v", err)) // TK-421 is at his post
	}()
}

func (s *Suite) TestVerifyGeneral(c *gc.C) {
	secret := "wait til you see those goddamn bats"
	m, err := NewMacaroon("The Mint Hotel", secret, "hst")
	c.Assert(err, gc.IsNil)
	defer m.Destroy()
	c.Assert(m, gc.NotNil)

	layout := "2006-01-02T15:04:05 -0700"
	deadline, err := time.Parse(layout, "1971-11-11T16:00:00 -0800")
	c.Assert(err, gc.IsNil)

	v := NewVerifier()
	err = v.SatisfyGeneral(func(s string) bool {
		fields := strings.SplitN(s, " ", 3)
		if len(fields) != 3 {
			return false
		}
		if fields[0] != "time" {
			return false
		}
		if fields[1] != "=" {
			return false
		}
		t, err := time.Parse(layout, fields[2])
		if err != nil {
			return false
		}
		return t.Before(deadline)
	})
	c.Assert(err, gc.IsNil)

	func() {
		m2, err := m.Copy()
		c.Assert(err, gc.IsNil)
		err = m2.WithFirstPartyCaveat("time = 2014-05-08T23:40:00 +0000")
		c.Assert(err, gc.IsNil)
		err = v.Verify(m2, secret)
		c.Assert(err, gc.NotNil)
	}()

	func() {
		m2, err := m.Copy()
		c.Assert(err, gc.IsNil)
		err = m2.WithFirstPartyCaveat("time = 1971-11-11T15:59:59 -0800")
		c.Assert(err, gc.IsNil)
		err = v.Verify(m2, secret)
		c.Assert(err, gc.IsNil)
	}()
}
