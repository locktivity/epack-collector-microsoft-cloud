package collector

import "time"

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

type FixedClock struct {
	Time time.Time
}

func (c FixedClock) Now() time.Time { return c.Time.UTC() }
