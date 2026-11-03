// Package ratelimit is an in-memory token bucket.
// Buckets are discarded on process restart. Id keys are capped with an LRU
// so random identifiers cannot grow memory without bound.
package ratelimit

import (
	"sync"
	"time"
)

// Rule is a token bucket that starts full.
type Rule struct {
	Capacity     float64
	RefillPerSec float64
}

// Production rules from the spec.
var (
	LoginRule  = Rule{Capacity: 5, RefillPerSec: 5.0 / 60}
	CreateRule = Rule{Capacity: 30, RefillPerSec: 30.0 / 3600}
	RevealRule = Rule{Capacity: 10, RefillPerSec: 10.0 / 60}
)

type state struct {
	tokens  float64
	updated time.Time
}

// Limiter bounds three independent key spaces.
type Limiter struct {
	mu  sync.Mutex
	now func() time.Time
	ip  *pool
	id  *pool
	ses *pool
}

func New(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		now: now,
		ip:  newPool(4096),
		id:  newPool(1024),
		ses: newPool(256),
	}
}

// AllowIP consumes one token for an IP-scoped key.
func (l *Limiter) AllowIP(key string, rule Rule) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return take(l.ip, key, rule, l.now())
}

// AllowPair consumes one token from each key only when both buckets allow it.
func (l *Limiter) AllowPair(poolA *pool, keyA string, ruleA Rule, poolB *pool, keyB string, ruleB Rule) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	a := poolA.touch(keyA, ruleA, now)
	b := poolB.touch(keyB, ruleB, now)
	if a.tokens < 1 || b.tokens < 1 {
		return false
	}
	a.tokens--
	b.tokens--
	return true
}

// AllowIPAndID enforces both reveal limits.
func (l *Limiter) AllowIPAndID(ipKey, idKey string, rule Rule) bool {
	return l.AllowPair(l.ip, ipKey, rule, l.id, idKey, rule)
}

// AllowIPAndSession enforces both create limits.
func (l *Limiter) AllowIPAndSession(ipKey, sessionKey string, rule Rule) bool {
	return l.AllowPair(l.ip, ipKey, rule, l.ses, sessionKey, rule)
}

func take(p *pool, key string, rule Rule, now time.Time) bool {
	st := p.touch(key, rule, now)
	if st.tokens < 1 {
		return false
	}
	st.tokens--
	return true
}

type pool struct {
	max   int
	items map[string]*state
	order []string
}

func newPool(max int) *pool {
	return &pool{max: max, items: map[string]*state{}}
}

func (p *pool) touch(key string, rule Rule, now time.Time) *state {
	if st, ok := p.items[key]; ok {
		p.promote(key)
		elapsed := now.Sub(st.updated).Seconds()
		if elapsed > 0 {
			st.tokens += elapsed * rule.RefillPerSec
			if st.tokens > rule.Capacity {
				st.tokens = rule.Capacity
			}
			st.updated = now
		}
		return st
	}
	if len(p.items) >= p.max && len(p.order) > 0 {
		old := p.order[0]
		p.order = p.order[1:]
		delete(p.items, old)
	}
	st := &state{tokens: rule.Capacity, updated: now}
	p.items[key] = st
	p.order = append(p.order, key)
	return st
}

func (p *pool) promote(key string) {
	for i, k := range p.order {
		if k == key {
			p.order = append(p.order[:i], p.order[i+1:]...)
			p.order = append(p.order, key)
			return
		}
	}
}
