package memtoken

import (
	"sync"

	"maunium.net/go/mautrix/bridgev2/networkid"
)

type MemToken struct {
	mu        sync.RWMutex
	TokenData map[networkid.UserLoginID]TokenData
}

type TokenData struct {
	Token       string
	CookieToken string
}

func NewMemToken() *MemToken {
	return &MemToken{
		TokenData: make(map[networkid.UserLoginID]TokenData),
	}
}

func (mt *MemToken) Register(id networkid.UserLoginID, t, ct string) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	mt.TokenData[id] = TokenData{
		Token:       t,
		CookieToken: ct,
	}
}

func (mt *MemToken) Retrieve(id networkid.UserLoginID) (t, ct string, found bool) {
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	v, ok := mt.TokenData[id]
	if !ok {
		return "", "", false
	}

	return v.Token, v.CookieToken, true
}
