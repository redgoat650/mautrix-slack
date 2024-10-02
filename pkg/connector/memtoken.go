package connector

import (
	"go.mau.fi/mautrix-slack/pkg/connector/internal/memtoken"
	"maunium.net/go/mautrix/bridgev2/networkid"
)

var mt = memtoken.MemToken{
	TokenData: make(map[networkid.UserLoginID]memtoken.TokenData),
}
