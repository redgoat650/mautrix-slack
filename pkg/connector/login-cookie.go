// mautrix-slack - A Matrix-Slack puppeting bridge.
// Copyright (C) 2024 Tulir Asokan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package connector

import (
	"context"
	"fmt"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/event"

	"go.mau.fi/mautrix-slack/pkg/slackid"
)

const (
	LoginFlowIDAuthToken          = "token"
	LoginFlowIDAuthTokenEphemeral = "token-forget"
	LoginStepIDAuthToken          = "fi.mau.slack.login.enter_auth_token"
	LoginStepIDComplete           = "fi.mau.slack.login.complete"
	EphemeralTokenValueV0         = "ephemeral"
)

func (s *SlackConnector) GetLoginFlows() []bridgev2.LoginFlow {
	return []bridgev2.LoginFlow{
		{
			Name:        "Auth token & cookie",
			Description: "Log in with an auth token (and a cookie, if the token is from a browser)",
			ID:          LoginFlowIDAuthToken,
		},
		{
			Name:        "Slack app",
			Description: "Log in with a Slack app",
			ID:          LoginFlowIDApp,
		},
		{
			Name:        "Auth token & cookie (non-persisted)",
			Description: `We won't store your login token on the server, but you'll need to login again on evey server reboot. This bot will notify you when it needs help loggnig in again.`,
			ID:          LoginFlowIDAuthTokenEphemeral,
		},
	}
}

func (s *SlackConnector) CreateLogin(ctx context.Context, user *bridgev2.User, flowID string) (bridgev2.LoginProcess, error) {
	switch flowID {
	case LoginFlowIDAuthToken:
		return &SlackTokenLogin{
			User: user,
		}, nil
	case LoginFlowIDApp:
		return &SlackAppLogin{
			User: user,
		}, nil
	case LoginFlowIDAuthTokenEphemeral:
		return &SlackTokenLogin{
			User:      user,
			Ephemeral: true,
		}, nil
	default:
		return nil, fmt.Errorf("unknown login flow %s", flowID)
	}
}

type SlackTokenLogin struct {
	User      *bridgev2.User
	Ephemeral bool
}

var _ bridgev2.LoginProcessCookies = (*SlackTokenLogin)(nil)

const ExtractSlackTokenJS = `
new Promise(resolve => {
	let mautrixSlackTokenCheckInterval
	let useSlackInBrowserClicked = false
	function mautrixFindSlackToken() {
		// Automatically click the "Use Slack in Browser" button
		if (/\.slack\.com$/.test(window.location.host)) {
			const link = document?.querySelector?.(".p-ssb_redirect__body")?.querySelector?.(".c-link")
			if (link && !useSlackInBrowserClicked) {
				location.href = link.getAttribute("href")
				useSlackInBrowserClicked = true
			}
		}
		if (!localStorage.localConfig_v2?.includes("xoxc-")) {
			return
		}
		const auth_token = Object.values(JSON.parse(localStorage.localConfig_v2).teams)[0].token
		window.clearInterval(mautrixSlackTokenCheckInterval)
		resolve({ auth_token })
	}
	mautrixSlackTokenCheckInterval = window.setInterval(mautrixFindSlackToken, 1000)
})
`

func (s *SlackTokenLogin) Start(ctx context.Context) (*bridgev2.LoginStep, error) {
	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeCookies,
		StepID:       LoginStepIDAuthToken,
		Instructions: "Enter a JSON object with your auth token and cookie token, or a cURL command copied from browser devtools.\n\nFor example: `{\"auth_token\":\"xoxc-...\",\"cookie_token\":\"xoxd-...\"}`",
		CookiesParams: &bridgev2.LoginCookiesParams{
			URL:       "https://slack.com/signin",
			UserAgent: "",
			Fields: []bridgev2.LoginCookieField{{
				ID:       "auth_token",
				Required: true,
				Sources: []bridgev2.LoginCookieFieldSource{{
					Type: bridgev2.LoginCookieTypeSpecial,
					Name: "fi.mau.slack.auth_token",
				}, {
					Type:            bridgev2.LoginCookieTypeRequestBody,
					Name:            "token",
					RequestURLRegex: `^https://.+?\.slack\.com/api/(client|experiments|api|users|teams|conversations)\..+$`,
				}},
				Pattern: `^xoxc-.+$`,
			}, {
				ID:       "cookie_token",
				Required: true,
				Sources: []bridgev2.LoginCookieFieldSource{{
					Type:         bridgev2.LoginCookieTypeCookie,
					Name:         "d",
					CookieDomain: "slack.com",
				}},
				Pattern: `^xoxd-[a-zA-Z0-9/+=]+$`,
			}},
			ExtractJS: ExtractSlackTokenJS,
		},
	}, nil
}

func (s *SlackTokenLogin) Cancel() {}

func (s *SlackTokenLogin) SubmitCookies(ctx context.Context, input map[string]string) (*bridgev2.LoginStep, error) {
	token, cookieToken := input["auth_token"], input["cookie_token"]

	client := makeSlackClient(&s.User.Log, token, cookieToken, "")
	info, err := client.ClientBootContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("client.boot failed: %w", err)
	}

	loginID := slackid.MakeUserLoginID(info.Team.ID, info.Self.ID)

	successInstructions := fmt.Sprintf("Successfully logged into %s as %s", info.Team.Name, info.Self.Profile.Email)

	if s.Ephemeral {
		mt.Register(loginID, token, cookieToken)

		token = EphemeralTokenValueV0
		cookieToken = ""

		roomID, err := s.User.GetManagementRoom(ctx)
		if err != nil {
			return nil, err
		}

		instructions := `You chose to log in with ephemeral key storage. The server can't remember your Slack access tokens (so no one else can either).
If the server happens to reboot for whatever reason, you'll need to log in again to keep syncing Slack messages to your space.
<br/><br/>

When that happens, I, the bot, will DM you, asking for your token info for ` + info.Team.Name +
			` again.
<br/><br/>
Simply copy the following text into a message with me:
<br/><br/>

<details>
<summary><strong>Click here to reveal the ` + fmt.Sprintf("%s (%s)", info.Team.Name, loginID) + ` Slack reconnect message</strong> &#128072</summary>

<pre><code>` +
			fmt.Sprintf("login token-forget %s %s", input["auth_token"], input["cookie_token"]) +
			`</code></pre>
<br/><br/></details>`

		content := event.MessageEventContent{
			MsgType:       event.MsgText,
			Format:        event.FormatHTML,
			FormattedBody: instructions,
		}
		_, err = s.User.Bridge.Bot.SendMessage(ctx, roomID, event.EventMessage, &event.Content{
			Parsed: content,
		}, nil)
		if err != nil {
			return nil, err
		}
	}

	ul, err := s.User.NewLogin(ctx, &database.UserLogin{
		ID:         loginID,
		RemoteName: fmt.Sprintf("%s - %s", info.Team.Name, info.Self.Profile.Email),
		Metadata: &slackid.UserLoginMetadata{
			Email:       info.Self.Profile.Email,
			Token:       token,
			CookieToken: cookieToken,
		},
	}, &bridgev2.NewLoginParams{
		DeleteOnConflict:  true,
		DontReuseExisting: false,
	})
	if err != nil {
		return nil, err
	}
	sc := ul.Client.(*SlackClient)
	err = sc.connect(ul.Log.WithContext(context.Background()), info)
	if err != nil {
		return nil, fmt.Errorf("failed to connect after login: %w", err)
	}
	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeComplete,
		StepID:       LoginStepIDComplete,
		Instructions: successInstructions,
		CompleteParams: &bridgev2.LoginCompleteParams{
			UserLoginID: ul.ID,
			UserLogin:   ul,
		},
	}, nil
}
