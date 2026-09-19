// Package natsauth is the NATS auth-callout service (ADR-0016 decision three; Interface & Topic Catalogue §5.14):
// Cortex connects to NATS with its on-chain identity; this package checks its binding against the chain and issues a short-lived user JWT.
package natsauth

import "github.com/nats-io/jwt/v2"

// CortexPermissions is the subject permission set issued in Cortex user JWTs: the CORTEX row of Interface & Topic Catalogue §5.13,
// plus the three JetStream subject groups (stream name supplied by deployment; TRUEOPEN_TASK on devnet).
// allow only, no deny: the allow list is the entire authorization.
func CortexPermissions(jetStreamStream string) jwt.Permissions {
	return jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{
			"trueopen.handraise.worker.*", "trueopen.handraise.verifier.*", "trueopen.verify-result.*", "trueopen.output-avail.*",
			"$JS.API.CONSUMER.>", "$JS.API.STREAM.INFO." + jetStreamStream, "$JS.ACK." + jetStreamStream + ".>",
		}},
		Sub: jwt.Permission{Allow: jwt.StringList{
			"trueopen.task.open.*", "trueopen.verify.open.*", "trueopen.worker-assignment.*", "trueopen.verifier-assignment.*",
			"trueopen.output-avail.*", "_INBOX.>", "$JS.API.CONSUMER.>", "$JS.API.STREAM.INFO." + jetStreamStream,
		}},
	}
}
