package chaincli

import (
	"regexp"
	"strings"
)

var (
	urlLikeRe      = regexp.MustCompile(`(?i)\b(?:https?|wss?|tcp|grpc)://[^\s"']+`)
	ipv4EndpointRe = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b`)
	ipv6EndpointRe = regexp.MustCompile(`\[[0-9a-fA-F:]+\](?::\d+)?`)
	hostPortRe     = regexp.MustCompile(`(?i)\b(?:[a-z0-9-]+\.)*[a-z0-9-]+:\d+\b`)
)

func configuredLabel(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unset"
	}
	return "configured"
}

func redactSensitiveText(value string) string {
	value = urlLikeRe.ReplaceAllString(value, "<redacted-endpoint>")
	value = ipv4EndpointRe.ReplaceAllString(value, "<redacted-endpoint>")
	value = ipv6EndpointRe.ReplaceAllString(value, "<redacted-endpoint>")
	value = hostPortRe.ReplaceAllString(value, "<redacted-endpoint>")
	return value
}
