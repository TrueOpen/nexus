package main

import (
	"io"
	"testing"
	"time"
)

func TestParseOptionsUsesEnvironmentAndFlagOverrides(t *testing.T) {
	environment := map[string]string{
		"MOCK_CORTEX_NATS_SERVERS":  "nats://env-a:4222,nats://env-b:4222",
		"MOCK_CORTEX_NATS_USER":     "env-user",
		"MOCK_CORTEX_NATS_PASSWORD": "env-password",
	}
	getenv := func(key string) string { return environment[key] }

	options, err := parseOptions([]string{
		"--nats-servers", "nats://flag:4222",
		"--workers", "4",
		"--response-delay", "250ms",
		"--once",
	}, getenv, io.Discard)
	if err != nil {
		t.Fatalf("parse options: %v", err)
	}
	if len(options.NATSServers) != 1 || options.NATSServers[0] != "nats://flag:4222" {
		t.Fatalf("servers=%v", options.NATSServers)
	}
	if options.NATSUser != "env-user" || options.NATSPassword != "env-password" {
		t.Fatalf("credentials not loaded from environment: %+v", options)
	}
	if options.WorkerCount != 4 || options.ResponseDelay != 250*time.Millisecond || !options.Once {
		t.Fatalf("flag overrides not applied: %+v", options)
	}
}

func TestParseOptionsFallsBackToNexusNATSEnvironment(t *testing.T) {
	environment := map[string]string{
		"NEXUS_NATS_SERVERS":  "nats://nexus:4222",
		"NEXUS_NATS_USER":     "nexus-user",
		"NEXUS_NATS_PASSWORD": "nexus-password",
	}
	getenv := func(key string) string { return environment[key] }

	options, err := parseOptions(nil, getenv, io.Discard)
	if err != nil {
		t.Fatalf("parse options: %v", err)
	}
	if len(options.NATSServers) != 1 || options.NATSServers[0] != "nats://nexus:4222" ||
		options.NATSUser != "nexus-user" || options.NATSPassword != "nexus-password" {
		t.Fatalf("Nexus environment fallback not applied: %+v", options)
	}
}

func TestParseOptionsRejectsTooFewWorkers(t *testing.T) {
	_, err := parseOptions([]string{"--workers", "2"}, func(string) string { return "" }, io.Discard)
	if err == nil {
		t.Fatal("expected worker count error")
	}
}
