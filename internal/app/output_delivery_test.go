package app

import (
	"context"
	"reflect"
	"testing"
)

type recordingLifecycle struct {
	name   string
	events *[]string
}

func (l recordingLifecycle) Start(context.Context) error {
	*l.events = append(*l.events, "start:"+l.name)
	return nil
}

func (l recordingLifecycle) Stop(context.Context) error {
	*l.events = append(*l.events, "stop:"+l.name)
	return nil
}

func TestOutputDeliveryModuleOrder(t *testing.T) {
	var events []string
	modules := runtimeModules(
		recordingLifecycle{name: "task-data", events: &events},
		recordingLifecycle{name: "relay", events: &events},
		recordingLifecycle{name: "coordinator", events: &events},
		outputRecoveryLifecycle{
			lifecycle: recordingLifecycle{name: "output-delivery", events: &events},
			complete: func() error {
				events = append(events, "complete:output-recovery")
				return nil
			},
		},
		recordingLifecycle{name: "ingress", events: &events},
	)
	for _, module := range modules {
		if err := module.start(context.Background()); err != nil {
			t.Fatalf("start %s: %v", module.name, err)
		}
	}
	stopRuntimeModules(
		context.Background(),
		modules,
		func(context.Context) error {
			events = append(events, "begin:ingress")
			return nil
		},
		func(name string, err error) { t.Errorf("stop %s: %v", name, err) },
	)
	want := []string{
		"start:task-data", "start:relay", "start:coordinator", "start:output-delivery", "complete:output-recovery", "start:ingress",
		"begin:ingress", "stop:output-delivery", "stop:ingress", "stop:coordinator", "stop:relay", "stop:task-data",
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("lifecycle order = %v, want %v", events, want)
	}
}
