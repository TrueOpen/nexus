package taskdata

import (
	"testing"

	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
)

// auth.rpc_method enters the request signature byte for byte and Cortex signs with the
// real Connect path; once a method name here drifts from the rpc name in ingress.proto,
// every such request is rejected as a request binding failure (MethodUpload once lingered
// on the old name UploadTaskResultData). Pins the six methods to the generated code.
func TestRequestMethodsMatchConnectProcedures(t *testing.T) {
	for method, procedure := range map[RequestMethod]string{
		MethodGetMetadata:      nexusv1connect.IngressAPIGetTaskDataMetadataProcedure,
		MethodFetch:            nexusv1connect.IngressAPIFetchTaskDataProcedure,
		MethodUpload:           nexusv1connect.IngressAPIUploadTaskResultObjectProcedure,
		MethodUploadStream:     nexusv1connect.IngressAPIUploadTaskOutputStreamProcedure,
		MethodFinalizeResult:   nexusv1connect.IngressAPIFinalizeTaskResultProcedure,
		MethodFinalizeVerifier: nexusv1connect.IngressAPIFinalizeVerifierEvidenceProcedure,
	} {
		if got := rpcMethodPath(method); got != procedure {
			t.Errorf("rpcMethodPath(%q) = %q, want Connect procedure %q", method, got, procedure)
		}
	}
}
