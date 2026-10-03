package taskdata

// A stored object's ref content_hash is the value this Builder checked the bytes against before
// storing them. In a plaintext task that value is the protocol commitment itself: the order's
// input_hash for the INPUT, the receipt's output_hash for the OUTPUT, and the receipt's typed
// commitment for a Worker evidence manifest. Every place that derives a ref content_hash from a
// commitment goes through the functions below, so the mapping is defined in one place.
//
// Encrypted tasks are not active. When they are, the Builder stores only ciphertext and these refs
// carry ciphertext values (the input ciphertext hash, the ciphertext output root, the manifest
// hash). Those cannot be derived from the plaintext commitment, so the signatures here will then
// take the task's payload mode and the ciphertext value as well (or one input carrying both); the
// callers of these functions are the list of sites to change.

// InputContentHash returns the content_hash of a task's INPUT object given the order's input_hash.
func InputContentHash(inputHash string) string { return inputHash }

// OutputContentHash returns the content_hash of a task's OUTPUT object given the receipt's
// output_hash.
func OutputContentHash(outputHash string) string { return outputHash }

// WorkerManifestContentHash returns the content_hash of a Worker evidence manifest given the
// receipt's commitment for that evidence kind.
func WorkerManifestContentHash(commitment EvidenceCommitment) string { return commitment.HashOrRoot }
