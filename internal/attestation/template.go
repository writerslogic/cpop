package attestation

import _ "embed"

//go:embed template.json
var templateJSON []byte

// Template returns the embedded attestation template JSON.
func Template() []byte {
	return templateJSON
}
