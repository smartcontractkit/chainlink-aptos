package internal

// MultiOCR3BaseOCRConfigArgsAptos holds OCR3 config args for Aptos offramp setup.
type MultiOCR3BaseOCRConfigArgsAptos struct {
	ConfigDigest                   [32]byte
	OcrPluginType                  uint8
	F                              uint8
	IsSignatureVerificationEnabled bool
	Signers                        [][]byte
	Transmitters                   [][]byte
}
