package models

// SIPStruct holds response properties
type SIPStruct struct {
	Method   string
	Username string
	Realm    string
	URI      string
	Nonce    string
	Response string
}
