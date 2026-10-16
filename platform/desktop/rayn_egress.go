package main

import "C"

import (
	"encoding/json"

	hcore "github.com/hiddify/hiddify-core/v2/hcore"
)

// raynEgressRouting returns hcore.EgressRouting as JSON, for the desktop app's
// "IP routing is on" warning. The caller frees the string with freeString,
// which releases it with the same C runtime that allocated it.
//
// An export rather than a gRPC method so the app needs no proto regeneration.
// Its own file so upstream changes to this package never conflict with it.
// Outside Windows the JSON reports "checked": false.
//
//export raynEgressRouting
func raynEgressRouting() *C.char {
	payload, err := json.Marshal(hcore.EgressRouting())
	if err != nil {
		payload = []byte(`{"checked":false}`)
	}
	return C.CString(string(payload))
}
