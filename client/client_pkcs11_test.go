// +build pkcs11

package client

import (
	"github.com/theupdateframework/notary/trustmanager/pkcs11/universal"
	"github.com/theupdateframework/notary/trustmanager/pkcs11/yubikey"
)

// clear out all keys
func init() {
	yubikey.SetYubikeyKeyMode(0)
	ks := yubikey.NewKeyStore()
	universal.SetKeyStore(ks)
	if !universal.IsAccessible() {
		return
	}
	store, err := universal.NewHardwareStore(nil, nil)
	if err == nil {
		for k := range store.ListKeys() {
			store.RemoveKey(k)
		}
	}
}
