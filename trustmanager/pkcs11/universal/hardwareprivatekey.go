//+build pkcs11

package universal

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/theupdateframework/notary"
	"github.com/theupdateframework/notary/tuf/data"
	"github.com/theupdateframework/notary/tuf/signed"
)

const (
	SigAttempts = 5
)

type HardwarePrivateKey struct {
	data.ECDSAPublicKey
	passRetriever notary.PassRetriever
	slot          []byte
	libLoader     Pkcs11LibLoader
}

type hardwareSigner struct {
	HardwarePrivateKey
}

func NewHardwarePrivateKey(slot []byte, pubKey data.ECDSAPublicKey,
	passRetriever notary.PassRetriever) *HardwarePrivateKey {
	return &HardwarePrivateKey{
		ECDSAPublicKey: pubKey,
		passRetriever:  passRetriever,
		slot:           slot,
		libLoader:      DefaultLoader,
	}
}

func (ys *hardwareSigner) Public() crypto.PublicKey {
	publicKey, err := x509.ParsePKIXPublicKey(ys.HardwarePrivateKey.Public())
	if err != nil {
		return nil
	}

	return publicKey
}

func (y *HardwarePrivateKey) SetLibLoader(loader Pkcs11LibLoader) {
	y.libLoader = loader
}

func (y *HardwarePrivateKey) CryptoSigner() crypto.Signer {
	return &hardwareSigner{HardwarePrivateKey: *y}
}

func (y *HardwarePrivateKey) Private() []byte {
	return nil
}

func (y HardwarePrivateKey) SignatureAlgorithm() data.SigAlgorithm {
	return data.ECDSASignature
}

func (y *HardwarePrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx, session, err := hardwareKeyStore.SetupHSMEnv(y.libLoader)
	if err != nil {
		return nil, err
	}
	defer Cleanup(ctx, session)

	v := signed.Verifiers[data.ECDSASignature]
	for i := 0; i < SigAttempts; i++ {
		sig, err := hardwareKeyStore.Sign(ctx, session, y.slot, y.passRetriever, msg)
		if err != nil {
			return nil, fmt.Errorf("failed to sign using %s: %v", hardwareName, err)
		}
		if err := v.Verify(&y.ECDSAPublicKey, sig, msg); err == nil {
			return sig, nil
		}
	}
	return nil, errors.New(fmt.Sprintln("failed to generate signature on %s", hardwareName))
}
