// +build pkcs11

package opencryptoki

import (
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/notary/passphrase"
	"github.com/theupdateframework/notary/trustmanager"
	"github.com/theupdateframework/notary/trustmanager/pkcs11/universal"
	"github.com/theupdateframework/notary/tuf/data"
	"github.com/theupdateframework/notary/tuf/utils"
)

var (
	ret          = passphrase.ConstantRetriever("passphrase")
	testSlot     = uint(3)
	testNumSlots = 10
)

// create a new store for clearing out keys, because we don't want to pollute
// any cache
func init() {
	SetSlot(testSlot)
	universal.SetKeyStore(NewKeyStore())
}

func clearAllKeys(t *testing.T) {
	store, _ := universal.NewHardwareStore(trustmanager.NewKeyMemoryStore(ret), ret)

	for k := range store.ListKeys() {
		err := store.RemoveKey(k)
		require.NoError(t, err)
	}
}

func testAddKey(t *testing.T, store trustmanager.KeyStore) (data.PrivateKey, error) {
	privKey, err := utils.GenerateECDSAKey(rand.Reader)
	require.NoError(t, err)

	err = store.AddKey(trustmanager.KeyInfo{Role: data.CanonicalRootRole, Gun: ""}, privKey)
	return privKey, err
}

func addMaxKeys(t *testing.T, store trustmanager.KeyStore) []string {
	var keys []string
	// create the maximum number of keys
	for i := 0; i < testNumSlots; i++ {
		privKey, err := testAddKey(t, store)
		require.NoError(t, err)
		keys = append(keys, privKey.ID())
	}
	return keys
}

// We can add keys enough times to fill up all the slots in the Yubikey.
// They are backed up, and we can then list them and get the keys.
func TestYubiAddKeysAndRetrieve(t *testing.T) {

	if !universal.IsAccessible() {
		t.Skip("Must have Opencryptoki access.")
	}

	clearAllKeys(t)

	SetSlot(testSlot)

	// create 4 keys on the original store
	backup := trustmanager.NewKeyMemoryStore(ret)
	store, err := universal.NewHardwareStore(backup, ret)
	require.NoError(t, err)
	keys := addMaxKeys(t, store)

	// create a new store, since we want to be sure the original store's cache
	// is not masking any issues
	cleanStore, err := universal.NewHardwareStore(trustmanager.NewKeyMemoryStore(ret), ret)
	require.NoError(t, err)

	// All 4 keys should be in the original store, in the clean store (which
	// makes sure the keys are actually on the Yubikey and not on the original
	// store's cache, and on the backup store)
	for _, store := range []trustmanager.KeyStore{store, cleanStore, backup} {
		listedKeys := store.ListKeys()
		require.Len(t, listedKeys, testNumSlots)
		for _, k := range keys {
			r, ok := listedKeys[k]
			require.True(t, ok)
			require.Equal(t, data.CanonicalRootRole, r.Role)

			_, _, err := store.GetKey(k)
			require.NoError(t, err)
		}
	}
}

// Test that we can successfully keys enough times to fill up all the slots in the Yubikey, even without a backup store
func TestYubiAddKeysWithoutBackup(t *testing.T) {
	if !universal.IsAccessible() {
		t.Skip("Must have Opencryptoki access.")
	}
	clearAllKeys(t)

	SetSlot(testSlot)

	// create 4 keys on the original store
	store, err := universal.NewHardwareStore(nil, ret)
	require.NoError(t, err)
	keys := addMaxKeys(t, store)

	// create a new store, since we want to be sure the original store's cache
	// is not masking any issues
	cleanStore, err := universal.NewHardwareStore(trustmanager.NewKeyMemoryStore(ret), ret)
	require.NoError(t, err)

	// All 4 keys should be in the original store, in the clean store (which
	// makes sure the keys are actually on the Yubikey and not on the original
	// store's cache)
	for _, store := range []trustmanager.KeyStore{store, cleanStore} {
		listedKeys := store.ListKeys()
		require.Len(t, listedKeys, testNumSlots)
		for _, k := range keys {
			r, ok := listedKeys[k]
			require.True(t, ok)
			require.Equal(t, data.CanonicalRootRole, r.Role)

			_, _, err := store.GetKey(k)
			require.NoError(t, err)
		}
	}
}

// If some random key in the middle was removed, adding a key will work (keys
// do not have to be deleted/added in order)
func TestYubiAddKeyCanAddToMiddleSlot(t *testing.T) {
	if !universal.IsAccessible() {
		t.Skip("Must have Opencryptoki access.")
	}
	clearAllKeys(t)
	SetSlot(testSlot)

	// create 4 keys on the original store
	backup := trustmanager.NewKeyMemoryStore(ret)
	store, err := universal.NewHardwareStore(backup, ret)
	require.NoError(t, err)
	keys := addMaxKeys(t, store)

	// delete one of the middle keys, and assert we can still create a new key
	keyIDToDelete := keys[testNumSlots/2]
	err = store.RemoveKey(keyIDToDelete)
	require.NoError(t, err)

	newKey, err := testAddKey(t, store)
	require.NoError(t, err)

	// create a new store, since we want to be sure the original store's cache
	// is not masking any issues
	cleanStore, err := universal.NewHardwareStore(trustmanager.NewKeyMemoryStore(ret), ret)
	require.NoError(t, err)

	// The new key should be in the original store, in the new clean store, and
	// in the backup store.  The old key should not be in the original store,
	// or the new clean store.
	for _, store := range []trustmanager.KeyStore{store, cleanStore, backup} {
		// new key should appear in all stores
		gottenKey, _, err := store.GetKey(newKey.ID())
		require.NoError(t, err)
		require.Equal(t, gottenKey.ID(), newKey.ID())

		listedKeys := store.ListKeys()
		_, ok := listedKeys[newKey.ID()]
		require.True(t, ok)

		// old key should not be in the non-backup stores
		if store != backup {
			_, _, err := store.GetKey(keyIDToDelete)
			require.Error(t, err)
			_, ok = listedKeys[keyIDToDelete]
			require.False(t, ok)
		}
	}
}

type nonworkingBackup struct {
	trustmanager.GenericKeyStore
}

// AddKey stores the contents of a PEM-encoded private key as a PEM block
func (s *nonworkingBackup) AddKey(keyInfo trustmanager.KeyInfo, privKey data.PrivateKey) error {
	return errors.New("nope")
}

// If, when adding a key to the Yubikey, we can't back up the key, it should
// be removed from the Yubikey too because otherwise there is no way for
// the user to later get a backup of the key.
func TestYubiAddKeyRollsBackIfCannotBackup(t *testing.T) {
	if !universal.IsAccessible() {
		t.Skip("Must have Opencryptoki access.")
	}
	clearAllKeys(t)

	SetSlot(testSlot)

	backup := &nonworkingBackup{
		GenericKeyStore: *trustmanager.NewKeyMemoryStore(ret),
	}
	store, err := universal.NewHardwareStore(backup, ret)
	require.NoError(t, err)

	_, err = testAddKey(t, store)
	require.Error(t, err)
	require.IsType(t, universal.ErrBackupFailed{}, err)

	// there should be no keys on the yubikey
	require.Len(t, cleanListKeys(t), 0)
}

// If, when adding a key to the Yubikey, and it already exists, we succeed
// without adding it to the backup store.
func TestYubiAddDuplicateKeySucceedsButDoesNotBackup(t *testing.T) {
	if !universal.IsAccessible() {
		t.Skip("Must have Opencryptoki access.")
	}
	clearAllKeys(t)

	SetSlot(testSlot)

	origStore, err := universal.NewHardwareStore(trustmanager.NewKeyMemoryStore(ret), ret)
	require.NoError(t, err)

	key, err := testAddKey(t, origStore)
	require.NoError(t, err)

	backup := trustmanager.NewKeyMemoryStore(ret)
	cleanStore, err := universal.NewHardwareStore(backup, ret)
	require.NoError(t, err)
	require.Len(t, cleanStore.ListKeys(), 1)

	err = cleanStore.AddKey(trustmanager.KeyInfo{Role: data.CanonicalRootRole, Gun: ""}, key)
	require.NoError(t, err)

	// there should be just 1 key on the yubikey
	require.Len(t, cleanListKeys(t), 1)
	// nothing was added to the backup
	require.Len(t, backup.ListKeys(), 0)
}

// RemoveKey removes a key from the yubikey, but not from the backup store.
func TestYubiRemoveKey(t *testing.T) {
	if !universal.IsAccessible() {
		t.Skip("Must have Opencryptoki access.")
	}
	clearAllKeys(t)

	SetSlot(testSlot)

	backup := trustmanager.NewKeyMemoryStore(ret)
	store, err := universal.NewHardwareStore(backup, ret)
	require.NoError(t, err)

	key, err := testAddKey(t, store)
	require.NoError(t, err)
	err = store.RemoveKey(key.ID())
	require.NoError(t, err)

	// key remains in the backup store
	backupKey, role, err := backup.GetKey(key.ID())
	require.NoError(t, err)
	require.Equal(t, data.CanonicalRootRole, role)
	require.Equal(t, key.ID(), backupKey.ID())

	// create a new store, since we want to be sure the original store's cache
	// is not masking any issues
	cleanStore, err := universal.NewHardwareStore(trustmanager.NewKeyMemoryStore(ret), ret)
	require.NoError(t, err)

	// key is not in either the original store or the clean store
	for _, store := range []*universal.HardwareStore{store, cleanStore} {
		_, _, err := store.GetKey(key.ID())
		require.Error(t, err)
	}
}

// If there are keys in the backup store but no keys in the Yubikey,
// listing and getting cannot access the keys in the backup store
func TestYubiListAndGetKeysIgnoresBackup(t *testing.T) {
	if !universal.IsAccessible() {
		t.Skip("Must have Opencryptoki access.")
	}
	clearAllKeys(t)

	SetSlot(testSlot)

	backup := trustmanager.NewKeyMemoryStore(ret)
	key, err := testAddKey(t, backup)
	require.NoError(t, err)

	store, err := universal.NewHardwareStore(trustmanager.NewKeyMemoryStore(ret), ret)
	require.NoError(t, err)
	require.Len(t, store.ListKeys(), 0)
	_, _, err = store.GetKey(key.ID())
	require.Error(t, err)
}

// Get a YubiPrivateKey.  Check that it has the right algorithm, etc, and
// specifically that you cannot get the private bytes out.  Assume we can
// sign something.
func TestYubiKeyAndSign(t *testing.T) {
	if !universal.IsAccessible() {
		t.Skip("Must have Opencryptoki access.")
	}
	clearAllKeys(t)

	SetSlot(testSlot)

	store, err := universal.NewHardwareStore(trustmanager.NewKeyMemoryStore(ret), ret)
	require.NoError(t, err)

	ecdsaPrivateKey, err := testAddKey(t, store)
	require.NoError(t, err)

	yubiPrivateKey, _, err := store.GetKey(ecdsaPrivateKey.ID())
	require.NoError(t, err)

	require.Equal(t, data.ECDSAKey, yubiPrivateKey.Algorithm())
	require.Equal(t, data.ECDSASignature, yubiPrivateKey.SignatureAlgorithm())
	require.Equal(t, ecdsaPrivateKey.Public(), yubiPrivateKey.Public())
	require.Nil(t, yubiPrivateKey.Private())

	// The signature should be verified, but the importing the verifiers causes
	// an import cycle.  A bigger refactor needs to be done to fix it.
	msg := []byte("Hello there")
	_, err = yubiPrivateKey.Sign(rand.Reader, msg, nil)
	require.NoError(t, err)
}

// ----- Negative tests that use stubbed pkcs11 for error injection -----

type pkcs11Stubbable interface {
	SetLibLoader(universal.Pkcs11LibLoader)
}

var setupErrors = []string{"Initialize", "GetSlotList", "OpenSession"}

// Create a new store, so that we avoid any cache issues, and list keys
func cleanListKeys(t *testing.T) map[string]trustmanager.KeyInfo {
	cleanStore, err := universal.NewHardwareStore(trustmanager.NewKeyMemoryStore(ret), ret)
	require.NoError(t, err)
	return cleanStore.ListKeys()
}

// If an error occurs during login, which only some functions do, the function
// under test will clean up after itself
func testYubiFunctionCleansUpOnLoginError(t *testing.T, toStub pkcs11Stubbable,

	functionUnderTest func() error) {
	toStub.SetLibLoader(func(string) universal.IPKCS11Ctx {
		return NewStubCtx(map[string]bool{"Login": true})
	})

	err := functionUnderTest()
	require.Error(t, err)
	// a lot of these functions wrap other errors
	require.Contains(t, err.Error(), trustmanager.ErrAttemptsExceeded{}.Error())

	// Set Up another time, to ensure we weren't left in a bad state
	// by the previous runs

	store := NewKeyStore()
	ctx, session, err := store.SetupHSMEnv(universal.DefaultLoader)
	require.NoError(t, err)
	universal.Cleanup(ctx, session)
}

// If one of the specified pkcs11 functions errors, the function under test
// will clean up after itself
func testYubiFunctionCleansUpOnSpecifiedErrors(t *testing.T,

	toStub pkcs11Stubbable, functionUnderTest func() error,
	dependentFunctions []string, functionShouldError bool) {
	for _, methodName := range dependentFunctions {

		toStub.SetLibLoader(func(string) universal.IPKCS11Ctx {
			return NewStubCtx(
				map[string]bool{methodName: true})
		})

		err := functionUnderTest()
		if functionShouldError {
			require.Error(t, err,
				fmt.Sprintf("Didn't error when %s errored.", methodName))
			// a lot of these functions wrap other errors
		} else {
			require.NoError(t, err)
		}
	}

	// Set Up another time, to ensure we weren't left in a bad state
	// by the previous runs
	store := NewKeyStore()
	ctx, session, err := store.SetupHSMEnv(universal.DefaultLoader)
	require.NoError(t, err)
	universal.Cleanup(ctx, session)
}

func TestYubiAddKeyCleansUpOnError(t *testing.T) {
	if !universal.IsAccessible() {
		t.Skip("Must have Opencryptoki access.")
	}
	clearAllKeys(t)

	SetSlot(testSlot)

	backup := trustmanager.NewKeyMemoryStore(ret)
	store, err := universal.NewHardwareStore(backup, ret)
	require.NoError(t, err)

	var _addkey = func() error {
		_, err := testAddKey(t, store)
		return err
	}

	testYubiFunctionCleansUpOnLoginError(t, store, _addkey)
	// all the PKCS11 functions AddKey depends on that aren't the login/logout
	testYubiFunctionCleansUpOnSpecifiedErrors(t, store, _addkey,
		append(
			setupErrors,
			"FindObjectsInit",
			"FindObjects",
			"FindObjectsFinal",
			"CreateObject",
		), true)

	// given that everything should have errored, there should be no keys on
	// the yubikey and no keys in backup
	require.Len(t, backup.ListKeys(), 0)
	require.Len(t, cleanListKeys(t), 0)

	// Logout should not cause a function failure - it s a universal.Cleanup failure,
	// which shouldn't break anything, and it should clean up after itself.
	// The key should be added to both stores
	testYubiFunctionCleansUpOnSpecifiedErrors(t, store, _addkey,
		[]string{"Logout"}, false)

	listedKeys := cleanListKeys(t)
	require.Len(t, backup.ListKeys(), 1)
	require.Len(t, listedKeys, 1)

	// Currently, if GetAttributeValue fails, the function succeeds, because if
	// we can't get the attribute value of an object, we don't know what slot
	// it's in, we assume its occupied slot is free (hence this failure will
	// cause the previous key to be overwritten).  This behavior may need to
	// be revisited.
	testYubiFunctionCleansUpOnSpecifiedErrors(t, store, _addkey,
		[]string{"GetAttributeValue"}, false)

}

func TestYubiGetKeyCleansUpOnError(t *testing.T) {
	if !universal.IsAccessible() {
		t.Skip("Must have Opencryptoki access.")
	}
	clearAllKeys(t)

	SetSlot(testSlot)

	store, err := universal.NewHardwareStore(trustmanager.NewKeyMemoryStore(ret), ret)
	require.NoError(t, err)
	key, err := testAddKey(t, store)
	require.NoError(t, err)

	var _getkey = func() error {
		_, _, err := store.GetKey(key.ID())
		return err
	}

	// all the PKCS11 functions GetKey depends on
	testYubiFunctionCleansUpOnSpecifiedErrors(t, store, _getkey,
		append(
			setupErrors,
			"FindObjectsInit",
			"FindObjects",
			"FindObjectsFinal",
			"GetAttributeValue",
		), true)
}

func TestYubiRemoveKeyCleansUpOnError(t *testing.T) {
	if !universal.IsAccessible() {
		t.Skip("Must have Opencryptoki access.")
	}
	clearAllKeys(t)

	SetSlot(testSlot)

	store, err := universal.NewHardwareStore(trustmanager.NewKeyMemoryStore(ret), ret)
	require.NoError(t, err)
	key, err := testAddKey(t, store)
	require.NoError(t, err)

	var _removekey = func() error { return store.RemoveKey(key.ID()) }

	testYubiFunctionCleansUpOnLoginError(t, store, _removekey)
	// RemoveKey just succeeds if we can't set up the yubikey
	testYubiFunctionCleansUpOnSpecifiedErrors(t, store, _removekey, setupErrors, false)
	// all the PKCS11 functions RemoveKey depends on that aren't the login/logout
	// or setup/universal.Cleanup
	testYubiFunctionCleansUpOnSpecifiedErrors(t, store, _removekey,
		[]string{
			"FindObjectsInit",
			"FindObjects",
			"FindObjectsFinal",
			"DestroyObject",
		}, true)

	// given that everything should have errored, there should still be 1 key
	// on the yubikey
	require.Len(t, cleanListKeys(t), 1)

	// this will not fail, but it should clean up after itself, and the key
	// should be added to both stores
	testYubiFunctionCleansUpOnSpecifiedErrors(t, store, _removekey,
		[]string{"Logout"}, false)

	require.Len(t, cleanListKeys(t), 0)
}

func TestYubiListKeyCleansUpOnError(t *testing.T) {
	if !universal.IsAccessible() {
		t.Skip("Must have Opencryptoki access.")
	}
	clearAllKeys(t)

	SetSlot(testSlot)

	// Do not call universal.NewHardwareStore, because it list keys immediately to
	// build the cache.

	store := &universal.HardwareStore{
		PassRetriever: ret,
		Keys:          make(map[string]universal.HardwareSlot),
		BackupStore:   trustmanager.NewKeyMemoryStore(ret),
		LibLoader:     universal.DefaultLoader,
	}

	var _listkeys = func() error {
		// ListKeys never fails
		store.ListKeys()
		return nil
	}

	// all the PKCS11 functions ListKey depends on - list keys never errors
	testYubiFunctionCleansUpOnSpecifiedErrors(t, store, _listkeys,
		append(
			setupErrors,
			"FindObjectsInit",
			"FindObjects",
			"FindObjectsFinal",
			"GetAttributeValue",
		), false)
}

func TestYubiSignCleansUpOnError(t *testing.T) {
	if !universal.IsAccessible() {
		t.Skip("Must have Opencryptoki access.")
	}
	clearAllKeys(t)

	SetSlot(testSlot)

	store, err := universal.NewHardwareStore(trustmanager.NewKeyMemoryStore(ret), ret)
	require.NoError(t, err)

	key, err := testAddKey(t, store)
	require.NoError(t, err)

	privKey, _, err := store.GetKey(key.ID())
	require.NoError(t, err)

	yubiPrivateKey, ok := privKey.(*universal.HardwarePrivateKey)
	require.True(t, ok)

	var _sign = func() error {
		_, err = yubiPrivateKey.Sign(rand.Reader, []byte("Hello there"), nil)
		return err
	}

	testYubiFunctionCleansUpOnLoginError(t, yubiPrivateKey, _sign)
	// all the PKCS11 functions SignKey depends on that is not login/logout
	testYubiFunctionCleansUpOnSpecifiedErrors(t, yubiPrivateKey, _sign,
		append(
			setupErrors,
			"FindObjectsInit",
			"FindObjects",
			"FindObjectsFinal",
			"SignInit",
			"Sign",
		), true)
	// this will not fail, but it should clean up after itself, and the key
	// should be added to both stores
	testYubiFunctionCleansUpOnSpecifiedErrors(t, yubiPrivateKey, _sign,
		[]string{"Logout"}, false)
}

// If Sign gives us an invalid signature, we retry until successful up to
// a maximum of 5 times.
func TestYubiRetrySignUntilSuccess(t *testing.T) {
	if !universal.IsAccessible() {
		t.Skip("Must have Opencryptoki access.")
	}
	clearAllKeys(t)

	SetSlot(testSlot)

	store, err := universal.NewHardwareStore(trustmanager.NewKeyMemoryStore(ret), ret)
	require.NoError(t, err)

	key, err := testAddKey(t, store)
	require.NoError(t, err)

	message := []byte("Hello there")
	goodSig, err := key.Sign(rand.Reader, message, nil)
	require.NoError(t, err)

	privKey, _, err := store.GetKey(key.ID())
	require.NoError(t, err)

	yubiPrivateKey, ok := privKey.(*universal.HardwarePrivateKey)
	require.True(t, ok)

	badSigner := &SignInvalidSigCtx{
		Ctx:     *pkcs11.New(pkcs11Lib),
		goodSig: goodSig,
		failNum: 2,
	}

	yubiPrivateKey.SetLibLoader(func(string) universal.IPKCS11Ctx { return badSigner })

	sig, err := yubiPrivateKey.Sign(rand.Reader, message, nil)
	require.NoError(t, err)
	// because the SignInvalidSigCtx returns the good signature, we can just
	// deep equal instead of verifying
	require.True(t, reflect.DeepEqual(goodSig, sig))
	require.Equal(t, 3, badSigner.signCalls)
}

// If Sign gives us an invalid signature, we retry until up to a maximum of 5
// times, and if it's still invalid, fail.
func TestYubiRetrySignUntilFail(t *testing.T) {
	if !universal.IsAccessible() {
		t.Skip("Must have Opencryptoki access.")
	}
	clearAllKeys(t)

	SetSlot(testSlot)

	store, err := universal.NewHardwareStore(trustmanager.NewKeyMemoryStore(ret), ret)
	require.NoError(t, err)

	key, err := testAddKey(t, store)
	require.NoError(t, err)

	message := []byte("Hello there")
	goodSig, err := key.Sign(rand.Reader, message, nil)
	require.NoError(t, err)

	privKey, _, err := store.GetKey(key.ID())
	require.NoError(t, err)

	yubiPrivateKey, ok := privKey.(*universal.HardwarePrivateKey)
	require.True(t, ok)

	badSigner := &SignInvalidSigCtx{
		Ctx:     *pkcs11.New(pkcs11Lib),
		goodSig: goodSig,
		failNum: universal.SigAttempts + 1,
	}

	yubiPrivateKey.SetLibLoader(func(string) universal.IPKCS11Ctx { return badSigner })

	_, err = yubiPrivateKey.Sign(rand.Reader, message, nil)
	require.Error(t, err)
	// because the SignInvalidSigCtx returns the good signature, we can just
	// deep equal instead of verifying
	require.Equal(t, universal.SigAttempts, badSigner.signCalls)
}

// -----  Stubbed pkcs11 for testing error conditions ------
// This is just a passthrough to the underlying pkcs11 library, with optional
// error injection.  This is to ensure that if errors occur during the process
// of interacting with the Yubikey, that everything gets cleaned up sanely.

// Note that this does not actually replicate an actual PKCS11 failure, since
// who knows what the pkcs11 function call may have done to the key before it
// errored. This just tests that we handle an error ok.

type errInjected struct {
	methodName string
}

func (e errInjected) Error() string {
	return fmt.Sprintf("Injected failure in %s", e.methodName)
}

const (
	uninitialized = 0
	initialized   = 1
	sessioned     = 2
	loggedin      = 3
)

type StubCtx struct {
	ctx                universal.IPKCS11Ctx
	functionShouldFail map[string]bool
}

func NewStubCtx(functionShouldFail map[string]bool) *StubCtx {
	realCtx := universal.DefaultLoader(pkcs11Lib)
	return &StubCtx{
		ctx:                realCtx,
		functionShouldFail: functionShouldFail,
	}
}

// Returns an error if we're supposed to error for this method
func (s *StubCtx) checkErr(methodName string) error {
	if val, ok := s.functionShouldFail[methodName]; ok && val {
		return errInjected{methodName: methodName}
	}
	return nil
}

func (s *StubCtx) Destroy() {
	// can't error
	s.ctx.Destroy()
}

func (s *StubCtx) Initialize() error {
	err := s.checkErr("Initialize")
	if err != nil {
		return err
	}
	return s.ctx.Initialize()
}

func (s *StubCtx) Finalize() error {
	err := s.checkErr("Finalize")
	if err != nil {
		return err
	}
	return s.ctx.Finalize()
}

func (s *StubCtx) GetSlotList(tokenPresent bool) ([]uint, error) {
	err := s.checkErr("GetSlotList")
	if err != nil {
		return nil, err
	}
	return s.ctx.GetSlotList(tokenPresent)
}
func (s *StubCtx) GetMechanismList(slotID uint) ([]*pkcs11.Mechanism, error) {
	err := s.checkErr("GetMechanismList")
	if err != nil {
		return nil, err
	}
	return s.ctx.GetMechanismList(slotID)
}
func (s *StubCtx) GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error) {
	err := s.checkErr("GetTokenList")
	if err != nil {
		return pkcs11.TokenInfo{}, err
	}
	return s.ctx.GetTokenInfo(slotID)
}
func (s *StubCtx) GetInfo() (pkcs11.Info, error) {
	err := s.checkErr("GetInfo")
	if err != nil {
		return pkcs11.Info{}, err
	}
	return s.ctx.GetInfo()
}

func (s *StubCtx) OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error) {
	err := s.checkErr("OpenSession")
	if err != nil {
		return pkcs11.SessionHandle(0), err
	}
	return s.ctx.OpenSession(slotID, flags)
}

func (s *StubCtx) CloseSession(sh pkcs11.SessionHandle) error {
	err := s.checkErr("CloseSession")
	if err != nil {
		return err
	}
	return s.ctx.CloseSession(sh)
}

func (s *StubCtx) Login(sh pkcs11.SessionHandle, userType uint, pin string) error {
	err := s.checkErr("Login")
	if err != nil {
		return err
	}
	return s.ctx.Login(sh, userType, pin)
}

func (s *StubCtx) Logout(sh pkcs11.SessionHandle) error {
	err := s.checkErr("Logout")
	if err != nil {
		return err
	}
	return s.ctx.Logout(sh)
}

func (s *StubCtx) CreateObject(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) (

	pkcs11.ObjectHandle, error) {
	err := s.checkErr("CreateObject")
	if err != nil {
		return pkcs11.ObjectHandle(0), err
	}
	return s.ctx.CreateObject(sh, temp)
}

func (s *StubCtx) DestroyObject(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) error {
	err := s.checkErr("DestroyObject")
	if err != nil {
		return err
	}
	return s.ctx.DestroyObject(sh, oh)
}

func (s *StubCtx) GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle,

	a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	err := s.checkErr("GetAttributeValue")
	if err != nil {
		return nil, err
	}
	return s.ctx.GetAttributeValue(sh, o, a)
}

func (s *StubCtx) FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error {
	err := s.checkErr("FindObjectsInit")
	if err != nil {
		return err
	}
	return s.ctx.FindObjectsInit(sh, temp)
}

func (s *StubCtx) FindObjects(sh pkcs11.SessionHandle, max int) (

	[]pkcs11.ObjectHandle, bool, error) {
	err := s.checkErr("FindObjects")
	if err != nil {
		return nil, false, err
	}
	return s.ctx.FindObjects(sh, max)
}

func (s *StubCtx) FindObjectsFinal(sh pkcs11.SessionHandle) error {
	err := s.checkErr("FindObjectsFinal")
	if err != nil {
		return err
	}
	return s.ctx.FindObjectsFinal(sh)
}

func (s *StubCtx) SignInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism,
	o pkcs11.ObjectHandle) error {
	err := s.checkErr("SignInit")
	if err != nil {
		return err
	}
	return s.ctx.SignInit(sh, m, o)
}

func (s *StubCtx) Sign(sh pkcs11.SessionHandle, message []byte) ([]byte, error) {
	// a call to Sign will clear SignInit whether or not it fails, so
	// replicate that by calling Sign, then optionally returning an error.
	sig, sigErr := s.ctx.Sign(sh, message)
	err := s.checkErr("Sign")
	if err != nil {
		return nil, err
	}
	return sig, sigErr
}

// a different stub Ctx object in which Sign returns an invalid signature some
// number of times
type SignInvalidSigCtx struct {
	pkcs11.Ctx

	// Signature verification is to mitigate against hardware failure while
	// signing - which might occur during testing. So to prevent spurious
	// errors, return a real known good signature in the success case.
	goodSig []byte

	failNum   int // number of calls to fail before succeeding
	signCalls int // number of calls to Sign so far
}

func (s *SignInvalidSigCtx) Sign(sh pkcs11.SessionHandle, message []byte) ([]byte, error) {
	s.signCalls++
	s.Ctx.Sign(sh, message) // clear out the SignInit

	if s.signCalls > s.failNum {
		return s.goodSig, nil
	}
	return []byte("12345"), nil
}
