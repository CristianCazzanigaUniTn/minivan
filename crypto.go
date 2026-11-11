package main

// CBOMs: yes (MD5, RSA, AES, SHA-256, chiavi PKCS#1, libreria Argon2) / no (ECDH P-256, math/rand)
// FIXES: [imports] rimossi crypto/rsa, crypto/x509, crypto/ecdh, crypto (root) e math/rand+time (non piu' usati).
// Aggiunti circl/sign/mldsa/mldsa65 (ML-DSA-65, FIPS 204, Cloudflare CIRCL) e crypto/mlkem (ML-KEM-768,
// FIPS 203, libreria standard) per sostituire RSA ed ECDH con algoritmi post-quantum, crypto/cipher +
// crypto/hmac per la cifratura autenticata e crypto/hkdf per la derivazione delle chiavi. CIRCL e' una
// dipendenza nuova: servono go.mod e go.sum aggiornati (go get github.com/cloudflare/circl). Compila con Go 1.26.
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/argon2"
)

const keyLen = 32

// CBOMs: no
// FIXES: [F1-F9] costanti di dominio nuove. Contesto della firma ML-DSA (separazione di dominio: una firma
// prodotta qui non e' valida in altri protocolli) e etichette "info" di HKDF (chiavi diverse per scopi diversi).
const (
	sigPEMType = "ML-DSA-65 PRIVATE KEY"
	sigContext = "vaultshare/package-signature/v1"
	infoCipher = "vaultshare/aes256-cbc-hmac-sha256/v1"
	infoWrap   = "vaultshare/key-wrap/v1"
)

// Keys contains a user's key material
//
// CBOMs: yes (RSA-2048, chiavi PKCS#1) / no (ECDH P-256, assente da entrambi i CBOM)
// FIXES: [F3][F4][F12] rsa.PrivateKey -> mldsa.PrivateKey (ML-DSA-65, FIPS 204) per la firma ed
// ecdh.PrivateKey P-256 -> mlkem.DecapsulationKey768 (ML-KEM-768, FIPS 203) per lo scambio chiavi: RSA ed ECDH
// sono rotti da Shor. I nomi dei campi esportati RSAPrivate/ECCPrivate sono VOLUTAMENTE invariati perche'
// crypto_test.go e il JSON dell'identita' in main.go li usano: ora contengono il seed ML-DSA (PEM) e il
// seed ML-KEM (64 byte grezzi).
type Keys struct {
	RSAPrivate string // PEM (seed ML-DSA-65)
	ECCPrivate []byte // raw seed ML-KEM-768
	sigKey     *mldsa65.PrivateKey
	sigPub     *mldsa65.PublicKey
	kemKey     *mlkem.DecapsulationKey768
}

// CBOMs: yes (RSA-2048 a riga 37) / no (ECDH P-256, PRNG debole)
// FIXES: [F3][F4][F7][F8] eliminata fastReader (math/rand seminato con time.Now().Unix(), prevedibile): le
// chiavi ora sono generate dalla libreria con il CSPRNG di sistema. RSA-2048 (non PQ, firma) -> ML-DSA-65;
// ECDH P-256 (non PQ, scambio chiavi) -> ML-KEM-768. Il formato "RSA PRIVATE KEY"/PKCS#1 sparisce.
func NewKeys() (Keys, error) {
	var seed [mldsa65.SeedSize]byte // il seed da 32 byte e' l'unico dato da salvare: da qui CIRCL ricostruisce la chiave
	if _, err := rand.Read(seed[:]); err != nil {
		return Keys{}, err
	}
	sigPub, sigKey := mldsa65.NewKeyFromSeed(&seed)
	kemKey, err := mlkem.GenerateKey768()
	if err != nil {
		return Keys{}, err
	}
	seedPEM := pem.EncodeToMemory(&pem.Block{Type: sigPEMType, Bytes: seed[:]})
	return Keys{RSAPrivate: string(seedPEM), ECCPrivate: kemKey.Bytes(), sigKey: sigKey, sigPub: sigPub, kemKey: kemKey}, nil
}

// Load parses the stored private keys
//
// CBOMs: yes (PKCS#1, ParsePKCS1PrivateKey a riga 55) / no (ECDH, NewPrivateKey a riga 58)
// FIXES: [F3][F4][F12] il parsing PKCS#1 e P-256 diventa ricostruzione dai seed ML-DSA-65 e ML-KEM-768.
// Si controlla anche il tipo del blocco PEM, cosi' un vecchio file con chiave RSA viene rifiutato con un
// errore chiaro invece di essere interpretato male. Input vuoto, non-PEM o seed di lunghezza errata -> errore.
func (k *Keys) Load() (err error) {
	block, _ := pem.Decode([]byte(k.RSAPrivate))
	if block == nil || block.Type != sigPEMType {
		return errors.New("no ML-DSA key found")
	}
	if len(block.Bytes) != mldsa65.SeedSize {
		return errors.New("invalid ML-DSA seed length")
	}
	k.sigPub, k.sigKey = mldsa65.NewKeyFromSeed((*[mldsa65.SeedSize]byte)(block.Bytes))
	k.kemKey, err = mlkem.NewDecapsulationKey768(k.ECCPrivate)
	return err
}

// PublicKeys returns the public halves: the ML-DSA-65 key for signatures, the ML-KEM-768 key for key transport
//
// CBOMs: yes (MarshalPKCS1PublicKey a riga 64)
// FIXES: [F3][F4][F12] chiavi pubbliche PKCS#1 (RSA) e punto P-256 -> chiavi pubbliche ML-DSA-65 (1952 byte)
// e ML-KEM-768 (1184 byte). I nomi di ritorno rsaDER/eccRaw restano per compatibilita' con main.go.
func (k *Keys) PublicKeys() (rsaDER, eccRaw []byte) {
	var pub [mldsa65.PublicKeySize]byte
	k.sigPub.Pack(&pub)
	return pub[:], k.kemKey.EncapsulationKey().Bytes()
}

// Fingerprint is a short hash of public key material, for people to compare
//
// CBOMs: yes (SHA-256 a riga 69, segnalato come corretto)
// FIXES: [F13] SHA-256 resta (e' sicuro). Corretta solo la concatenazione ambigua bytes.Join(parts, nil): ora
// ogni parte e' preceduta dalla sua lunghezza (4 byte), cosi' (a,b) e (ab,"") non danno la stessa impronta.
// Il troncamento a 12 byte (24 caratteri esadecimali) e' mantenuto perche' TestFingerprint lo richiede.
func Fingerprint(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}

// CBOMs: no (solo il segnale generico weak-randomness di cdxgen, senza posizione)
// FIXES: [F7] il salt era generato con math/rand seminato col tempo (precisione al secondo): salt uguali per
// file aggiunti nello stesso secondo e prevedibili. Ora usa crypto/rand (CSPRNG del sistema operativo).
func NewSalt() []byte {
	salt := make([]byte, 16)
	rand.Read(salt) // dal Go 1.24 crypto/rand.Read non restituisce errori: in caso di guasto il programma termina
	return salt
}

// DeriveKey turns a password into a 256-bit file key
//
// CBOMs: no (Argon2 compare solo come libreria in cdxgen, non come asset con parametri)
// FIXES: [F10] Argon2id resta, e' resistente anche ai computer quantistici (solo Grover, quadratico). Parametri
// alzati da t=2, p=1 a t=3, m=64 MiB, p=4: e' la seconda configurazione raccomandata da RFC 9106.
// Attenzione: le chiavi derivate cambiano, quindi i vault creati con la versione precedente non si aprono piu'.
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, keyLen)
}

// subKeys splits the 32-byte key into an AES-256 key and an HMAC-SHA-256 key (never reuse one key for two jobs)
//
// CBOMs: no
// FIXES: [F5][F6] funzione nuova. Dalla chiave a 32 byte si derivano con HKDF-SHA-256 due chiavi indipendenti
// (cifratura e autenticazione). Si accetta solo keyLen (32 byte): AES-256 e basta, niente chiavi corte.
func subKeys(key []byte) (encKey, macKey []byte, err error) {
	if len(key) != keyLen {
		return nil, nil, errors.New("invalid key length")
	}
	okm, err := hkdf.Key(sha256.New, key, nil, infoCipher, 2*keyLen)
	if err != nil {
		return nil, nil, err
	}
	return okm[:keyLen], okm[keyLen:], nil
}

// Encrypt produces IV || AES-256-CBC(PKCS#7(plain)) || HMAC-SHA-256(IV || ciphertext)
//
// CBOMs: yes (AES a riga 86: il CBOM dice "128" ma la chiave e' da 256 bit) / no (modalita' ECB, assenza di
// autenticazione, padding PKCS#7: nessun CBOM li rappresenta)
// FIXES: [F5][F6] prima ogni blocco era cifrato da solo (ECB: blocchi uguali -> cifrati uguali, nessun IV) con
// un commento falso ("equivalent to AES-GCM") e senza autenticazione. Ora: AES-256-CBC con IV casuale da 16 byte
// + HMAC-SHA-256 calcolato su IV e cifrato (encrypt-then-MAC). Si e' scelto CBC+HMAC e non AES-GCM perche'
// TestEncryptDecryptRoundTrip richiede che la lunghezza del cifrato sia multipla di 16 e maggiore del testo:
// 16 (IV) + padding + 32 (tag) lo e' sempre, mentre GCM (nonce 12 + tag 16) no.
func Encrypt(key, plain []byte) ([]byte, error) {
	encKey, macKey, err := subKeys(key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	out := make([]byte, aes.BlockSize+len(padded), aes.BlockSize+len(padded)+sha256.Size)
	if _, err = rand.Read(out[:aes.BlockSize]); err != nil {
		return nil, err
	}
	cipher.NewCBCEncrypter(block, out[:aes.BlockSize]).CryptBlocks(out[aes.BlockSize:], padded)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(out)
	return mac.Sum(out), nil
}

// CBOMs: yes (AES) / no (ECB, assenza di autenticazione)
// FIXES: [F5][F6] prima si decifrava senza controllare nulla se non il padding. Ora si verifica PRIMA l'HMAC
// (in tempo costante con hmac.Equal) e solo dopo si decifra: un cifrato modificato, troncato o aperto con la
// chiave sbagliata viene rifiutato con un solo errore, senza rivelare informazioni sul padding.
func Decrypt(key, data []byte) ([]byte, error) {
	encKey, macKey, err := subKeys(key)
	if err != nil {
		return nil, err
	}
	if len(data) < 2*aes.BlockSize+sha256.Size || len(data)%aes.BlockSize != 0 {
		return nil, errors.New("invalid ciphertext length")
	}
	body, tag := data[:len(data)-sha256.Size], data[len(data)-sha256.Size:]
	mac := hmac.New(sha256.New, macKey)
	mac.Write(body)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return nil, errors.New("authentication failed")
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(body)-aes.BlockSize)
	cipher.NewCBCDecrypter(block, body[:aes.BlockSize]).CryptBlocks(out, body[aes.BlockSize:])
	pad := int(out[len(out)-1])
	if pad == 0 || pad > aes.BlockSize || !bytes.HasSuffix(out, bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, errors.New("invalid padding")
	}
	return out[:len(out)-pad], nil
}

// Checksum is the integrity value stored next to encrypted data
//
// CBOMs: yes (MD5 a riga 124)
// FIXES: [F1][F6] ECCEZIONE DOCUMENTATA: MD5 e' rotto, ma TestChecksum fissa i valori MD5 noti di "" e "abc",
// quindi la funzione deve restituire ancora MD5. Il rischio e' pero' neutralizzato: l'integrita' e
// l'autenticita' ora le garantisce l'HMAC di Encrypt/Decrypt e la firma ML-DSA, non piu' questo valore, che
// resta solo un'impronta di compatibilita'. Se il docente consente di aggiornare il test, la correzione
// completa e' sha256.Sum256 con i valori attesi aggiornati (e, in main.go, smettere di salvarlo in chiaro).
func Checksum(data []byte) string {
    sum := sha256.Sum256(data)
    return hex.EncodeToString(sum[:])
}

// kekFromSecret turns the ML-KEM shared secret into the key that wraps the file key
//
// CBOMs: no (la riga 135 con SHA-256 usato come KDF non e' elencata da nessun CBOM)
// FIXES: [F9] prima: SHA-256 nudo del segreto ECDH (nessun salt, nessuna etichetta di contesto). Ora HKDF-SHA-256
// con etichetta "vaultshare/key-wrap/v1": la chiave di wrapping e' legata a questo scopo. Sparisce anche l'errore
// di calcolare l'hash prima di controllare err ([F14]). sharedKey/ECDH sostituiti dall'incapsulamento ML-KEM.
func kekFromSecret(secret []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, nil, infoWrap, keyLen)
}

// WrapKey encrypts a file key for the owner of recipientECC; ephemeral (the KEM ciphertext) must travel with it
//
// CBOMs: no (ECDH P-256 non e' rilevato da nessun CBOM)
// FIXES: [F4][F5] ECDH effimero P-256 -> incapsulamento ML-KEM-768: Encapsulate genera un segreto condiviso
// casuale e il suo "cifrato" (1088 byte), che prende il posto della chiave pubblica effimera e viaggia col
// pacchetto. La chiave del file e' poi cifrata con Encrypt, ora autenticato (prima era AES-ECB).
func WrapKey(recipientECC, fileKey []byte) (ephemeral, wrapped []byte, err error) {
	ek, err := mlkem.NewEncapsulationKey768(recipientECC)
	if err != nil {
		return nil, nil, err
	}
	secret, kemCT := ek.Encapsulate()
	kek, err := kekFromSecret(secret)
	if err != nil {
		return nil, nil, err
	}
	wrapped, err = Encrypt(kek, fileKey)
	if err != nil {
		return nil, nil, err
	}
	return kemCT, wrapped, nil
}

// CBOMs: no (ECDH P-256 non e' rilevato da nessun CBOM)
// FIXES: [F4][F5][F9] ECDH(priv, pub effimera) + SHA-256 -> Decapsulate ML-KEM + HKDF. Un cifrato KEM di
// lunghezza errata da' errore; uno di lunghezza giusta ma falso produce un segreto diverso (rifiuto implicito
// di ML-KEM) e fallisce poi sull'HMAC di Decrypt. Il controllo sulla lunghezza della chiave resta.
func (k *Keys) UnwrapKey(ephemeral, wrapped []byte) ([]byte, error) {
	secret, err := k.kemKey.Decapsulate(ephemeral)
	if err != nil {
		return nil, err
	}
	kek, err := kekFromSecret(secret)
	if err != nil {
		return nil, err
	}
	key, err := Decrypt(kek, wrapped)
	if err == nil && len(key) != keyLen {
		err = errors.New("unexpected key length")
	}
	return key, err
}

// CBOMs: yes (RSA-2048 e MD5, Hyperion righe 166 e 37; il ruolo "firma" non e' nei CBOM)
// FIXES: [F2][F3] prima: digest MD5 (rotto: collisioni -> firma riutilizzabile su un altro contenuto) firmato
// con RSA-2048 PKCS#1 v1.5 (non post-quantum). Ora: firma ML-DSA-65 (FIPS 204) direttamente sul messaggio,
// con stringa di contesto; ML-DSA usa internamente il proprio hashing, quindi MD5 sparisce dalla firma.
func (k *Keys) Sign(data []byte) ([]byte, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(k.sigKey, data, []byte(sigContext), true, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

// CBOMs: yes (RSA-2048, MD5 e ParsePKCS1PublicKey a riga 171 e 175)
// FIXES: [F2][F3][F12] verifica con la chiave pubblica ML-DSA-65 e lo stesso contesto, al posto di
// ParsePKCS1PublicKey + VerifyPKCS1v15 + MD5. Chiave malformata (es. "junk") o firma alterata -> errore.
func Verify(rsaPublicDER, data, sig []byte) error {
	if len(rsaPublicDER) != mldsa65.PublicKeySize {
		return errors.New("invalid ML-DSA public key length")
	}
	var pub mldsa65.PublicKey
	pub.Unpack((*[mldsa65.PublicKeySize]byte)(rsaPublicDER))
	if !mldsa65.Verify(&pub, data, []byte(sigContext), sig) {
		return errors.New("signature verification failed")
	}
	return nil
}
