# Fix di `crypto.go`: spiegazione e confronto prima/dopo (versione con Cloudflare CIRCL)

Il file corretto è `crypto.go` (stessa cartella). Ogni modifica è marcata con `// CBOMs:` e `// FIXES:` come richiede il README. Gli ID `[F1]…[F14]` sono quelli di `Manual_analysis_crypto_go.md`.

## 0. Prima di compilare

1. **Dipendenza nuova.** La firma ML-DSA-65 usa `github.com/cloudflare/circl/sign/mldsa/mldsa65`. Nel progetto, con Go 1.26:
   ```bash
   go get github.com/cloudflare/circl@latest
   go mod tidy
   make test
   ```
   `go get` modifica `go.mod` e `go.sum`: **vanno inclusi nella zip** insieme a `crypto.go`, altrimenti chi corregge non riesce a compilare.
2. **Non ho compilato né eseguito i test**: li ho verificati a mano (sezione 1). I nomi delle funzioni CIRCL (`NewKeyFromSeed`, `Pack`, `Unpack`, `SignTo`, `Verify`) sono scritti dalla mia conoscenza dell'API: se `make test` dà un errore tipo `undefined: …`, incollamelo e si sistema con una modifica.
3. Non ho visto `main_test.go` né `go.mod`; ho mantenuto invariate tutte le firme pubbliche usate da `main.go`.

---

## 1. Vincoli dei test e come sono rispettati

| Test (`crypto_test.go`) | Cosa pretende | Come lo soddisfa il nuovo codice |
| --- | --- | --- |
| `TestEncryptDecryptRoundTrip` | round trip per 0, 1, 15, 16, 17, 100, 4096 byte; cifrato **multiplo di 16 e più lungo del testo** | cifrato = 16 (IV) + testo con padding (multiplo di 16, ≥16) + 32 (tag): sempre multiplo di 16 e > n |
| `TestEncryptRejectsBadKeyLength` | errore con chiave di 5 byte | `subKeys` rifiuta ogni chiave diversa da 32 byte |
| `TestDecryptRejectsMalformedInput` | errore con nil, vuoto, 15 e 17 byte | controllo `len >= 64 && len%16 == 0` |
| `TestDecryptWithWrongKey…` | con chiave sbagliata niente testo in chiaro | l'HMAC non coincide → errore |
| `TestDeriveKey` | 32 byte, deterministico, sensibile a password e salt | Argon2id invariato nella struttura |
| `TestNewSalt` | 16 byte | `crypto/rand` su 16 byte |
| `TestChecksum` | valori **MD5** noti di `""` e `"abc"` | `Checksum` resta MD5 (sezione 2b) |
| `TestFingerprint` | 24 caratteri esadecimali, stabile, input diversi → impronte diverse | troncamento a 12 byte mantenuto; aggiunte solo le lunghezze davanti a ogni parte |
| `TestKeysSurviveStoringAndLoading` | `Keys{RSAPrivate, ECCPrivate}` + `Load()` ricostruisce le stesse chiavi pubbliche | i campi mantengono nome e tipo; contengono i seed ML-DSA (32 byte, PEM) e ML-KEM (64 byte); la chiave ML-DSA ricavata dal seed è deterministica |
| `TestLoadRejectsBrokenKeys` | errore con chiavi vuote, `"hello"` non-PEM, ECC di 3 byte | PEM assente o di tipo sbagliato → errore; seed ML-DSA ≠ 32 byte → errore; `NewDecapsulationKey768` rifiuta seed ≠ 64 byte |
| `TestSignVerify` | firma valida; rifiutata se cambiano dati, un byte della firma, la chiave, o se la chiave pubblica è `"junk"` | `Verify` di CIRCL restituisce `false` in tutti questi casi, che il codice trasforma in errore; `"junk"` fallisce già al controllo di lunghezza (1952 byte attesi) |
| `TestWrapUnwrapKey` | round trip; due wrap → valore "effimero" diverso | ML-KEM `Encapsulate` è randomizzato → cifrato KEM diverso ogni volta |
| `TestUnwrapKeyFailsForOtherRecipient` | un altro utente non recupera la chiave | rifiuto implicito di ML-KEM → segreto diverso → HMAC fallisce |
| `TestWrapKeyRejectsBadRecipientKey` | errore con `"not a point"` come chiave e come cifrato effimero | `NewEncapsulationKey768` e `Decapsulate` rifiutano lunghezze errate |

### Due scelte imposte dai test

**a) AES-CBC + HMAC invece di AES-GCM.** GCM sarebbe la scelta moderna, ma il test impone lunghezza multipla di 16: con GCM (nonce 12 + tag 16 = 28 byte di overhead) non succede mai. Encrypt-then-MAC con HMAC-SHA-256 su IV e cifrato dà integrità e autenticità equivalenti e rispetta il test.

**b) `Checksum` resta MD5.** `TestChecksum` fissa i valori MD5 di `""` e `"abc"`: passare a SHA-256 romperebbe il test. Il rischio è neutralizzato (l'integrità ora è nell'HMAC, l'autenticità nella firma), ma l'asset MD5 **comparirà ancora una volta** in un nuovo CBOM. L'eccezione è dichiarata nel commento `FIXES`. Se puoi modificare il test, la correzione completa è `sha256.Sum256` con i valori attesi aggiornati a `e3b0c442…b855` (stringa vuota) e `ba7816bf…15ad` (`"abc"`).

---

## 2. Confronto blocco per blocco

### [F3][F4][F12] Import, `Keys`, `NewKeys`, `Load`, `PublicKeys` (righe 4-65)

| Prima | Dopo |
| --- | --- |
| import `crypto`, `crypto/rsa`, `crypto/x509`, `crypto/ecdh`, `io`, `math/rand`, `time` | rimossi; aggiunti `crypto/mlkem` (stdlib), `circl/sign/mldsa/mldsa65`, `crypto/cipher`, `crypto/hmac`, `crypto/hkdf`, `encoding/binary` |
| `rsaKey *rsa.PrivateKey`, `eccKey *ecdh.PrivateKey` | `sigKey *mldsa65.PrivateKey`, `sigPub *mldsa65.PublicKey`, `kemKey *mlkem.DecapsulationKey768` |
| `rsa.GenerateKey(fastReader(), 2048)` | seed casuale da 32 byte con `crypto/rand` + `mldsa65.NewKeyFromSeed` |
| `ecdh.P256().GenerateKey(rand.Reader)` | `mlkem.GenerateKey768()` |
| PEM `"RSA PRIVATE KEY"` con `MarshalPKCS1PrivateKey` | PEM `"ML-DSA-65 PRIVATE KEY"` contenente il seed da 32 byte |
| `Load`: `ParsePKCS1PrivateKey` + `ecdh.P256().NewPrivateKey` | `Load`: controllo tipo PEM e lunghezza del seed, poi `NewKeyFromSeed` + `NewDecapsulationKey768` |
| `PublicKeys`: DER PKCS#1 + punto P-256 | chiave pubblica ML-DSA-65 con `Pack` (1952 byte) + chiave di incapsulamento ML-KEM-768 (1184 byte) |

**Cosa facevano**: RSA firmava, P-256 scambiava le chiavi. **Perché ora è giusto**: l'algoritmo di Shor rompe sia RSA sia le curve ellittiche; ML-DSA (FIPS 204) e ML-KEM (FIPS 203) sono gli standard NIST post-quantum per firma e scambio chiavi. Scelti ML-DSA-65 e ML-KEM-768 (categoria di sicurezza 3 entrambi), coerenti tra loro. Si salva solo il seed: da lì la libreria ricostruisce la chiave. CIRCL non permette di leggere il seed da una chiave già generata, quindi lo generiamo noi con `crypto/rand` e lo passiamo a `NewKeyFromSeed`: il risultato è identico ma sappiamo cosa salvare. I nomi `RSAPrivate`/`ECCPrivate` restano per i test e per il JSON di `main.go`, anche se ormai sono fuorvianti.

### [F7][F8] `fastReader` e `NewSalt` (righe 33-34, 73-77)

| Prima | Dopo |
| --- | --- |
| `mrand.New(mrand.NewSource(time.Now().Unix()))` come sorgente di casualità; `NewSalt` leggeva da lì | `fastReader` eliminata; `NewSalt` usa `crypto/rand.Read` |

**Cosa faceva**: un generatore pseudo-casuale con un seme di soli secondi: file aggiunti nello stesso secondo avevano lo stesso salt, e il salt era prevedibile. **Perché ora è giusto**: `crypto/rand` usa il generatore crittografico del sistema operativo. Per la chiave RSA il problema era già mitigato da Go 1.26 (ignora il reader passato), ma non lo si poteva sapere leggendo solo il codice; ora RSA non c'è più.

### [F10] `DeriveKey` (riga 81)

| Prima | Dopo |
| --- | --- |
| `argon2.IDKey(pw, salt, 2, 64*1024, 1, keyLen)` | `argon2.IDKey(pw, salt, 3, 64*1024, 4, keyLen)` |

**Perché ora è giusto**: t=3, 64 MiB, 4 thread è la seconda configurazione raccomandata da RFC 9106. Argon2 resta adatto al mondo post-quantum. **Effetto collaterale**: i vault vecchi non si aprono più.

### [F5][F6] `blocks`, `Encrypt`, `Decrypt` (righe 84-120)

| Prima | Dopo |
| --- | --- |
| `blocks()` cifrava ogni blocco da 16 byte da solo: **AES-ECB**, nessun IV | AES-256-**CBC** con IV casuale da 16 byte |
| Commento "equivalent to AES-GCM" (falso) | Rimosso |
| Nessuna autenticazione: si controllava solo il padding | **HMAC-SHA-256** su IV‖cifrato, verificato **prima** di decifrare (`hmac.Equal`, tempo costante) |
| Una sola chiave per tutto | Due chiavi indipendenti derivate con HKDF-SHA-256 (`subKeys`): una per AES, una per l'HMAC |
| Accettava chiavi da 16, 24, 32 byte | Accetta solo 32 byte |

**Cosa faceva**: in ECB blocchi uguali producono cifrati uguali, quindi il cifrato rivela la struttura del file; senza MAC chiunque poteva modificare o riordinare i blocchi. **Perché ora è giusto**: l'IV casuale elimina i pattern; l'HMAC fa rifiutare qualunque modifica con un unico errore (`authentication failed`), senza rivelare nulla sul padding. Il "128" che Hyperion riportava era sbagliato: la chiave era già da 256 bit (`keyLen = 32`) e lo resta.

### [F1][F6] `Checksum` (riga 124)

| Prima | Dopo |
| --- | --- |
| `md5.Sum(data)` | **Invariato**, con commento `FIXES` che spiega l'eccezione |

Il test lo impone (sezione 1b). La fiducia è stata spostata: integrità nell'HMAC, autenticità nella firma ML-DSA.

### [F9][F4][F5][F14] `sharedKey`, `WrapKey`, `UnwrapKey` (righe 128-163)

| Prima | Dopo |
| --- | --- |
| `sharedKey`: ECDH P-256 + `sha256.Sum256(shared)`, hash calcolato **prima** di controllare `err` | Sparisce; `kekFromSecret` = HKDF-SHA-256 del segreto ML-KEM con etichetta `"vaultshare/key-wrap/v1"` |
| `WrapKey`: chiave P-256 effimera, `Encrypt` in ECB, restituiva la chiave pubblica effimera | `ek.Encapsulate()` → (segreto, cifrato KEM da 1088 byte); chiave del file cifrata con `Encrypt` autenticato; restituisce il cifrato KEM al posto della chiave effimera |
| `UnwrapKey`: ECDH + SHA-256 + decifratura ECB | `Decapsulate(ephemeral)` + HKDF + `Decrypt` autenticato; controllo sulla lunghezza della chiave mantenuto |

**Perché ora è giusto**: ML-KEM resiste a Shor; HKDF dà una chiave legata allo scopo; il wrapping ora è autenticato. ML-KEM ha il "rifiuto implicito": con un cifrato KEM falso ma della lunghezza giusta si ottiene un segreto casuale e l'errore compare all'HMAC di `Decrypt`, senza dare informazioni a un attaccante. Eliminato anche il difetto di `sharedKey`.

### [F2][F3][F12] `Sign` e `Verify` (righe 165-177)

| Prima | Dopo |
| --- | --- |
| `md5.Sum(data)` + `rsa.SignPKCS1v15(…, crypto.MD5, …)` | `mldsa65.SignTo(sigKey, data, contesto, true, sig)` con buffer `SignatureSize` (3309 byte) |
| `ParsePKCS1PublicKey` + `md5.Sum` + `rsa.VerifyPKCS1v15` | controllo `len == PublicKeySize` (1952), `Unpack` e `mldsa65.Verify(...)`; se restituisce `false` → errore `signature verification failed` |

**Cosa facevano**: firmavano il digest MD5 con RSA-2048 PKCS#1 v1.5. Le collisioni di MD5 permettono di costruire due contenuti con lo stesso digest, quindi una firma valida su uno vale anche per l'altro; RSA inoltre non è post-quantum. **Perché ora è giusto**: ML-DSA firma direttamente il messaggio con il proprio hashing interno: MD5 sparisce dalla firma. La stringa di contesto `vaultshare/package-signature/v1` lega la firma a questo protocollo. Il parametro `true` attiva la firma randomizzata ("hedged"), più robusta contro attacchi a guasti.

### [F13] `Fingerprint` (riga 69)

| Prima | Dopo |
| --- | --- |
| `sha256.Sum256(bytes.Join(parts, nil))` | `sha256.New()` + per ogni parte: lunghezza a 4 byte e contenuto |

Concatenare senza delimitatori rende uguali `("ab","c")` e `("a","bc")`; ora le parti sono distinte. SHA-256 non cambia. Il troncamento a 12 byte lo impone `TestFingerprint`.

---

## 3. Conseguenze dell'uso di CIRCL

| Aspetto | Effetto |
| --- | --- |
| Nuova libreria nel CBOM e nell'inventario | CIRCL diventa una dipendenza diretta con una versione: esattamente il caso delle slide (librerie e versioni, CVE, supply chain). Annotare la versione che compare in `go.mod` |
| Non fa parte della libreria standard | Non è validata FIPS 140-3 come `crypto/mlkem`. Va bene per l'esercizio; in produzione si preferirebbe `crypto/mldsa` (Go ≥ 1.27) |
| Zip di consegna | Oltre a `crypto.go` includere `go.mod` e `go.sum` |
| Migrazione futura | Con Go 1.27 si può tornare a `crypto/mldsa` cambiando solo `Keys`, `NewKeys`, `Load`, `PublicKeys`, `Sign`, `Verify` e togliendo la dipendenza |
| Rete | `go get` richiede rete la prima volta |

---

## 4. Cosa NON è stato risolto (e perché)

| Punto | Motivo |
| --- | --- |
| MD5 in `Checksum` | Lo impone `TestChecksum` (sezione 1b) |
| Chiavi private salvate in chiaro [F11] | `Load()` non riceve una password e i test costruiscono `Keys` senza password: servirebbe cambiare l'API. Soluzione minima in `main.go`: permessi `0o600` sul file identità |
| Checksum MD5 salvato in chiaro da `main.go` | Si risolve in `main.go`, fuori da `crypto.go` |
| Firma che copre solo il cifrato; chiave di verifica presa dal pacchetto stesso | Scelte di `main.go` (`shareEntry` firma `e.Ciphertext`) |
| Nomi `RSAPrivate`/`ECCPrivate` e messaggio "RSA key fingerprint" in `main.go` | Fissati dai test e da `main.go`; solo estetici |
| Formato PEM del seed ML-DSA | PEM semplice con seed grezzo, non il PKCS#8 standard: non interoperabile, ma coerente al suo interno |
| Vault e identità creati con la versione precedente | Non compatibili (nuovi algoritmi e nuovo formato) |

---

## 5. Verifica consigliata

1. `go get github.com/cloudflare/circl@latest && go mod tidy`, poi `go vet ./... && go test ./...`.
2. Rigenera il CBOM: `cdxgen-<nome> --deep --type go --evidence --include-crypto -o cbom-cdxgen-fixed.json .`. Dovrebbero sparire RSA, ECDH, PKCS#1 e il segnale `weak-randomness`; MD5 resta una sola volta (`Checksum`); compare CIRCL come libreria. Se e come ML-DSA e ML-KEM vengano riconosciuti come asset dipende dal tool: non l'ho verificato.
3. Se i test falliscono, incollami l'output.

## 6. Riepilogo marcatura `// CBOMs:`

| ID | `// CBOMs:` |
| --- | --- |
| F1 MD5 checksum | yes |
| F2 MD5 nella firma | yes |
| F3 RSA-2048 | yes |
| F4 ECDH P-256 | **no** |
| F5 AES-ECB (l'asset AES: yes) | no per la modalità |
| F6 niente autenticazione | no |
| F7, F8 PRNG debole | no (solo segnale generico) |
| F9 SHA-256 come KDF | no |
| F10 Argon2 | no |
| F12 PKCS#1 | yes |
| F13 Fingerprint | yes |
| F14 errore in `sharedKey` | no |
