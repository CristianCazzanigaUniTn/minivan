# To Inventory and Beyond (EX_08_01): analisi manuale di `crypto.go`

Questo report confronta l'analisi manuale di `crypto.go` con quanto emerso dai due CBOM (CBOMkit-hyperion e cdxgen) e dai report di cbomcompliance.com. **Nessun file è stato modificato.**

Verifica dei riferimenti: i numeri di riga dei CBOM coincidono con il codice (37 `GenerateKey`, 45 `MarshalPKCS1PrivateKey`, 55 `ParsePKCS1PrivateKey`, 64 `MarshalPKCS1PublicKey`, 69 `sha256.Sum256`, 81 `argon2.IDKey`, 86 `aes.NewCipher`, 124/166/175 `md5.Sum`, 171 `ParsePKCS1PublicKey`). Le righe nuove citate sotto sono contate sullo stesso file.

Legenda colonna CBOM: ✅ presente, ⚠️ presente solo in parte o con dati errati, ❌ assente.

---

## 1. Come funziona `vaultshare` dal punto di vista crittografico

Il codice dice più di quanto dicano i CBOM sui **ruoli** degli algoritmi:

| Funzione | Cosa fa | Primitive usate |
| --- | --- | --- |
| `NewKeys` / `Load` | genera e carica l'identità | RSA-2048 (**firma**), ECDH P-256 (**scambio chiavi**) |
| `DeriveKey` | password → chiave del file a 256 bit | Argon2id (t=2, 64 MiB, p=1) |
| `Encrypt` / `Decrypt` / `blocks` | cifra il file e le chiavi | AES-256 in **ECB** + padding PKCS#7 |
| `Checksum` | integrità del file in chiaro | MD5 |
| `sharedKey` | segreto ECDH → chiave di wrapping | SHA-256 |
| `WrapKey` / `UnwrapKey` | cifra la chiave del file per il destinatario | ECDH effimero + AES-ECB |
| `Sign` / `Verify` | firma del pacchetto | RSA PKCS#1 v1.5 con **MD5** |
| `Fingerprint` | impronta delle chiavi pubbliche | SHA-256 troncato a 96 bit |
| `fastReader` / `NewSalt` | casualità per chiave RSA e salt | `math/rand` seminato con `time.Now().Unix()` |

Conseguenza importante: **RSA serve solo per firmare** (righe 167 e 176), non per cifrare. Lo scambio chiavi è fatto con **ECDH P-256**.

---

## 2. Riepilogo dei finding

| ID | Finding | Righe | Gravità | Hyperion | cdxgen | Report cbomcompliance |
| --- | --- | --- | --- | --- | --- | --- |
| F1 | MD5 come checksum di integrità | 124 | Alta | ✅ | ✅ (`weak`) | ✅ already broken |
| F2 | MD5 come digest della firma RSA | 166-167, 175-176 | **Critica** | ⚠️ trova `md5.Sum`, non il ruolo | ❌ trova solo la riga 124 | ⚠️ già "broken", ma non il ruolo |
| F3 | RSA-2048 con PKCS#1 v1.5, usato solo per firmare | 37, 167, 176 | Alta (non PQ) | ⚠️ trova RSA-2048, non il ruolo né il padding | ⚠️ trova RSA, non dimensione né ruolo | ⚠️ suggerisce ML-KEM, ma il ruolo reale è la firma |
| F4 | **ECDH P-256** per lo scambio chiavi | 7, 30, 41, 58, 64, 130, 134, 141, 154 | **Critica (non PQ)** | ❌ | ❌ | ❌ |
| F5 | AES in modalità **ECB** (il commento dice "equivalente ad AES-GCM") | 84-99 | **Critica** | ⚠️ trova AES, dice 128 bit (in realtà 256), nessuna modalità | ⚠️ trova AES, nessun parametro né modalità | ❌ |
| F6 | Nessuna autenticazione del cifrato; checksum MD5 del testo in chiaro salvato in chiaro | 102-120, 122-126 | Alta | ❌ | ❌ | ❌ |
| F7 | Salt generato con `math/rand` seminato con il tempo (secondi) | 17, 33-34, 73-77 | Alta | ❌ | ⚠️ solo il contatore `weak-randomness`, senza posizione | ❌ |
| F8 | Chiave RSA generata con lo stesso PRNG debole | 37 | Media (mitigata, vedi sotto) | ❌ | ⚠️ come F7 | ❌ |
| F9 | Chiave di wrapping = SHA-256 del segreto ECDH (nessun KDF, nessun contesto) | 128-137 | Media | ❌ (riga 135 non trovata) | ❌ (riga 135 non trovata) | ❌ |
| F10 | Argon2id: parametri accettabili ma non ottimali | 79-82 | Bassa | ❌ | ⚠️ solo come libreria e call stack | ❌ |
| F11 | Chiavi private serializzate in chiaro (campi esportati di `Keys`) | 25-31, 45 | Alta | ❌ | ⚠️ rileva il materiale, non lo stoccaggio | ❌ |
| F12 | Formato PKCS#1 legacy per le chiavi RSA | 45, 55, 64, 171 | Bassa (sparisce con RSA) | ❌ | ✅ | ⚠️ "needs review" |
| F13 | Fingerprint: SHA-256 troncato e concatenazione senza delimitatori | 67-71 | Bassa | ✅ SHA-256 | ✅ SHA-256 | non segnalato |
| F14 | `sharedKey` calcola l'hash prima di controllare l'errore | 134-136 | Bassa | ❌ | ❌ | ❌ |

---

## 3. Dettaglio

### 3.1 Trovati nei CBOM e confermati dal codice

**F1 e F2, MD5.** Il CBOM di Hyperion elenca le tre righe giuste. Il codice mostra che **hanno due ruoli diversi**:
- riga 124 (`Checksum`): checksum di integrità del file;
- righe 166 e 175 (`Sign`/`Verify`): digest su cui si calcola la firma RSA, con `crypto.MD5` alle righe 167 e 176.

Il secondo è molto più grave del primo: le collisioni di MD5 permettono di costruire due messaggi con lo stesso digest, quindi una firma può essere riusata su un contenuto diverso. cdxgen segnala solo la riga 124. Nessun CBOM distingue i ruoli.

**F3, RSA-2048.** Entrambi i CBOM lo trovano (riga 37). Il codice aggiunge tre informazioni assenti nei CBOM:
- RSA è usato **solo per la firma**;
- lo schema è **PKCS#1 v1.5** (`SignPKCS1v15`), non PSS;
- l'identità RSA è salvata come PEM "RSA PRIVATE KEY" (PKCS#1).

**Impatto sulla raccomandazione di cbomcompliance.com**: il sito classifica RSA come *key establishment* (perché la primitiva dichiarata è `pke`) e propone **ML-KEM**. Per questo codice è fuorviante: la sostituzione corretta per la firma è **ML-DSA (FIPS 204)**.

**F5, AES.** Hyperion lo trova (riga 86) ma indica 128 bit; cdxgen non indica parametri. Nel codice la chiave è sempre da 32 byte (`keyLen = 32`, e il segreto di wrapping è un SHA-256), quindi si usa **AES-256**. Il parametro "128" di Hyperion è con ogni probabilità un valore di default, non quello reale. Il vero problema è la **modalità**:

- `blocks()` cifra ogni blocco da 16 byte in modo indipendente con `cipher.Encrypt`: è **ECB**;
- blocchi di testo in chiaro uguali producono blocchi cifrati uguali, quindi il cifrato rivela la struttura del file;
- non ci sono IV né nonce;
- il commento "equivalent to AES-GCM" (riga 84) è falso e può trarre in inganno chi legge il codice.

ECB è usato in due punti: per cifrare i file (via `Encrypt` in `main.go`) e per il wrapping della chiave del file (riga 149).

**F7, casualità.** cdxgen riporta nei metadati il segnale `weak-randomness` senza posizione. Il codice lo conferma: `fastReader()` (riga 34) è un `math/rand` seminato con `time.Now().Unix()`, cioè con precisione al secondo. `NewSalt` (riga 75) lo usa direttamente: due file aggiunti nello stesso secondo ricevono lo stesso salt, e il salt è prevedibile. Il salt non è segreto, ma deve essere unico e imprevedibile; qui non lo è.

**F8, chiave RSA.** La riga 37 passa `fastReader()` a `rsa.GenerateKey`. Con una versione di Go precedente alla 1.26 sarebbe stata una vulnerabilità grave (chiave ricostruibile provando i secondi attorno alla creazione). Con **Go 1.26** (il `go.mod` dichiara 1.26.0) il parametro è ignorato e viene usato un generatore sicuro, a meno di `GODEBUG=cryptocustomrand=1`, quindi qui è mitigato dal toolchain. Resta comunque uno smell: la sicurezza dipende dalla versione di Go e non dal codice.

**F12, chiavi PKCS#1.** cdxgen le rileva correttamente (righe 45, 55, 64, 171). Scompaiono con la sostituzione di RSA.

**F13, SHA-256.** Il CBOM lo segnala come corretto e per l'uso in `Fingerprint` lo è. Due dettagli minori: il troncamento a 12 byte lascia 96 bit (accettabile per un controllo manuale), e `bytes.Join(parts, nil)` concatena senza delimitatori né lunghezze.

### 3.2 Presenti nel codice ma assenti da entrambi i CBOM

**F4, ECDH P-256.** È il finding più importante di tutta l'analisi. Né Hyperion né cdxgen elencano `crypto/ecdh`: non compare né l'algoritmo, né il materiale (chiave privata ECC a riga 28 e 58, pubblica a riga 64). Per i CBOM lo scambio chiavi di `vaultshare` **non esiste**. P-256 è vulnerabile all'algoritmo di Shor, quindi è il vero candidato per **ML-KEM (FIPS 203)**, non RSA.

**F6, nessuna autenticazione.** Né `Encrypt` né `Decrypt` usano un MAC o un tag. L'integrità è delegata a un checksum MD5 del testo in chiaro, salvato **in chiaro** accanto al cifrato (`VaultEntry.Checksum`). Due conseguenze:
- non protegge dalle manomissioni, perché chi modifica il cifrato può ricalcolare il checksum;
- espone un'informazione sul contenuto: chi ha il file può verificare offline se il testo coincide con un'ipotesi (rilevante per file brevi o prevedibili).

Il padding PKCS#7 (righe 101-120) non appare in nessun CBOM.

**F9, derivazione della chiave di wrapping.** `sharedKey` (riga 135) usa `sha256.Sum256(shared)` come chiave. SHA-256 è un asset noto ai CBOM, ma **questa occorrenza** (riga 135) non è elencata (entrambi trovano solo la 69). È una derivazione senza HKDF, senza salt e senza legare la chiave al contesto (chiavi pubbliche dei due lati, nome dell'algoritmo).

**F10, Argon2id.** I CBOM vedono solo la libreria `golang.org/x/crypto` (cdxgen, con call stack fino a `argon2.IDKey`). Non c'è un asset "KDF". Parametri: t=2, 64 MiB, 1 thread, salt di 16 byte, output di 32 byte. Sono sopra i minimi OWASP, ma inferiori alla seconda configurazione raccomandata da RFC 9106 (t=3, 64 MiB, p=4). Con Argon2 non c'è un problema post-quantum.

**F11, chiavi in chiaro a riposo.** La struct `Keys` espone `RSAPrivate` (PEM non cifrato) ed `ECCPrivate` (scalare grezzo) come campi esportati, quindi `main.go` li scrive in chiaro nel JSON dell'identità. I CBOM rilevano le chiavi ma non come vengono conservate.

**F14.** `sharedKey` calcola `sha256.Sum256(shared)` prima di controllare `err`. Funziona perché i chiamanti controllano l'errore, ma è fragile.

### 3.3 Imprecisioni e falsi positivi nei CBOM

| Elemento | Problema |
| --- | --- |
| cdxgen: "X.509 certificate" (riga 45) | **Falso positivo**: nel codice non ci sono certificati; è la serializzazione PEM di una chiave PKCS#1 |
| Hyperion: AES parametro 128 | **Errato**: le chiavi sono da 256 bit |
| cdxgen: OID di RSA `2.5.8.1.1` | Famiglia X.500, ambiguo; l'OID corretto di `rsaEncryption` è `1.2.840.113549.1.1.1` (quello di Hyperion) |
| cdxgen: descrizione di MD5 ("RSA coupled with MD5") | Fuorviante, l'OID dell'hash è corretto |
| cdxgen: `cryptoAssetCount = 5` | Non coincide con gli 8 asset elencati |
| cbomcompliance.com: "RSA → ML-KEM" | Il ruolo reale è la firma, quindi ML-DSA |
| Hyperion, cdxgen: nessun padding né modalità | Il CBOM non rappresenta PKCS#1 v1.5, ECB e PKCS#7 |

---

## 4. Correzioni a quanto detto nei passi precedenti

1. **AES-128 → AES-256 non serve.** Nel file `CBOM_analysis.md` lo avevo indicato come hardening a partire dal parametro di Hyperion; il codice usa già chiavi da 256 bit. L'intervento è sulla **modalità** (ECB), non sulla dimensione.
2. **RSA non va sostituito con ML-KEM.** Il report cbomcompliance.com e una mia ipotesi precedente lasciavano aperta la questione; il codice la chiude: RSA firma, quindi ML-DSA. ML-KEM serve per sostituire **ECDH P-256**, che i CBOM non vedono.
3. **I segnali di cdxgen hanno un riscontro.** `weak-randomness` corrisponde a F7 e F8; per gli altri due vedi l'appendice.

---

## 5. Direzione dei fix (nessuna modifica fatta) e marcatura per la consegna

Il README chiede di marcare ogni modifica con `// CBOMs: yes/no` e `// FIXES: ...`. Compilazione proposta del campo CBOMs:

| ID | Fix proposto | `// CBOMs:` |
| --- | --- | --- |
| F1 | Sostituire MD5 con SHA-256 (o SHA-384/SHA-3). Meglio ancora: eliminare il checksum separato e affidare l'integrità al tag di un cifrario autenticato | yes |
| F2 | Rimuovere MD5 dalla firma: l'algoritmo ML-DSA usa il proprio hashing interno | yes (le righe sì, il ruolo no) |
| F3 | RSA-2048 PKCS#1 v1.5 → ML-DSA (FIPS 204) | yes |
| F4 | ECDH P-256 → ML-KEM (FIPS 203), eventualmente in forma ibrida durante la transizione | **no** |
| F5 | AES-ECB + PKCS#7 → AES-256-GCM con nonce casuale unico per cifratura (per i file e per il wrapping della chiave), e correggere il commento | no per la modalità (l'asset AES: yes) |
| F6 | Integrità tramite AEAD; non salvare un hash del testo in chiaro | no |
| F7 | `NewSalt` con `crypto/rand`; eliminare `fastReader` e l'import `math/rand` | no (segnale generico in cdxgen) |
| F8 | `rsa.GenerateKey` con `crypto/rand.Reader` (sparisce con RSA) | no |
| F9 | HKDF-SHA-256 con informazione di contesto al posto del SHA-256 nudo | no |
| F10 | Valutare t=3 e più thread (RFC 9106), mantenere salt da 16 byte | no |
| F11 | Non salvare le chiavi private in chiaro: cifrarle con una password o almeno permessi restrittivi sul file | no |
| F12 | Si risolve con la sostituzione di RSA | yes |
| F13 | Nessuna modifica obbligatoria; eventualmente fingerprint più lungo e con lunghezze prefissate | yes |
| F14 | Controllare `err` prima di derivare la chiave | no |

---

## 6. Appendice: osservazioni su `main.go` (fuori dal perimetro di `crypto.go`)

Non sono richieste dalla consegna (che riguarda `crypto.go`), ma spiegano due segnali di cdxgen che altrimenti restano senza posizione. Le associazioni sono nostre deduzioni, il CBOM non indica righe.

- **`filesystem`**: `writeJSON` scrive con permessi `0o644` il file dell'identità, che contiene le chiavi private.
- **`deserialization`**: `json.Unmarshal` su file forniti dall'esterno (pacchetti e identità pubbliche).
- **Firma non completa**: `shareEntry` firma solo `e.Ciphertext`. Nome del file, mittente, checksum, chiave effimera e chiave incapsulata non sono coperti.
- **Chiave di verifica auto-dichiarata**: `Verify` usa la chiave RSA contenuta nel pacchetto stesso. "Signature valid" dimostra solo che il pacchetto è coerente con la chiave inclusa; l'autenticità del mittente dipende dal confronto manuale dell'impronta.

---

## 7. Sintesi

- **Trovato nei CBOM e confermato**: MD5 (3 righe), RSA-2048, AES, SHA-256, chiavi PKCS#1, Argon2 (come libreria), segnale `weak-randomness`.
- **Il CBOM trova l'asset ma sbaglia o omette il dettaglio decisivo**: ruolo di MD5 nella firma, ruolo e padding di RSA, dimensione di AES (256 e non 128) e modalità ECB.
- **Assente da entrambi i CBOM**: ECDH P-256 e relativo materiale, assenza di autenticazione, padding PKCS#7, PRNG debole per il salt, KDF debole per il wrapping, chiavi private in chiaro.
- **Falsi positivi**: certificato X.509; parametro AES-128.
- **Priorità**: F2/F3 (firma con MD5 su RSA), F4 (ECDH non PQ), F5/F6 (ECB senza autenticazione), F7 (salt prevedibile).
