# To Inventory and Beyond (EX_08_01): analisi dei CBOM

Progetto analizzato: `vaultshare` (Go), commit `b9bd3f5`.
Fonti usate in questa fase: **solo** i due CBOM (`cbom.json` di CBOMkit-hyperion e `cbom-cdxgen.json` di cdxgen) e i due report di cbomcompliance.com. Il codice Go non è stato letto; le righe citate provengono dai CBOM.

---

## 1. Cosa ha trovato ciascun tool

### CBOMkit-hyperion (`cbom.json`, CycloneDX 1.6)

4 asset, tutti algoritmi, con parametri e occorrenze nel codice (`evidence.occurrences`).

| Asset | Primitiva | Parametro | OID | Righe in `crypto.go` |
| --- | --- | --- | --- | --- |
| SHA-256 | hash | 256 | 2.16.840.1.101.3.4.2.1 | 69 |
| RSA-2048 | pke | 2048 | 1.2.840.113549.1.1.1 | 37 (`GenerateKey`) |
| AES | block-cipher | 128 | 2.16.840.1.101.3.4.1 | 86 (`NewCipher`) |
| MD5 | hash | 128 | assente | 124, 166, 175 |

`dependencies` è vuoto: nessun asset è collegato a un componente.

### cdxgen (`cbom-cdxgen.json`, CycloneDX 1.7, v13.7.0)

8 asset crittografici + 2 librerie Go.

| Tipo | Elementi | Righe |
| --- | --- | --- |
| Algoritmi | aes (strong), md5 (**weak**), rsa (acceptable), sha-256 (strong) | 86, 124, 37, 69 |
| Materiale | chiave privata PKCS#1, `private-key`, `public-key` | 55; 37; 171, 45, 64 |
| Certificato | "X.509 certificate" | 45 |
| Librerie | `golang.org/x/crypto v0.58.0` (diretta, usa `argon2.IDKey` in `DeriveKey`, riga 81), `golang.org/x/sys v0.49.0` (indiretta) | 20, 81 |

Nei metadati compaiono anche 9 segnali di sicurezza, con categorie `deserialization`, `filesystem`, `weak-crypto`, `weak-randomness`. Sono solo contatori: senza posizione.

---

## 2. Differenze tra i due CBOM

| Aspetto | Hyperion | cdxgen |
| --- | --- | --- |
| Algoritmi base (AES, MD5, RSA, SHA-256) | sì | sì |
| Parametri (2048 / 128 / 256) | sì | **no** |
| Occorrenze MD5 | 3 (124, 166, 175) | solo 1 (124) |
| Posizione nel codice | standard (`evidence.occurrences`) | proprietà custom (`cdx:golem:crypto:sourceLocation`) |
| Forza dell'algoritmo | no | sì, ma in proprietà custom (`cdx:golem:crypto:strength`) |
| Chiavi e materiale crittografico | no | sì |
| Certificati | no | sì, ma è un **falso positivo** (vedi sotto) |
| Librerie e dipendenze (Argon2) | no | sì, come librerie, non come asset |
| Segnali weak-crypto / weak-randomness / ... | no | solo come contatori |
| Collegamento asset-componenti | no | parziale (grafo delle dipendenze fra librerie) |

### Anomalie di cdxgen da non riportare alla leggera

- **OID di RSA**: `2.5.8.1.1` (famiglia X.500, descritto dallo stesso tool come ambiguo). L'OID di `rsaEncryption` è `1.2.840.113549.1.1.1`, quello riportato da Hyperion.
- **Descrizione di MD5**: l'OID `1.2.840.113549.2.5` è quello corretto dell'hash MD5, ma la descrizione parla di "RSA coupled with MD5", che è fuorviante.
- **"X.509 certificate"**: deriva dal simbolo `MarshalPKCS1PrivateKey` (riga 45), che serializza una chiave privata. Non c'è nessun certificato: è un falso positivo.
- **Conteggi incoerenti**: `cryptoAssetCount = 5` nei metadati, ma i componenti `cryptographic-asset` sono 8 (come dice anche l'annotazione del documento).
- **Argon2** (KDF per le chiavi derivate dalle password) è visibile solo come libreria e call stack, non come asset algoritmo.

---

## 3. Cosa dicono i report di cbomcompliance.com

Entrambi i report sono marcati dal sito come *UNSIGNED, NOT COMPLIANCE EVIDENCE*: servono per l'analisi, non come prova di conformità. Il sito valuta solo gli asset *dichiarati* nel manifest e non può trovare crittografia non dichiarata.

| | Hyperion | cdxgen |
| --- | --- | --- |
| Asset valutati | 4 | 8 |
| Quantum vulnerable | 1 (RSA) | 1 (RSA) |
| Already broken | 1 (famiglia MD, **MD5**) | 1 (famiglia MD, **MD5**) |
| Quantum safe | 0 | 0 |
| Needs review | 0 | **4** |
| Conformità CBOM | 8 / 10 | 6 / 10 |
| Regole MISS | CBOM-006, CBOM-007 | CBOM-005, 006, 007, 008 |
| Esito | NON-COMPLIANT: 2 asset da sostituire | NON-COMPLIANT: 2 asset da sostituire |

Raccomandazioni del sito:

- **MD5**: stato *IMMEDIATE* (già non conforme, non è un problema quantistico). Sostituzione suggerita: SHA-384.
- **RSA**: scadenza 2030-12-31 (EO 14412, key establishment, perché la primitiva dichiarata è `pke`). Sostituzione suggerita: ML-KEM (FIPS 203).

Le regole mancanti:

- **CBOM-005** (parametro o dimensione chiave): mancante solo in cdxgen. È la conseguenza diretta dell'assenza di `parameterSetIdentifier`.
- **CBOM-006** (`nistQuantumSecurityLevel`): mancante in **entrambi**.
- **CBOM-007** (asset collegati ai componenti via dipendenze): mancante in **entrambi**.
- **CBOM-008** (finestra di validità del certificato): mancante in cdxgen, a causa del falso certificato X.509.

I 4 "needs review" di cdxgen sono con ogni probabilità i 4 elementi non-algoritmo (chiave privata PKCS#1, `private-key`, `public-key`, X.509): è un'inferenza, il report non li elenca.

### Perché il viewer di Zurich/CBOMkit mostrava poco

Il viewer valuta solo la conformità post-quantum. MD5 è un hash, non attaccabile da Shor, quindi finisce in "Not Applicable". La debolezza classica (collisioni) è invece segnalata da cbomcompliance.com ("already broken") e, per cdxgen, dalla proprietà `strength: weak`. I due viewer sono complementari e vanno usati entrambi, come chiede il README.

---

## 4. Bad assets individuati dai soli CBOM

| # | Asset | Dove / da chi | Problema | Gravità | Intervento proposto |
| --- | --- | --- | --- | --- | --- |
| 1 | **MD5** | Hyperion: righe 124, 166, 175. cdxgen: riga 124 (`weak`). cbomcompliance: *already broken* | Hash rotto per collisioni, non è un problema quantistico | Critica, immediata | Sostituire con SHA-256 o SHA-384 (suggerito dal sito) o SHA-3. Se serve autenticità e non solo checksum, usare HMAC o la firma già presente |
| 2 | **RSA-2048** | Entrambi, riga 37 (`GenerateKey`). cbomcompliance: *quantum vulnerable* | Vulnerabile all'algoritmo di Shor | Critica (scadenza EO 14412: 2030-12-31 per key establishment, 2031-12-31 per firme) | Sostituire con ML-KEM (FIPS 203) per lo scambio chiavi e/o ML-DSA (FIPS 204) per le firme, a seconda dell'uso. **Il CBOM non dice se RSA serve per firma, cifratura o entrambe**: da verificare nel codice |
| 3 | **Chiavi PKCS#1** (private riga 55 e 37, pubbliche righe 171, 45, 64) | cdxgen | Formato legacy specifico di RSA | Media, conseguenza del punto 2 | Sparisce con la migrazione; verificare formato di serializzazione delle nuove chiavi |
| 4 | **AES, parametro 128** | Hyperion, riga 86 | Accettabile oggi, margine ridotto in ottica post-quantum (Grover); modalità e autenticazione non dichiarate | Bassa, hardening | Passare ad AES-256 e verificare nel codice la modalità (preferibile una autenticata, tipo GCM). Nessuno dei due report lo segnala: è una valutazione nostra |
| 5 | **Segnali `weak-randomness`, `deserialization`, `filesystem`** | cdxgen, solo contatori nei metadati | Indicano possibili problemi senza posizione | Da accertare | Cercare a mano nel codice (prossima fase) |

### Asset accettabili

- **SHA-256** (Hyperion riga 69, cdxgen `strong`): nessun intervento necessario. Il sito non lo segnala; la raccomandazione SHA-384 vale solo come sostituto di MD5.
- **`golang.org/x/crypto` e `golang.org/x/sys`**: nessuna criticità emerge dai CBOM, ma i CBOM non contengono verifiche CVE sulle versioni, quindi nessuna conclusione su questo punto.

---

## 5. Limiti dei CBOM (cosa non dicono)

- Modalità e padding di AES, gestione di nonce/IV e autenticazione del cifrato.
- Schema e padding di RSA (PKCS#1 v1.5, OAEP, PSS) e a cosa serve la coppia di chiavi.
- Parametri di Argon2 (memoria, iterazioni, parallelismo, lunghezza del salt).
- Quale algoritmo viene usato per il "key agreement" citato nel README: nessun asset ECDH/X25519 compare in nessuno dei due CBOM.
- Origine dei segnali `weak-randomness`, `deserialization` e `filesystem`.
- Perché MD5 compaia in 3 punti (Hyperion) invece di 1 (cdxgen).

Questi punti sono l'agenda della fase 4 del README (analisi manuale del codice).

---

## 6. Miglioramenti ai CBOM stessi (solo per la relazione, il README non richiede di aggiornarli)

- Aggiungere `nistQuantumSecurityLevel` e `classicalSecurityLevel` ad ogni algoritmo (regola CBOM-006).
- Popolare `dependencies` per legare ogni asset al componente che lo usa (regola CBOM-007; entrambi i CBOM sono carenti).
- Aggiungere `parameterSetIdentifier` agli algoritmi di cdxgen (regola CBOM-005).
- Rimuovere il falso certificato X.509 di cdxgen.
- Unire i due CBOM: Hyperion per parametri e occorrenze, cdxgen per chiavi, forza dell'algoritmo e librerie.

---

## 7. Riepilogo per la consegna

- **Trovati da entrambi**: MD5, RSA, AES, SHA-256.
- **Solo Hyperion**: parametri (2048, 128, 256) e tutte e 3 le occorrenze di MD5.
- **Solo cdxgen**: forza degli algoritmi, materiale crittografico, librerie e segnali di sicurezza; contiene però un falso positivo (X.509) e OID errati.
- **Da risolvere (da soli CBOM)**: MD5 (immediato), RSA (post-quantum), AES-128 (hardening, nostra valutazione).
- **Da approfondire nel codice**: modalità AES, parametri Argon2, uso effettivo di RSA (firma o scambio chiavi), randomness, deserializzazione e permessi dei file.
