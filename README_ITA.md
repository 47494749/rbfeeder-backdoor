
# ANALISI FORENSE: MALWARE SU RASPBERRY PI (RBFEEDER / RADARBOX)

Sono stato hackerato e non me ne sono mai accorto fino a ieri (17.04.2026)!

Tutto è iniziato molti anni fa quando ho comprato un Raspberry Pi 3 per condividere le posizioni degli aerei con FlightRadar24, ADSBexchange, RadarBox e qualcun altro. Ho installato tutto e l'ho lasciato andare per anni senza mai controllarlo. Lo riavviavo giusto quando ricevevo un messaggio che era offline.

Qualche giorno fa, per "allenarmi" un po' con l'AI, mi è venuto in mente di dare un'occhiata a dump1090 (progetto open source per decodifica ADS-B). Ho fatto controllare all'AI cosa mancasse rispetto alle specifiche tecniche... tempo 3 minuti e già avevo chiesto di aggiungere quello che ancora non aveva.

Ho fatto compilare e provare sul Raspberry. Tutto funzionava fino a che non trovo un conflitto su una porta. Chiedo all'AI di investigare e mi segnala un processo sospetto: un certo **"dump1090-rb"** che girava in `/tmp` e si connetteva a un server su Alibaba Cloud in Cina (`8.219.81.242`).

L'AI inizialmente lo identifica come il client di RadarBox, il relay che legge i dati ADS-B dalla porta 30005 e li inoltra al server remoto. Però il fatto che girasse in `/tmp`, fosse compresso con UPX e offuscato non mi convinceva. A quel punto ho fermato tutti i servizi di sharing che giravano sul RaspBerry ed ho scaricato il binario che girava in /tmp/ e l'ho decompresso per dargli un'occhiata.

Da qui è partita l'analisi vera e propria.

---

> **NOTA IMPORTANTE SULLA METODOLOGIA**
>
> L'analisi di reverse engineering è stata effettuata **ESCLUSIVAMENTE** sui file malevoli trovati sul dispositivo (il RAT `upevm`, il client FRP mascherato come `dump1090-rb`, lo script dropper `rbfeeder.sh` e i binari scaricati dal server C2).
>
> Il software **rbfeeder di AirNav (RadarBox) NON è stato sottoposto a reverse engineering** del binario. Le informazioni sul comportamento di rbfeeder sono state ricavate dall'AI utilizzando normali strumenti Linux di sistema in modo automatico:
> - `readelf` per leggere la tabella dei simboli importati
> - `strings` per estrarre le stringhe di testo leggibili
> - `strace` per osservare le chiamate di sistema in tempo reale
> - `ss`/`netstat` per le connessioni di rete attive
> - `ps`/`systemctl` per i processi e servizi in esecuzione
>
> Nessuna analisi di disassembly o reverse engineering è stata condotta sul codice di AirNav. Le informazioni estratte (nomi di funzioni importate, stringhe di log, connessioni di rete) sono tutte ottenibili con strumenti standard disponibili su qualsiasi sistema Linux.

---


## 1. CRONOLOGIA DELL'INFEZIONE SUL MIO RASPBERRY

| Data | Evento |
|------|--------|
| **2023-02-22** | rbfeeder v0.3.5 installato dal repository ufficiale `apt.rb24.com` |
| **2023-02-22** | Il servizio rbfeeder si avvia e si connette al server AirNav (`212.224.72.114:33755`) |
| **2023-07-27** | Primo log disponibile in `rbfeeder.log` (485MB, mai ruotato). Il log contiene SOLO statistiche periodiche. |
| **2025-08-18 10:03:47** | `upev.service` creato sul sistema, **data della prima infezione**. Qui il comando di installazione del malware è stato eseguito. |
| **2025-09-10 03:00:43** | Binario RAT `upevm` compilato (versione "20250910") |
| **2025-10-17 05:25:39** | Symlink `/usr/bin/upev` → `/usr/bin/upevm` ricreato (aggiornamento automatico del RAT) |
| **2025-10-22 04:09:57** | Binario `upevm` aggiornato a una nuova versione |


## 2. RICOSTRUZIONE COMPLETA DELLA CATENA DI ATTACCO BASATA SUGLI EVENTI NEI LOG ANCORA PRESENTI

**Fase 1: INSTALLAZIONE DEL SOFTWARE** (Febbraio 2023)
- Utente installa rbfeeder dal repository ufficiale RadarBox
- Si stabilisce una connessione permanente al server AirNav

**Fase 2: COMMAND INJECTION** (~18 Agosto 2025)
- Attraverso il protocollo proprietario, viene inviato un comando
- rbfeeder lo riceve e lo esegue tramite shell di sistema (vedremo dopo)
- Il comando scarica ed esegue uno script malevolo dal dominio `apt.transponderlive.org`

**Fase 3: INSTALLAZIONE MALWARE** (18 Agosto 2025, ~10:03)
- Lo script viene eseguito con privilegi **ROOT** (perché rbfeeder gira come root, almeno nel mio raspberry)
- Risolve il dominio del server C2 bypassando il DNS locale
- Scarica il binario RAT con credenziali hardcoded
- Installa:
  - `/usr/bin/upevm` (binario RAT scritto in Go, compresso con UPX)
  - `/usr/bin/upev` → symlink al binario
  - `upev.service` (servizio systemd mascherato come "udev")
- Pulisce le tracce dal crontab

**Fase 4: RAT ATTIVO** (da Agosto 2025)
- Il servizio malevolo si avvia ad ogni boot
- Comunica con il server C2 via HTTPS con crittografia AES-256
- Riceve la configurazione per il tunnel di rete
- Avvia un tunnel che espone i dati ADS-B verso l'esterno

**Fase 5: AGGIORNAMENTI AUTOMATICI** (Ottobre 2025)
- Il RAT si aggiorna periodicamente scaricando nuove versioni (file sul server aggiornati a Marzo ed Aprile 2026)
- Oct 17: symlink ricreato
- Oct 22: binario aggiornato


## 3. CATENA DI INFEZIONE: COME ARRIVA IL MALWARE

L'installer ufficiale di RadarBox (`apt.rb24.com`) e il pacchetto Debian sono risultati puliti: installano solo il binario rbfeeder, il file di configurazione e il servizio systemd. Nessuno script malevolo nel pacchetto.

Analizzando rbfeeder con strumenti Linux standard (`readelf`, `strings`) è emerso che il binario importa la funzione `posix_spawn` e contiene stringhe come `"Run command: %s"`, `"/bin/sh"`, `"Expected CMD has arrived!"` , indicatori di una capacità di esecuzione comandi ricevuti dal server (BACKDOOR!)

**L'infezione avviene DOPO l'installazione**, attraverso il protocollo di comunicazione proprietario tra rbfeeder e il server AirNav: il server invia un comando, rbfeeder lo esegue come shell di sistema.

Lo script malevolo cancella le proprie tracce dopo l'esecuzione.

**Timestamp dell'infezione** (dal filesystem):

| Evento | Timestamp |
|--------|-----------|
| `upev.service` creato | 2025-08-18 10:03:47 |
| Symlink ricreato | 2025-10-17 05:25:39 |
| Binario aggiornato | 2025-10-22 04:09:57 |

**L'attacco non lascia tracce perché:**

1. Il comando viene eseguito via protocollo proprietario, e non salvato nei logs
2. Il dropper installa i file direttamente, senza usare il gestore pacchetti
3. Il dropper pulisce il crontab
4. I log di sistema del periodo dell'infezione (agosto-ottobre 2025) sono stati ruotati e persi, restano solo quelli da aprile 2026
5. Il log di rbfeeder (485MB) contiene solo statistiche, mai i comandi eseguiti
6. Nessuna traccia in `bash_history`, `auth.log` o `journal` del periodo

## 4. CHI HA MODIFICATO IL CRON

Il dropper script ha **pulito** il crontab (rimuovendo righe contenenti "rbfeeder"), non lo ha modificato per aggiungere entries malevole. Questo meccanismo cancella tracce di precedenti versioni dell'attacco che usavano il crontab per la persistenza.

Nessun crontab del sistema contiene entries malevole. La persistenza del malware è affidata esclusivamente al servizio systemd `upev.service`.


## 5. INFRASTRUTTURA SERVER, DOMINI, FILE DEL RAT

**Dominio:** `apt.TransponderLive.org` (registrato per sembrare un repository APT legittimo)

L'infrastruttura è composta da 4 server, tutti su Alibaba Cloud (Asia), più un server di fallback su Vultr:

| IP | Porte | Funzione |
|----|-------|----------|
| `47.91.75.121` | 80, 58888 | Server HTTP dropper (distribuzione binari RAT e script di installazione) |
| `47.245.129.80` | 443 | Server C2 HTTPS (ricezione beacon cifrati dai dispositivi infetti) |
| `8.219.81.242` | 7000 | Server FRP per tunnel dati ADS-B |
| `47.89.154.27` | 7700 | Server FRP secondario (proxy admin, SOCKS5, accesso a reti interne) |
| `45.63.1.41` | n/a | Vultr, fallback server rbfeeder |

> **NOTA:** Il server FRP secondario (`47.89.154.27`) contiene configurazioni per raggiungere indirizzi di rete interna (`10.0.10.56`), il che indica la compromissione di dispositivi all'interno di reti private aziendali.

## 6. PROTOCOLLO C2 (COMMAND & CONTROL)

Il malware utilizza un sistema di comunicazione sofisticato:

**Risoluzione DNS:**
Il binario malevolo non usa il DNS di sistema ma fa query dirette a Google (`8.8.8.8`) e Cloudflare (`1.1.1.1`) per risolvere il dominio `apt.TransponderLive.org`. Inoltre, i risultati DNS standard e quelli interni puntano a IP diversi, tecnica per rendere più difficile il tracciamento.

**Crittografia:**
La comunicazione con il server C2 è cifrata con **AES-256-CBC**. La chiave è derivata dal serial number del dispositivo, quindi ogni dispositivo infetto ha una chiave unica.

**Comunicazione:**
Il RAT invia periodicamente al server C2 (via HTTPS) informazioni sul sistema: serial number, hostname, IP, architettura, versione OS. Il server può rispondere con comandi, inclusa la possibilità di aprire una shell remota interattiva sul dispositivo.


### 6.1 CONTENUTO DEL SERVER HTTP DROPPER

Mirror del server eseguito il 18-Apr-2026. Il sito ha directory listing attivo e contiene:

```
http://47.91.75.121/
│
├── c                          crontab pulito (rimpiazzo)
├── upev                       init.d script per upev
├── upev.service               systemd unit per upev
│
├── /08967/frp/                directory con client e config FRP
│   ├── adm                    config FRP → proxy admin
│   ├── dump987                client FRP x86-64 (rinominato per mimetismo)
│   ├── frpc_arm               client FRP ARM32
│   ├── frpc_x64               client FRP x86-64
│   ├── readadsb               config FRP → SOCKS5 proxy
│   ├── sock5.toml             config FRP → SOCKS5 proxy
│   └── sql                    config FRP → proxy database interno
│
├── /494/                      staging area (dropper + config)
│   ├── frpc_arm               client FRP ARM32
│   ├── ip                     IP del server FRP (gzip)
│   ├── rbfeeder.sh            script dropper di installazione (gzip)
│   └── sock5.toml             config SOCKS5
│
├── /a/                        campaign "a", feeder ADS-B generico
│   ├── amd64 / arm / arm64 / armv6l     binari RAT (UPX packed)
│   └── *.md5                             hash per update check
│
├── /e/                        campaign "e", sconosciuta
├── /k/                        campaign "k", KiwiSDR
├── /n/                        campaign "n", sconosciuta
├── /r/                        campaign "r", RadarCape
├── /u/                        campaign "u", sconosciuta
│   └── (stessa struttura: 4 binari + 4 MD5 per ogni campaign)
│
├── /tmp/                      staging area (= /494/)
│
└── /files/                    directory vuote (staging futuro?)
    ├── /a/, /e/, /k/, /n/, /r/, /tmp/, /u/  (tutte vuote)

TOTALE: 66 file, 17 directory, ~280 MB
```

*Le credenziali per autenticarsi sul sito erano presenti nei file di configurazione inviati con il RAT.*


### 6.2 CAMPAGNE MALWARE (6 VARIANTI)

Il server distribuisce il RAT in 6 "campagne" diverse, ognuna mirata a un tipo specifico di dispositivo:

| Campagna | Target |
|----------|--------|
| **a** | Default (feeder ADS-B generico) |
| **e** | Sconosciuto |
| **k** | KiwiSDR (ricevitore SDR web) |
| **n** | Sconosciuto |
| **r** | RadarCape (ricevitore ADS-B dedicato) |
| **u** | Sconosciuto |

Ogni campagna ha binari per 4 architetture hardware, tutti compressi con UPX. I binari sono leggermente diversi tra campagne (probabilmente con configurazione specifica per il tipo di dispositivo).


### 6.3 CONFIGURAZIONI FRP (4 PROFILI TUNNEL)

Sul server sono stati trovati 4 profili di configurazione per il tunnel FRP, che permettono all'attaccante di:
- Usare i dispositivi infetti come **proxy SOCKS5** (navigazione anonima)
- Accedere a **pannelli di amministrazione** remoti
- Raggiungere **database interni** su reti private (`10.x.x.x`)

Il client FRP viene mascherato come `dump987` o `dump1090-rb` per sembrare un processo legittimo di decodifica ADS-B.

## 7. ACCESSO ALL'INFRASTRUTTURA C2 (Aprile 2026) 

Il server HTTP dropper (`47.91.75.121`) è accessibile con credenziali hardcoded trovate nello script malevolo. Il directory listing è attivo, permettendo di enumerare tutti i file distribuiti.

Il server C2 HTTPS (`47.245.129.80`) riceve i beacon cifrati dai dispositivi infetti. La cifratura usa AES-256-CBC con chiave derivata dal serial number del dispositivo.

Il server FRP (`8.219.81.242`) crea tunnel TCP per l'esfiltrazione dei dati ADS-B. Il token di autenticazione FRP è hardcoded nel binario malevolo.

**Credenziali e accessi trovati:**
- **HTTP dropper:** Basic Auth con credenziali hardcoded nello script
- **FRP relay:** token di autenticazione hardcoded nel binario
- **Cifratura beacon:** chiave derivata dal serial number del dispositivo
- **Dominio C2:** `apt.transponderlive.org`


## 8. MECCANISMO FRP: TUNNEL DATI

Il RAT, una volta attivo, scarica un client FRP (Fast Reverse Proxy) dal server C2, lo salva come `/tmp/dump1090-rb` (nome scelto per mimetizzarsi con il legittimo dump1090) e lo avvia.

Il tunnel FRP espone la porta locale **30005** (dove dump1090-fa serve i dati ADS-B in formato Beast) verso un server remoto. Chiunque si connetta al server FRP sulla porta assegnata riceve lo stream di dati radar in tempo reale dal dispositivo (a che scopo??).

Questo tunnel è per l'esfiltrazione dei dati ADS-B. Il RAT ha **ANCHE** capacità di shell remota interattiva, ma quella passa dal canale C2 HTTPS separato.


## 9. LO SCRIPT DI INSTALLAZIONE MALEVOLO (rbfeeder.sh)

Lo script dropper, scaricato dal server C2 e analizzato, fa quanto segue:

1. Determina l'architettura del sistema e il continente geografico
2. Risolve il dominio C2 bypassando il DNS locale (usa DNS over HTTPS)
3. Scarica il binario RAT appropriato per l'architettura del dispositivo

**Se eseguito come ROOT** (caso di rbfeeder):
- Installa il binario come `/usr/bin/upevm`
- Crea un symlink `/usr/bin/upev`
- Registra un servizio systemd mascherato come "udev" (gestione dispositivi)
- Pulisce le tracce dal crontab
- Elimina se stesso

**Se eseguito come utente normale:**
- Salva il binario in una directory nascosta (`/tmp/.font-unix/`)
- Aggiunge un crontab per la persistenza (ri-scarica ogni minuto se non attivo)


## 10. AIRNAV RBFEEDER E LA CAPACITÀ DI ESECUZIONE COMANDI

> **Metodologia di analisi:** Il comportamento di rbfeeder è stato analizzato utilizzando **esclusivamente** strumenti Linux standard, senza reverse engineering del binario:
> - `readelf` ha mostrato che il programma importa la funzione `posix_spawn` (usata per avviare processi figli)
> - `strings` ha estratto le stringhe di testo leggibili dal binario
> - `strace` ha confermato che rbfeeder avvia processi figli in tempo reale
> - `ss`/`netstat` ha mostrato la connessione attiva al server AirNav

**Risultati:**

Dalle stringhe e dai simboli importati emerge che rbfeeder ha la capacità di ricevere comandi dal server via il protocollo proprietario ed eseguirli come shell di sistema. Le stringhe indicano un meccanismo strutturato: il server invia un comando, rbfeeder lo riceve (`"Expected CMD has arrived!"`) e lo esegue tramite `posix_spawn("/bin/sh", "-c", <comando>)`.

Stringhe chiave trovate:
- `"Run command: %s"`
- `"/bin/sh"`
- `"Expected CMD has arrived!"`
- `"posix_spawn: %s"`
- `"WaitCMD done!"`

Il programma attende in un loop permanente i comandi dal server. I comandi vengono eseguiti silenziosamente: **non vengono mai scritti nel file di log**.

**Connessioni attive confermate:**
- Connessione al server AirNav (`212.224.72.114:33755`)
- Connessione locale a dump1090 (porta 30005)
- Connessione locale al client MLAT

## 11. RIEPILOGO: CAPACITÀ DI ESECUZIONE REMOTA

Dai simboli importati e dalle stringhe del binario rbfeeder risulta che:

- Il server ha la capacità di **eseguire comandi su ogni rbfeeder connesso**
- Nella **v0.3.5** (installata sul Pi): i comandi vengono eseguiti con compromissione totale del sistema
- Nella **v1.0.15** (ultima versione): i comandi vengono eseguiti come utente dedicato `rbfeeder` , mitigato ma comunque significativo
- Non risulta alcuna validazione o firma dei comandi ricevuti
- La v0.3.5 **non usa crittografia** sul canale di comunicazione
- Un attaccante che intercetti il traffico di rete potrebbe iniettare comandi (attacco man-in-the-middle)


## 12. RBFEEDER: DIFFERENZE TRA VERSIONI

La versione v1.0.15 (la più recente) presenta alcune differenze significative rispetto alla v0.3.5 installata sul mio Pi:

- Gira come utente dedicato `rbfeeder` invece che come root
- Usa un formato di comunicazione più strutturato
- Il pacchetto di installazione contiene **codice anti-malware** che cerca e rimuove attivamente i file della campagna transponderlive

Quest'ultimo punto è particolarmente significativo: il post-install della v1.0.15 cerca specificamente i file e processi del malware transponderlive e li rimuove.

Tuttavia, **il meccanismo di esecuzione comandi remota rimane presente** anche nella v1.0.15: la capacità c'è ancora, solo con privilegi ridotti.


## 13. CONCLUSIONE

Quattro ipotesi principali con una supposizione comune:

> Il meccanismo di esecuzione comandi remota è una **FUNZIONALITÀ INTENZIONALE** di rbfeeder, non una vulnerabilità scoperta da terzi.

**Ipotesi 1:** AirNav Systems (RadarBox) lo ha fatto di proposito *(lo escludo a priori)*

**Ipotesi 2:** Qualcuno ha compromesso l'infrastruttura RadarBox e, trovando questa capacità di esecuzione remota, l'ha sfruttata per distribuire il malware

**Ipotesi 3:** Un dipendente o collaboratore di AirNav, conoscendo il sistema dall'interno, ha abusato dell'accesso per creare una campagna parallela di intercettazione dati ADS-B

**Ipotesi 4:** La comunicazione tra rbfeeder ed il server avviene senza una connessione sicura. Qualcuno potrebbe aver compromesso il server DNS cambiando l'IP, facendo arrivare le connessioni su un server fake che a sua volta ha usato l'RCE presente nel sistema (che non include alcuna protezione)

---

### Parere personale

Il meccanismo di esecuzione comandi è stato senza dubbio inserito da AirNav. Forse volevano un canale di gestione remota per i loro dispositivi, ma così facendo hanno creato una backdoor su tutti i device di inconsapevoli utenti.

**AirNav È CONSAPEVOLE della campagna malware**, la prova è nel fatto che le versioni successive del loro software contengono codice specifico per cercare e rimuovere il malware transponderlive. Questo dimostra che conoscono il problema, ma non hanno mai avvisato gli utenti (io non ho mai ricevuto alcuna email di avviso).

La campagna RAT sembra colpire anche RadarCape e KiwiSDR, il che fa pensare che abbiano accesso anche ad altri dispositivi.

Consiglio : Se hai uno di questi software che girano su qualche dispositivo, dai un'occhiata a cosa sta girando... ;-) 