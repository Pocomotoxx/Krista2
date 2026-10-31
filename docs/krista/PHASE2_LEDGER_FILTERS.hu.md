# 2. fázis: helyi napló, döntési események, bemeneti és kimeneti szűrő

Ez a fázis a `krista-gate` bővítményt egészíti ki. Az 1. fázis azt dönti el, hogy egy hívás **megengedett-e**; a 2. fázis azt,
hogy **mi kerülhet be a modellbe és mi mehet ki belőle**, és mindezt **hash-láncolt naplóba** írja.

## Mi változott

| Elem | Fájl | Mit tesz |
|---|---|---|
| Helyi napló | `plugins/krista-gate/bin/krista_ledger.py` | A KRISTA `runtime_ledger` formátumával azonos, hash-láncolt JSONL (`gate`, `ingress`, `egress`, `decisions`). Írás közben `flock`, így párhuzamos hookok nem ágaztatják el a láncot. |
| Szűrők | `plugins/krista-gate/bin/krista_filters.py` | A rögzített KRISTA `repo_scan` és `redaction` alakfelismerői (hitelesítő adatok; magyar azonosítók: e-mail, telefon, adó- és TAJ-szám, IBAN, bankszámla) és a KRISTA-rekordok előállítása. |
| Kapu | `plugins/krista-gate/bin/krista_gate.py` | `Read`, a promptot (`UserPromptSubmit`) és a `Stop` eseményt is szűri; az írás, a `git add`, a `git commit -m`, a hálózati és MCP bemenetek kimeneti szűrést kapnak. Minden döntés naplóba kerül. |
| Hookok | `hooks/hooks.json`, `bin/managed.py` | A mátrix kiegészült `Read\|NotebookRead`-del; `UserPromptSubmit` és `Stop` ugyanazzal a fail-closed burkolóval fut. A `managed.py check` mindhárom eseményt ellenőrzi. |
| Rögzítés | `krista/` (17 fájl) | A döntési események, a bemeneti/kimeneti rekordok sémái és validátorai is a rögzített, digesttel védett másolatból jönnek. |

## Bemeneti szűrő

* Egy hook **nem tud maszkolni**, csak egy egységet teljesen beengedni (`ADMITTED`) vagy visszatartani (`WITHHELD`).
* `Read`/`NotebookRead` és a tartalmat olvasó parancsok (`cat`, `head`, `tail`, `grep`, `wc`): a fájlt a kapu beolvassa és
  átnézi. Találat esetén a hívás letiltva (`G-INGRESS`); a modell a fájl tartalmát nem kapja meg.
* Bináris fájl: `UNVERIFIABLE` rekord, a hívás átmegy (nincs mit átnézni). Túl nagy fájl (alap 2 MiB): visszatartva, mert nem ellenőrizhető.
* A felhasználó promptja: hitelesítő adat vagy azonosító esetén a prompt **nem jut el a modellhez** (0 kör, 0 költség).
* A hibaüzenet kategóriát és darabszámot mond (`github-token x1`), értéket soha.

## Kimeneti szűrő

* `Write` (`content`), `Edit` (`new_string`), `MultiEdit` (minden `new_string`), `NotebookEdit` (`new_source`): az útvonal-ellenőrzés
  **után** nézi át a tartalmat. Találat: `G-EGRESS`.
* `git add`: a fájl tartalma; `git commit -m`: az üzenet.
* Engedélyezett `WebFetch`/`WebSearch` és MCP-eszköz: a bemenete. (Az engedélyezés előbb jön, mint a szűrés.)
* `Stop`: az utolsó asszisztensválasz szövege. A hook **nem tudja visszavonni** a már megjelent szöveget; azt tudja, hogy a modellt
  egyszer javításra kéri (`stop_hook_active` megakadályozza a végtelen ciklust), és naplózza a találatot.

## Beállítás (az indító adja, nem az ügynök)

| Változó | Jelentés |
|---|---|
| `KRISTA_RUNTIME_LOG_ROOT` | Abszolút könyvtár **a projekten kívül**; 0700, nem lehet mindenki által írható. |
| `KRISTA_LEDGER_REQUIRED=1` | Napló nélkül egyetlen hívás sem megy át (`G-LOG`). |
| `KRISTA_FILTER_PII=off` | A magyar azonosítók szűrését kikapcsolja; a hitelesítő adatok mindig blokkolnak. |
| `KRISTA_FILTER_ALLOW_PATHS` | Kettősponttal elválasztott minták: ezeket nem nézi át (tesztadatok); a napló `allowlist` szabályt jegyez. |
| `KRISTA_FILTER_MAX_BYTES` | A beolvasható fájl felső mérete. |

Ha a napló be van állítva (vagy kötelező), és nem írható, az **engedélyezés tiltássá** válik (`G-LOG`). A tiltás tiltás marad. A
`Stop` eseményt naplóhiba nem blokkolja, mert az csak ciklust okozna.

## Napló

* `gate.jsonl`: `gate_decision` (esemény, eszköz, döntés, kód, `permission_mode`, session- és tool-use-hivatkozás, a munkamenet-rekord
  digestje) és `session_record_changed` (amikor a rekord digestje megváltozik). Soha nem tartalmaz parancsot, útvonalat vagy tartalmat.
* `ingress.jsonl`, `egress.jsonl`: a KRISTA saját `ingress-sanitization-record` / `egress-sanitization-record` rekordjai, a rögzített
  validátorral ellenőrizve, `assurance_level: DECLARED`, `limitation` mezővel (a detektor heurisztika).
* `decisions.jsonl`: döntésértékelési események. `krista_ledger.py append-decision` csak akkor ír, ha a **teljes** értékelési folyam
  (D1–D8) továbbra is érvényes; a KRISTA `runtime_ledger.verify_ledger` és a bővítmény `verify` parancsa egymás fájljait is ellenőrzi.
* `krista_ledger.py verify|tail|append-decision --root <könyvtár>`.

## Mérés

* 119 egységteszt (`python3 -B -m unittest discover -s tests`). Köztük: lánc-hamisítás öt módja, 6 párhuzamos író × 10 rekord, a KRISTA
  `runtime_ledger` és a bővítmény kölcsönös ellenőrzése, mind a nyolc rekordalak a rögzített validátoron, az érték sehol sem szerepel.
* Mutációs ellenőrzés (minden `raise Denied/LedgerError` törlése): kapu 44/44, napló 17/17, `managed.py` 18/18 elfogva.
* Élő próba (`tests/live/phase2_probe.py`, Claude Code 2.1.314, root, `-p`): 7/7.
  Olvasás tiltva és a titok nem jut a modellhez; tiszta olvasás átmegy; összefűzött titok írása `G-EGRESS`; titkos prompt 0 körrel megáll;
  napló íródik és ellenőrizhető, a gyökér a projekten kívül van; kötelező napló gyökér nélkül tilt; `Stop` jelzi a megjelent titkot, a második
  körben (`stop_hook_active`) átengedi. Az 1. fázis (12/12) és a gépszintű (13 + 1 mért) próbák változatlanul átmennek.

## Mérési megfigyelések, amik a határt jelölik

1. A letiltott prompt szövegét a Claude Code **visszaírja a saját `result` mezőjébe** (a felhasználónak, nem a modellnek).
2. A letiltott hívás bemenete a `permission_denials` mezőben marad a parancssori kimenetben (szintén nem a modellnek, nem a naplónak).
3. A `Stop` hook **csak utólag** jelez; a megjelent szöveget nem lehet visszahívni.
4. A szűrő **alakot** keres. Név, cím, szabad szöveges személyes adat, ismeretlen alakú titok nem akad fenn. Egy 12 karakternél hosszabb
   `ghp_`-előtagú darab már hitelesítő adatnak számít, a rövidebb nem; aki darabolva adja át, az összefűzés kimeneténél akad fenn.
5. `git show` / `git diff` kimenetét nem szűri (nem fájlt nyit meg, hanem a tárolót olvassa).
6. Egy környezet (Claude Code 2.1.314, Linux, root, fej nélküli mód); macOS és Windows nincs mérve.

## Nincs még meg

* A folyamat-szintű (nem csak naplózás) döntésértékelési rekord automatikus előállítása: a naplóba ma `append-decision` írja a kész eseményeket.
* Aláírás: a `krista-receipt-signing` és `krista-log-signing` környezet nincs beállítva, így a napló lánca sértetlenséget bizonyít, eredetet nem.
