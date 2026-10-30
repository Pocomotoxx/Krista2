# KRISTA-kapu, 1. fázis: útvonal-, művelet- és nyitott-kérdés ellenőrzés

Állapot: **megépítve és mérve, külön ágon (`claude/phase1-gate`), nincs beolvasztva.** A kapu egy Claude Code
bővítmény (`plugins/krista-gate`), amely a Ruflo hookfelületén dolgozik, de attól függetlenül is betölthető.
A KRISTA-ból csak egy rögzített pillanatképet használ (`krista/`, a forráscommit: `krista/PINNED_COMMIT`).

## Mit csinál

A kapu minden `Bash`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `WebFetch`, `WebSearch` és `mcp__*` hívás
előtt lefut, és a **vibe-code munkamenet-rekord** alapján dönt. Hívásonként újraolvassa a rekordot, így egy
megválaszolt kérdés újraindítás nélkül feloldja a kaput.

| Kód | Mikor tilt |
| --- | --- |
| `G-NOREC` | nincs rekord, nem olvasható, nem érvényes JSON, vagy a KRISTA validátora szerint érvénytelen |
| `G-OPENQ` | blokkoló nyitott kérdés van (vagy hibás bejegyzés); olvasás ilyenkor is megy |
| `G-ACT` | a rekord nem engedi az `edit`, `test`, `commit` vagy `push` műveletet, vagy `PLAN_ONLY` |
| `G-PATH` | az útvonal a projekten kívül van, vagy nincs az `allowed_paths`-ban (szimbolikus link feloldva) |
| `G-FORB` | az útvonal a `forbidden_paths`-ban van |
| `G-PROT` | védett útvonal: `.claude/**`, `.git/**`, `krista/**`, a kapu mappája, `CLAUDE.md`, `AGENTS.md`, `.mcp.json`, titokfájl |
| `G-BRANCH` | alapág, vagy a kiolvasott ág eltér a rekord `target.branch`-étől |
| `G-BASH` | a parancs nem csak olvas, és a rekord nem deklarálja szó szerint |
| `G-GIT` | nem engedett git-forma (csak olvasó parancsok, `add <fájl>`, `commit -m`, `push [-u] <remote> <ág>`) |
| `G-NET`, `G-MCP` | hálózat vagy MCP-eszköz külön engedély nélkül |
| `G-PIN` | a rögzített KRISTA-másolat megváltozott vagy hiányzik |
| `G-ERR`, `G-TOOL` | a kapu hibázott, vagy ismeretlen eszköz: ilyenkor is tilt |

A bash nincs útvonalra elemezve (nem is lehet megbízhatóan): vagy egyszerű, csak olvasó parancs, vagy a rekord
`test_receipts[].command` / `reproduction.repro_command` mezőjében szó szerint deklarált, vagy szűk `git` forma.

## Használat

1. Az **indító** (ember vagy keretrendszer) a munkaterületen **kívül** írja a rekordot, és beállítja:
   `KRISTA_SESSION_RECORD=<abszolút útvonal>`. Opcionális: `KRISTA_GATE_NETWORK=1`, `KRISTA_GATE_MCP_ALLOW=<minta,...>`,
   `KRISTA_GATE_PROTECTED=<minta:minta>`, `KRISTA_GATE_LOG=<útvonal>` (csak metaadat: eszköz, döntés, kód).
2. A bővítményt a Claude Code betölti (`--plugin-dir plugins/krista-gate`, vagy telepítve).
3. Rekord nélkül a kapu csak olvasó parancsokat enged, írást nem.

## Mérés

- **48 egységteszt** (`python3 -I -m unittest discover -s plugins/krista-gate/tests`), köztük a KRISTA validátorával való
  keresztellenőrzés arról, mi számít blokkoló kérdésnek.
- **Mutációs ellenőrzés:** a kapu mind a 35 tiltó ágát egyenként kitörölve mindegyiket elkapják a tesztek. Ez két valódi hibát
  hozott felszínre: a burkoló `sh`-t `PATH`-ból kereste (hiányos `PATH` mellett `127`-tel átengedett, ezért `/bin/sh`), és a
  `git rev-parse` commit nélküli friss repóban hibázott, így az alapágvédelem csendben kimaradt (most `symbolic-ref`).
- **12 élő próba valódi Claude Code-ban** (`tests/live/live_probe.py`), fájl-jelölővel mérve:
  nincs rekord, érvényes rekord, engedélyezett körön kívül, **hook-beállítás írása `bypassPermissions` alatt**, blokkoló kérdés,
  alapág, nem deklarált és deklarált bash, **bypass mód nem kerüli meg**, **MCP-shell**, kérdés megválaszolása, megváltoztatott rögzítés.
  Mind 12 az elvárt kóddal és hatással zárt.

Ezzel a leltár két kritikus rése (B-01 MCP-shell, B-02 önmódosítás bypass alatt) a kapun át le van zárva, **ha a bővítmény be van töltve**.

## Korlátok (kimondva)

- **Betöltés:** ha a bővítmény nincs betöltve, nincs kapu. A Ruflo munkásprofilja hiányzó bővítménynél csak figyelmeztet, és a
  `RUFLO_HEADLESS_PLUGINS=none` kikapcsol mindent (B-06). **Ennek lezárása a következő lépés:** kezelt/felhasználói szintű
  regisztráció és a munkásindítás tiltása a bővítmény nélkül. Ez a fázis még nem köti be a Ruflo munkásprofiljába.
- **A rekord bizalmi bemenet.** A kapu a szerkezetét ellenőrzi, nem az igazságát. Az `AUTHORIZED_WRITE` emberi jóváhagyása a rekordon kívül
  van; a kapu a két írási módot egyformán kezeli.
- **A deklarált parancs** szó szerint fut, és azt tehet, amit a szerzője beleírt.
- **Nem korlátoz olvasást** (`Read`, `Glob`, `Grep`), és nem néz fájltartalmat.
- **Platform:** a burkoló `/bin/sh`-t és GNU `timeout`-ot kíván (Linux; macOS-en `gtimeout`, Windowson nincs). Hiányuk esetén **minden** hívást tilt (biztonságos, de használhatatlan).
- **Verzió:** egy Claude Code-verzión (2.1.314), `root` felhasználóval, fejetlen módban mérve.
- A rögzített másolat sérthetetlenség-jelzés, nem biztonsági határ.

## Mi következik

2. fázis: naplózás (helyi napló, döntési események), bemeneti és kimeneti szűrő a határon.
Előtte vagy mellette: a gate bekötése a Ruflo munkásprofiljába és a megkerülések (hiányzó bővítmény, `none`, `--dangerously-skip-permissions`) lezárása.
