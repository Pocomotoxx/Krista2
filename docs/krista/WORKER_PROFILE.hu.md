# A kapu kötelezővé tétele: Ruflo munkásprofil és gépszintű házirend

Állapot: **megépítve és mérve, külön ágon (`claude/worker-profile`), nincs beolvasztva.** A leltár B-06 pontját (a munkás a
bővítmény nélkül is elindulhat) két rétegben zárja le, a B-02 (önmódosítás) és a B-03 (hibára engedés) mellett.

## Két réteg, két feladat

| | **B réteg: Ruflo munkásprofil** | **A réteg: gépszintű házirend (Claude Code kezelt beállítások)** |
| --- | --- | --- |
| Mit kényszerít | a Ruflo által indított munkás megkapja a `krista-gate` bővítményt | minden `claude` folyamat a gépen megkapja a kaput, akárhogy indult |
| Hol él | a fork kódjában (`headless-plugins.ts` és a hívóhelyek) | `/etc/claude-code/managed-settings.json` (Linux) |
| `none` és hiányzás | nem kapcsolhatja ki, nem engedi tovább: a munkás el sem indul (`RequiredPluginError`) | nincs bővítmény, amit ki lehetne hagyni |
| Mire nem jó | nem véd egy másik hook bemenet-átírása ellen; csak a Ruflo útvonalait fedi | az egész gépre érvényes, a Ruflo saját hookjait letiltja (`strict`) |
| Ajánlott | ha a gépet másra is használod, és csak a Ruflo-t kell kötelezni | **dedikált gépen, konténerben vagy VM-ben, ahol az ügynök fut** |

### B réteg: mit változtattam a Ruflo kódjában (a fork `claude/worker-profile` ága)

- `mods/headless-plugins.ts`: a `KRISTA_GATE_PLUGIN_DIR` (az indító adja, **nem** a projekt) kötelező: üres, relatív, hiányzó,
  más nevű vagy `hooks/hooks.json` nélküli mappa esetén `RequiredPluginError`-t dob, **mielőtt bármi elindulna**. A kötelező
  bővítmény a profiltól függetlenül mindig hozzáadódik, `none` mellett is, és nem duplikálódik.
- `commands/hive-mind.ts`: a staging az interaktív ágban is lefut (`requiredOnly`: csak a kapu, a felhasználó profilja marad).
- `commands/hive-mind-worker.ts` és `services/headless-worker-executor.ts`: a hibás kapu sikertelen eredménnyé alakul, nem indul folyamat.
- `plugins/ruflo-testgen/scripts/tdd-repair/tdd-repair.mjs`: szerkeszthet és `Bash`-t futtathat, a staging mellett elment, ezért most ő is kapu nélkül megtagadja az indulást.
- **Felületvizsgálat teszttel:** minden `claude`-t indító termékkód vagy stagel, vagy dokumentált kivétel (a `fable-harness` eszköz nélküli bírálóhívás,
  a `headless-check` önteszt, két `claude plugin` validáló szkript). Egy új, stagelés nélküli indítóhely elbuktatja a tesztet.

### A réteg: a házirend

`bin/managed.py` három parancsot ad: `install-tree` (a kaput és a rögzített KRISTA-fájlokat védett helyre másolja), `install`
(a házirendet kiírja, nem ír felül meglévőt, és megtagadja a nem védett kapufát) és `check` (ellenőrzi, hogy a telepített házirend valóban kikényszerít).
A `strict` profil beállítja: a kapu `PreToolUse` hookját a hibára tiltó burkolóval, `allowManagedHooksOnly: true`-t és
`permissions.disableBypassPermissionsMode: "disable"`-t.

## Mérés

- **78 egységteszt** a bővítménymappában, köztük a **valódi, javított `headless-plugins.ts`** futtatása Node-dal (a két testvér-importot kicsinyítve).
- **Mutációs ellenőrzés:** a staging 12 és a `managed.py` 17 mutánsából mind elbukik. (A mutációs szkriptem előbb egy elavult bájtkód miatt
  megbízhatatlan volt; kijavítottam, és kétszer lefuttattam.)
- **14 élő próba valódi Claude Code-ban** (`tests/live/managed_probe.py`), a házirend csak a próba gyermekfolyamatának saját csatolási névterében látszik:

| Próba | Eredmény |
| --- | --- |
| kapu bővítmény nélkül, csak a házirendből | **blokkolt** (`G-PATH`) |
| érvényes írás | átment (`G-OK`) |
| bypass mód házirend nélkül (kontroll) | az írás létrejött |
| bypass mód a házirenddel | **megtagadva**, az írás nem jött létre |
| projekt `disableAllHooks` és `--settings disableAllHooks` | a kapu **tovább blokkol** |
| bemenet-átírás kontroll (házirend nélkül) | az átírt parancs lefutott |
| **bemenet-átírás `coexist` mellett** | **a kapu megkerülve: az `ls`-t a másik hook `touch`-ra írta át, és az lefutott** |
| bemenet-átírás `strict` mellett | **blokkolva** (a projekt-hookok nem futnak) |
| altevékenység | örökli a kaput |
| Ruflo munkáskörnyezet | kapus |
| érvénytelen házirend | a munkamenet **el sem indul** (`exit 1`) |
| hibás kapu-útvonal | **blokkol** (a burkoló) |
| plugin-hook `strict` / `coexist` mellett | `strict`: 0 futás, `coexist`: 1 futás |

## A legfontosabb új eredmény: a `coexist` profil megkerülhető

A Claude Code dokumentációja szerint több hook döntése közül a `deny > defer > ask > allow` sorrend számít, vagyis egy másik hook `allow`-ja
nem írhatja felül a tiltást. A hookok **bemenet-átírását** (`updatedInput`) viszont a dokumentum nem szabályozza több hook esetén,
és a mérés megmutatta a következményt: a kapu az eredeti `ls`-t látta és engedte, a másik hook átírta, és az **átírt** parancs futott le.
Ezért a gépszintű házirend **csak `strict` profillal** kapható; a `coexist` kiírását csak `--allow-unsafe` mellett engedi.
Ugyanez a rés a B rétegre is áll: ha a munkás környezetében egy másik hook átírja a bemenetet, a bővítménybeli kapu nem látja.

## Korlátok (kimondva)

- **A házirend az egész gépre érvényes**, projektenként nem szűkíthető. Ha a saját interaktív munkádat is ugyanazon a gépen végzed, azt is a kapu fogja
  (rekord nélkül írás nincs). Dedikált gépet, konténert vagy VM-et ajánlok.
- **`strict` mellett a Ruflo saját hookjai és a bővítmény-hookok nem futnak** (útválasztás, memória-szinkron, állapotsor), mert a házirend csak a kezelt hookokat engedi.
- **A kapu védelme annyit ér, amennyire védett a mappája és a házirendfájl.** Az `install` megtagadja az olyan fát, amit az ügynök felhasználója írhat; a gyökér tulajdonlása a telepítés dolga.
- **B réteg:** az indító környezetétől függ (a változó beállítása), csak a fork Ruflo-útvonalait fedi, és nem véd bemenet-átírás ellen.
- **Nem mértem:** az `"onFailure": "block"` hookbeállítást (a burkoló ugyanezt tudja, mérten), a macOS-t és a Windowst (a házirendfájl útvonala más, a burkolóhoz `/bin/sh` és GNU `timeout` kell), a tmux-os csapattagot.
- **Verzió:** egyetlen Claude Code-verzió (2.1.314), Linux, `root`, fejetlen mód.
