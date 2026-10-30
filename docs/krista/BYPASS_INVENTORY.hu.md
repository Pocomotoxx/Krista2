# Megkerülési leltár: Ruflo és a KRISTA-kapuk (0. fázis)

Állapot: **elemzés és élő próbák, nincs benne módosítás.** A statikus leltár után a hét próbát
lefuttattam (5. szakasz). Ez a leltár nem szabály és nem kapu. A KRISTA
változatlan marad; a leltár azt rögzíti, hol léphet át egy írás, hálózati hívás, push vagy
részfolyamat a Ruflo mai hookjain, hogy a KRISTA-bővítmény ezekre építhessen.

## 1. Hatókör és módszer

- **Vizsgált:** a `Pocomotoxx/Krista2` fork, a Ruflo 3.65.0 kiadása, commit
  `d000e27e82c783a5a188abb01d89b8ccbc12b271`, sekély klón.
- **Módszer:** csak statikus olvasás (beállítások, hook-szkriptek, CLI- és MCP-forrás).
  Semmit nem futtattam, nem telepítettem, és a repó utasításfájljait (`CLAUDE.md`,
  skillek, bővítmények) nem töltöttem be a munkamenetbe.
- **Nem vizsgált:** federáció, `agentbbs`, a böngészőeszközök belseje, a Rust-crate-ek,
  a WASM, a `chatgpt-plugin`, a telepítőszkriptek, a Windows-utak és a Codex-gazda.
- **Jelölés:** **[kód]** = a kódból közvetlenül olvasott, **[mérve]** = élő próbával igazolt (5. szakasz).

## 2. Összefoglaló

| Azonosító | Súly | Megállapítás | Érintett KRISTA-kapu |
| --- | --- | --- | --- |
| B-01 | kritikus | Az MCP `terminal_execute` tetszőleges shellt futtat, előre engedélyezett, a `PreToolUse` nem látja. | művelet-lista, védett útvonalak, szűrők, napló |
| B-02 | magas, módfüggő | Írásra nincs `PreToolUse`; jogosultságot kihagyó módban a hook-beállítás felülírható. | védett útvonalak, önmódosítás tilalma |
| B-03 | magas | Hibára engedő: Claude Code-ban csak az `exit 2` blokkol; a Ruflo hookja is `exit 0`-val enged hibán. | minden kapu fail-closed elve |
| B-04 | magas | Az engedélylista (`node:*`, `npx:*`, `git push`, `git config:*`) kijátssza a parancsszintű védelmet. | művelet-lista |
| B-05 | magas | Rögzítetlen kód fut: `npx -y ruflo@latest`, `@claude-flow/cli` `@latest`, piactér-klón. | revízióhoz kötés, ellátási lánc |
| B-06 | magas | Négy helyen indul gyermek `claude`-folyamat; a hive-mind kihagyhatja a jogosultságot. | minden kapu a munkásokon |
| B-07 | közepes | Háttérautonómia: démonok, `auto-commit.sh`, `git reset --hard`, tanulás, ügynökcsapatok. | kernel: nincs háttérfutás, nincs memória-előléptetés |
| B-08 | közepes | Nem kért hálózati kapcsolat és távoli tartalom (`funnel.ruv.io`, `flow-nexus`). | „nincs rejtett hálózati hívás” |
| B-09 | közepes | A saját MCP-policy állítása ellentmond a kódnak; a kikényszerítés opt-in és részleges. | DECLARED és kikényszerített különbsége |
| B-10 | közepes | Két hookmechanizmus, eltérő lefedettséggel és hibaviselkedéssel. | a bővítmény elsődleges illesztési pontja |
| B-11 | közepes | A függvény-hook modok betöltése szerveroldali kapcsolótól függ, és a `.catch` nélküli mod hibára enged. | a bővítmény megbízhatósága |

## 3. Részletek

### B-01 MCP-shell, amit a `Bash`-hook nem lát (kritikus) [kód]
- `terminal_execute` (`v3/@claude-flow/cli/src/mcp-tools/terminal-tools.ts:140`) a megadott
  parancsot `execSync`-kel futtatja (sor 203), a teljes környezettel.
- A `terminalTools` feltétel nélkül regisztrált (`src/mcp-client.ts:161`), mellette a
  `githubTools` (164) és az `httpFetchTools` (200).
- A `.claude/settings.json` `permissions.allow` listája előre engedi a
  `mcp__claude-flow__*`, `mcp__ruv-swarm__*`, `mcp__flow-nexus__*` mintát, tehát nincs kérdés.
- A `PreToolUse` egyetlen illesztője a `Bash`. Az MCP-hívás elkerüli.
- **Kezelés:** a KRISTA-kapu illeszkedjen `mcp__.*`-ra is; a profil tiltsa a `terminal_*`,
  `github_*`, `http_fetch`, `browser_*` eszközöket; a `mcp__*__*` engedélyezés szűnjön meg.

### B-02 Önmódosítás védelem nélkül (kritikus) [kód]
- A klasszikus hookbeállításban (`settings.json`) a `PostToolUse` illeszti a `Write|Edit|MultiEdit`-et
  (`post-edit`), de az utólagos, nem blokkolhat. `PreToolUse` nincs írásra, `NotebookEdit`-re,
  `WebFetch`-re, `WebSearch`-re és az ügynök-indításra. (A függvény-hook mod ennél többet lát, lásd B-10.)
- A hook-szkriptek (`.claude/helpers/*.cjs`) és a beállítás a munkaterületen vannak
  (`$CLAUDE_PROJECT_DIR`).
- **[mérve, T-3]** Alapmódban, `allowedTools` mellett és `acceptEdits` módban a Claude Code saját
  védelme megtagadta az írást a `.claude/settings.json`-ba és a `.claude/helpers/` alá. **Jogosultságot
  kihagyó módban (`bypassPermissions`, a hive-mind `--dangerously-skip-permissions` útja) a
  `settings.json` felülírása átment**, `Bash`-illesztőjű hook mellett. Egy `Write|Edit|MultiEdit|NotebookEdit`
  illesztőjű `PreToolUse` hook ebben a módban is blokkolt.
- A `SessionStart`-kor futó beállítás-kockázat szkenner tanácsadó: a kód megjegyzése szerint nem
  módosítja a beállítást és nem blokkolja az indítást (`hook-handler.cjs:448` környéke).
- **Kezelés:** a KRISTA-kapu védje a `.claude/**`, a bővítménymappák és a git-hookok útvonalát
  `Write|Edit|MultiEdit|NotebookEdit` illesztővel (mérve: működik); a hook-regisztráció
  felhasználói vagy kezelt szintre kerüljön, ne a projektbe.

### B-03 Hibára engedő klasszikus hook (magas) [kód]
- `.claude/helpers/hook-handler.cjs`: a globális időzítő 5 s után `process.exit(0)` (739–742),
  a hibás bemenetet figyelmen kívül hagyja (751), a `main().catch` csak figyelmeztet, és a
  `finally` `exit(0)`-val zár (1267–1271). Csak az explicit tiltó ág lép ki `2`-vel (1118).
- A kód saját megjegyzése (893–894) elismeri, hogy egy korábbi hiba „csendben `exit 0`-val
  átengedte a veszélyes parancsot”.
- A `pre-bash` tiltólistája négy minta (896): `rm -rf /`, `format c:`, `del /s /q c:\`, fork-bomba.
- **[mérve, T-4]** A Claude Code maga is így viselkedik: összeomló hook (`exit 1`), időtúllépés (a hook
  megölve), hiányzó `node`-szkript (`exit 1`) és hiányzó program (`127`) mind **átengedte** a hívást.
  Egyetlen eset blokkolt, véletlenül: a hiányzó `python3`-szkript `exit 2`-t ad.
- **[mérve, T-4r]** A Ruflo tényleges `pre-bash` hookja (elszigetelt másolaton, csak bemenettel): a
  `rm -rf /` `exit 2`; a `node -e` törlés, a `curl … | sh`, a `git push --force origin main`, a hibás JSON
  és a nyers, nem JSON bemenet mind `exit 0`.
- **Kezelés [mérve, T-4w]:** a KRISTA-hook burkolóval fut: `sh -c 'timeout 2 "$@"; [ $? -eq 0 ] || exit 2' _ <hook>`.
  Ezzel az összeomlás, az időtúllépés és a hiányzó program is blokkol, a rendben lévő hook átmegy.

### B-04 Az engedélylista kijátssza a parancsszűrést (magas) [kód]
- Engedett: `Bash(node:*)`, `Bash(npx:*)`, `Bash(git push)`, `Bash(git commit:*)`,
  `Bash(git config:*)` (átállíthatja a git-hookok útvonalát), `Bash(git checkout:*)`.
- Tiltott: csak `Read(./.env)`, `Read(./.env.*)` és `Bash(rm -rf /)`.
- Bármely `node -e`/`npx` hívás tetszőleges kódot futtat, így a parancsmintás védelem nem határ.
- **Kezelés:** alapértelmezett tiltás; a KRISTA művelet-lista a munkamenet-rekordból jön, nem
  regexből.

### B-05 Rögzítetlen futó kód (magas) [kód]
- `settings.json`: `mcpServers.claude-flow = npx -y ruflo@latest mcp start`: minden munkamenet a
  legfrissebb kiadást futtatja. A hook tartaléka `npx --prefer-offline --prefix … @claude-flow/cli`
  (`cliSpawnArgs`, `hook-handler.cjs` ~300–306).
- A `ruflo` piactér a `ruvnet/ruflo` GitHub-repóból klónozódik az első használatkor
  (`extraKnownMarketplaces`), és a `ruflo-mods`, `ruflo-swarm`, `ruflo-console` engedélyezett.
- A bővítmény-megbízhatóság a README szerint alapértelmezetten megfigyelő (`observe`; a mondat a
  vágott kivonatban csonka); a `refuse-risky` opt-in.
- **Kezelés:** rögzített verzió és lockfile, offline tükör, `modTrust = refuse-risky` felhasználói
  szinten engedélylistával.

### B-06 Gyermek `claude`-folyamatok (magas) [kód]
- `commands/hive-mind.ts:296–302`: a `--dangerously-skip-permissions` átadódik a gyermeknek,
  ha a kapcsolót megadják.
- `services/headless-worker-executor.ts:1423`: a démon-munkások `claude --print`-et indítanak a
  projektgyökérben, `CLAUDE_ENTRYPOINT=worker` és eltávolított munkamenet-jelzők mellett,
  kényszerített függvény-hookokkal. Ebben a fájlban nincs saját jogosultsági mód vagy eszközkorlát,
  így a projekt-engedélylistát öröklik.
- Továbbá `services/fable-harness.ts:210` és `mods/headless-check.ts:67`.
- A munkások bővítményprofilja `RUFLO_HEADLESS_PLUGINS`, alapértelmezés `['ruflo-mods']`
  (`mods/headless-plugins.ts:25,54`).
- **[mérve, T-5]** A `--plugin-dir` bővítmény hookja fejetlen (`-p`) módban, a Ruflo munkáskörnyezetével
  (`CLAUDE_ENTRYPOINT=worker`, `CLAUDE_CODE_HEADLESS=true`) és `bypassPermissions` alatt is blokkolt.
- **[mérve, a valódi `withHeadlessPlugins` kód futtatva]** A `RUFLO_HEADLESS_PLUGINS=ruflo-mods,krista-gate`
  hozzáadja a bővítményt. **Hiányzó bővítménynél csak figyelmeztet, a munkás nélküle fut** (fail-open), és a
  `RUFLO_HEADLESS_PLUGINS=none` minden bővítményt kikapcsol.
- **Kezelés:** a KRISTA-bővítmény kerüljön a munkásprofilba; a hiányzását a munkásindítás előtt kelljen
  ellenőrizni (tiltás, nem figyelmeztetés); a `none` érték legyen tiltott; a jogosultságot kihagyó
  kapcsoló tiltott.

### B-07 Háttérautonómia (közepes) [kód]
- `daemon-manager.sh:70,92`: `nohup` démonok. `auto-commit.sh:71,84,98,140`: `git add -A`, `commit`,
  `push`. `checkpoint-manager.sh:133`: `git reset --hard` opció.
- A `SessionStart` első indításkor leválasztott folyamatokat indít és a `~/.ruflo/` alá ír
  (`hook-handler.cjs:348–`, kikapcsolható: `RUFLO_NO_AUTO_ENABLE`).
- A beállításokban: kísérleti ügynökcsapatok (`CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`),
  `trainPatternsOnComplete: true`, megosztott memória-névtér.
- Ütközik a kernel szabályaival (nincs háttérfutás; a memória felülvizsgálat nélkül nem lép elő).
- **Kezelés:** a profil kapcsolja ki; a helperszkriptek ne legyenek engedélyezett parancsok.

### B-08 Nem kért hálózat és távoli tartalom (közepes) [kód]
- A hook leválasztott `GET`-et indít a `https://funnel.ruv.io/v1/messages` címre
  (`src/funnel/message-transport.ts:48`); a tartalmat nem megbízhatónak kezeli, és ellenőrzi.
  Kikapcsolás: `RUFLO_FUNNEL_MESSAGES=0` vagy `RUFLO_FUNNEL=0` (27. sor).
- `.claude/mcp.json`: `flow-nexus` szerver, abszolút útvonal (`/workspaces/flow-cloud/…`) és
  `SUPABASE_URL`, `SUPABASE_ANON_KEY` környezet; a `mcp__flow-nexus__*` előre engedélyezett.
- **Kezelés:** kapcsoló beállítása, a `flow-nexus` eltávolítása, kimenő hálózati engedélylista.

### B-09 Állítás és kód eltérése (közepes) [kód]
- `.harness/mcp-policy.json` szerint az MCP-szerver eszközei „pure-data”, „nem nyers shell,
  hálózat vagy fájlrendszer”, és a három tiltott. A B-01 szerinti `terminal_execute`,
  `http_fetch`, `github_*` és böngészőeszközök ellentmondanak ennek.
- A kikényszerítő (`mcp-tools/policy-enforcer.ts`) opt-in (`RUFLO_MCP_ENFORCE_POLICY=1`, 21. és
  94. sor), és csak az auditnaplót és a hívásszám-korlátot érvényesíti; a `allowShell`,
  `allowNetwork`, `allowFileWrite`, `dangerousPatterns` mezők szándékosan nincsenek érvényesítve.
  Bekapcsolva hibára tiltó.
- **Tanulság:** a Ruflo saját „governance” fájlja deklarált szándék, nem kikényszerített
  szabály. A KRISTA ne támaszkodjon rá.

### B-10 Két hookmechanizmus (közepes) [kód]
- **Klasszikus parancs-hook** (`settings.json`): `PreToolUse` csak `Bash`; hibára engedő (B-03).
- **Függvény-hook mod** (`plugins/ruflo-mods/hooks/guard/`): a `tool.check` a `Bash`, `Write`,
  `Edit`, `MultiEdit`, `NotebookEdit`, `WebFetch`, `WebSearch` és `mcp__*` hívásokat is látja
  (`policy.ts:59–60,116`), és ha az ellenőrzés nem fut le, **kérdez** (`index.ts:12`). Feltétel:
  Claude Code ≥ 2.1.287 (vagy 2.1.277 a `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1` mellett).
- A bővítmények a felhasználó jogaival, sandbox nélkül futnak (README).
- Az opcionális `ruflo-protector` alapértelmezett módja a csendes tanulás (`learn`), magától nem
  kényszerít, és hibára engedő.
- **[mérve, T-7]** Egy saját, minimális `tool.check` mod (nem a Ruflo guardja) tiltása érvényesült
  `bypassPermissions` alatt is; a `deny` és az `ask` fejetlen módban egyaránt megtagadást jelent. A mod
  ötből ötször az első hívást is elkapta.
- **Kezelés:** a KRISTA-bővítmény elsődleges illesztése a függvény-hook, tartalékként a
  parancs-hook (a T-4w burkolóval), mindkettőn bizonyított blokkolással.

### B-11 A függvény-hook modok megbízhatósága (közepes) [mérve]
- A debug-napló szerint egy telepített bővítmény modulja csak akkor tölt be, ha egy szerveroldali
  bevezetési kapcsoló „bekapcsolt”-ra válaszol; különben a modul nincs betöltve, a hívások pedig
  mod nélkül mennek. Az egykörös futásban (`say ok`) a mod nem töltődött be; a tool-hívásos futásokban
  igen. A kapcsoló a környezettől függ, így a mod jelenléte nem garantált.
- **A `.catch` nélküli mod hibára enged:** a `tool.check` kezelő kivétele `.catch` nélkül átengedte a
  hívást, `bypassPermissions` alatt is. `.catch`-csel (ask-t visszaadva) a hívás megtagadva.
- A modulok sandboxban futnak: csak relatív útvonalú fájlokat és a `claude-code`-ot importálhatják, a
  `node:fs` nem érhető el, az `on(...)` értéke nem tárolható, csak láncolható. Egy mod tehát nem hív
  külső validátort közvetlenül.
- **Kezelés:** a KRISTA-kapu ne a mod egyedüli jelenlétére építsen: minden kezelő kapjon `.catch`-et,
  és a parancs-hook (T-4w burkolóval) maradjon a tartalék, ami a mod hiányában is tilt.

## 4. Amit a Ruflo jól csinál (átvehető minta)

- ADR-509/510: a klónozott projekt nem választhatja meg, melyik bővítménymappát tölti be a rendszer.
- A `tool.check` hibára **kérdez**, nem enged.
- Az `http_fetch` alapból blokkolja a belső és loopback címeket, és nem ad át hitelesítést.
- A MCP-policy kikényszerítő bekapcsolva hibára tilt.
- Őszinte kitételek: „conceptual flow, not a live trace”, a demók mintaadatok.

## 5. Élő próbák: eredmények

**Környezet.** Claude Code 2.1.314, Node 22.22, Linux, `root` felhasználó, fejetlen (`claude -p`) futás.
Minden próba külön, elszigetelt könyvtárban, saját, ártalmatlan hookokkal és egy saját minimális MCP-szerverrel
zajlott; a hatást fájl-jelölővel mértem (a parancs lefutott-e), nem a modell beszámolójával. A Ruflo kódjából
csak két pontot futtattam, elszigetelt másolaton, kizárólag bemenettel: a `pre-bash` hookot (T-4r) és a
`withHeadlessPlugins` függvényt (T-5).

| Próba | Eredmény | Mérés |
| --- | --- | --- |
| T-1 `exit 2` blokkol | **Igazolva** | Blokkolt `-p` módban előre engedélyezett paranccsal és `bypassPermissions` alatt is. Kontroll: engedő hook mellett a jelölő létrejött. |
| T-2 MCP-shell elkerüli a `Bash`-hookot | **Igazolva** | `Bash` illesztő mellett a `terminal_execute`-szerű MCP-hívás lefutott, a hook nem hívódott. `Bash\|mcp__.*` illesztővel blokkolt. |
| T-3 írás a hook-beállításba | **Igazolva, módfüggően** | Alap, `allowedTools` és `acceptEdits` módban a Claude Code saját védelme megtagadta. `bypassPermissions` alatt a `settings.json` felülíródott. `Write\|Edit\|…` hookkal ebben a módban is blokkolt. |
| T-4 hibás hook átenged | **Igazolva** | Összeomlás, időtúllépés, hiányzó `node`-szkript és hiányzó program: átengedett. A hiányzó `python3`-szkript véletlenül blokkolt (`exit 2`). Burkolóval (T-4w) minden hiba blokkol. A Ruflo hookja (T-4r): csak a `rm -rf /` blokkol. |
| T-5 munkás betölti a bővítményt | **Igazolva** | `--plugin-dir` hook blokkolt `-p`, munkáskörnyezet és `bypassPermissions` mellett. A Ruflo staging függvénye hozzáadja a bővítményt; hiányzó bővítménynél csak figyelmeztet, `none` mellett kikapcsol mindent. |
| T-6 altevékenység/csapattag örököl | **Igazolva** | Az altevékenység és a kísérleti ügynökcsapat tagja `Bash`-hívását a hook látta és blokkolta. A tmux/osztott paneles csapattag nem volt tesztelve. |
| T-7 `tool.check` tiltása érvényesül | **Igazolva, feltételekkel** | `deny` érvényesült `bypassPermissions` alatt is; `ask` fejetlenül megtagadás; `.catch`-csel összeomlás után tilt, `.catch` nélkül **átenged**. A betöltés szerveroldali kapcsolótól függ (B-11). A tesztelt mod saját minimális mod, nem a Ruflo guardja. |

**Korlátok.** Egyetlen Claude Code-verzió, `root` felhasználó, fejetlen mód; az interaktív felület, a Windows és a
Codex-gazda nem volt tesztelve. A T-7 ötszöri ismétlése csak a betöltés stabilitását mutatja ebben a környezetben,
a szerveroldali kapcsolót nem tudom befolyásolni. A modell-hívások száma kicsi, az eredmények a hook- és
engedélyrendszer determinisztikus viselkedését mérik, nem a modell döntését.

## 6. Javasolt alapértelmezett tiltó profil (javaslat, nincs alkalmazva)

- `permissions.allow`: csak olvasó `git` parancsok (`status`, `diff`, `log`) és `ls`; töröljük a
  `node:*`, `npx:*`, `git push`, `git config:*`, és az `mcp__*__*` mintákat.
- `permissions.deny`: `mcp__claude-flow__terminal_*`, `…github_*`, `…http_fetch`, `…browser_*`,
  `mcp__flow-nexus__*`.
- Környezet: `RUFLO_NO_AUTO_ENABLE=1`, `RUFLO_FUNNEL=0`, `RUFLO_MCP_ENFORCE_POLICY=1`; a
  `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS` ne legyen beállítva; `claudeFlow.agentTeams.enabled=false`.
- `mcpServers`: rögzített verzió; `modTrust = refuse-risky` felhasználói szinten, engedélylistán a
  KRISTA-bővítménnyel; a munkásprofil csak a KRISTA-bővítmény.

## 7. Következő lépés

A próbák lezárultak, az 1. fázis építhető. Tervezési szabályok a mérésekből:
1. A kapu `PreToolUse` hook, `Bash`, `Write|Edit|MultiEdit|NotebookEdit` és `mcp__.*` illesztővel.
2. A hook a T-4w burkolóval fut, így minden hiba blokkol.
3. Minden mod-kezelő kap `.catch`-et; a parancs-hook a tartalék.
4. A munkásprofil nem indulhat a KRISTA-bővítmény nélkül; a `none` tiltott.
5. Minden kapuhoz tartozik egy ilyen mérő próba, ami a blokkolást bizonyítja, nem csak a kódot.
