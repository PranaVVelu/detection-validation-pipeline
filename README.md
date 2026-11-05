# Detection Validation Pipeline

![Detection Validation](https://github.com/PranaVVelu/detection-validation-pipeline/actions/workflows/detect-test.yml/badge.svg)

**Detection-as-code with a real test step.** When a Sigma or KQL rule is added or changed, CI replays telemetry modeled on the rule's mapped Atomic Red Team test through a mock SIEM, then blocks the merge unless the rule fires on the attack and stays quiet on normal activity.

A rule that parses isn't necessarily a rule that works. Syntax linters can't tell you that a rule misses the abbreviated `-e` flag attackers really use, or that it also fires on every `-ExecutionPolicy`. This pipeline catches both.

## How it works

```mermaid
flowchart LR
    PR["PR adds or changes<br/>a Sigma or KQL rule"] --> D["discover_rules.py<br/>build job matrix"]
    D --> SIM

    subgraph Range["Isolated Docker range, one per rule, no internet"]
        SIM["simulate_atomic.py<br/>attack + benign telemetry"] --> SHIP["ship_events.py<br/>load rule, send events"]
        SHIP --> SIEM[("Mock SIEM<br/>evaluates rule")]
        SIEM --> VAL["validate_alert.py<br/>polls alerts, judges rule"]
    end

    VAL --> R{"Exit code"}
    R -->|0 PASS| G["Detection gate<br/>merge allowed"]
    R -->|1 FAIL| B["Merge blocked:<br/>fix the rule"]
    R -->|2 ERROR| E["Merge blocked:<br/>fix the pipeline"]
```

A rule passes only if all three checks hold for that specific run:

| Check | Catches |
| --- | --- |
| **Technique mapping** | A rule tagged with a different ATT&CK technique than its test exercises |
| **True positive** | A rule too narrow to fire on the attack |
| **No false positive** | A rule so broad it fires on the benign baseline |

The result is a clear exit code, so a broken log pipeline is never mistaken for a bad rule:

| Exit | Verdict | Meaning | Who acts |
| --- | --- | --- | --- |
| `0` | PASS | The rule behaved as expected | Nobody |
| `1` | FAIL | The rule is wrong | Rule author |
| `2` | ERROR | No trustworthy verdict: telemetry missing, SIEM down, or a rule the engine can't evaluate | Pipeline owner or rule author |

## Example output

From the included `fail_too_broad.yml` negative control:

```text
Rule: Negative control: too broad (00000000-0000-4000-8000-000000000002)
Test: T1059.001 PowerShell Command Execution (a538de64-1c74-46ed-aa60-b995ed302598)
  [PASS] Technique mapping: test exercises T1059.001; rule declares ['T1059.001']
  [PASS] True positive: 1 alert(s) on 2 attack event(s) from 'PowerShell Command Execution'
  [FAIL] No false positive: 1 alert(s) on 4 benign event(s)
      matched: powershell.exe -ExecutionPolicy RemoteSigned -File C:\Ops\inventory.ps1
RESULT: FAIL
```

## Quick start

You need Python 3.9 or later. Docker is only needed for `make validate-docker`.

```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

```bash
make setup
```

```bash
make test
```

```bash
make validate RULE=detections/kql/powershell_encoded_command.kql
```

```bash
make validate RULE=tests/fixtures/rules/fail_too_narrow.yml
```

The last command fails on purpose.

## Repository layout

```text
.github/workflows/detect-test.yml   CI: self-test, discover, validate (matrix), gate
detections/
  sigma/                            Sigma rules (*.yml, *.yaml)
  kql/                              KQL rules (*.kql)
game/                               FakeQuest, its test tool, the license server, and the abuse scenarios
simulation/catalog.yml              Test telemetry and the benign baseline
telemetry/sysmon-config.xml         Sysmon configuration for real runs
scripts/
  discover_rules.py                 Selects changed rules, builds the job matrix
  simulate_atomic.py                Generates telemetry for a rule's mapped test
  collect_real_telemetry.py         Runs a test on Windows and labels the real Sysmon logs
  ship_events.py                    Loads the rule and forwards events to the SIEM
  validate_alert.py                 Applies the pass criteria, returns the exit code
src/dvp/
  sigma_engine.py, kql_engine.py    Fail-closed rule evaluators
  rules.py, catalog.py              Rule and test loading
  siem.py, siem_server.py           Mock SIEM logic and REST API
tests/                              Unit tests, negative controls, end-to-end runs
docs/                               Architecture and implementation guide
Dockerfile, docker-compose.yml      Hardened, network-isolated test range
```

## Adding a rule

Every rule declares the Atomic test that proves it, by GUID because test numbers shift upstream.

**Sigma:** add a custom field.

```yaml
tags:
  - attack.t1059.001
x_atomic_test: a538de64-1c74-46ed-aa60-b995ed302598
```

**KQL:** add a comment header.

```kql
// @id: 9c3e1a72-5d08-4f6b-b1e7-40a8d2c6f915
// @title: PowerShell Launched With Encoded Command (Defender XDR)
// @techniques: T1059.001
// @atomic_test: a538de64-1c74-46ed-aa60-b995ed302598
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
```

**Game rules:** use `x_game_test` with the name of a test in the catalog, and add a matching script to `game/scenarios/`.

If the test isn't in [simulation/catalog.yml](simulation/catalog.yml) yet, add it there too.

## Simulated and real telemetry

The pipeline tests rules against two kinds of telemetry:

| | Simulated | Real |
| --- | --- | --- |
| **Workflow** | `detect-test.yml` | `real-telemetry.yml` |
| **Runs on** | Every PR | Pushes to `main`, `telemetry/**` branches, and manual runs |
| **Telemetry** | Events modeled on each Atomic test | Sysmon logs from running the test with `Invoke-AtomicTest` on a disposable Windows VM |
| **Purpose** | Fast, safe merge gate | Evidence that the rules work on what Windows actually logs |

Real tests never run on PRs, because code from a PR must not choose what gets executed. Each real run keeps its raw Sysmon logs as a downloadable artifact.

Real machines are noisy, so events are labeled by process tree instead of by time: only the process running the test's own command, and its children, count as attack events. Benign commands from the baseline run for real as well.

Real logs have already changed this project. The exported Sysmon logs showed `%VAR%` as `%%VAR%%` in a command line, so the simulated events now match what Windows logged.

## Game security detections

Real game tampering is the project's niche. These rules protect [FakeQuest](game/), a harmless stand-in game with a pretend license check, so nothing here touches a real game or real anti-cheat software.

| Threat | Rule watches for | Sysmon event | ATT&CK |
| --- | --- | --- | --- |
| **License bypass** | A command writing a license server entry to the `hosts` file | Process creation | T1565.001 |
| **Mod or crack injection** | The game loading a system-named DLL from outside the Windows folder | DLL load | T1574.001 |
| **Memory tampering** | A process requesting write access to the game's memory | Process access | T1055 |
| **Bootleg copy** | FakeQuest running with a hash that isn't on the official list | Process creation | T1554 |

The tests are harmless on purpose. The license domain uses the reserved `.invalid` name, the planted DLL is an unmodified signed Windows file, the memory tool closes its handle without reading or writing anything, and the bootleg copy only has one word changed in its startup message. **This project detects tampering, so it doesn't include cracks, cheats, or bypass techniques.**

ATT&CK describes attacks on organizations, so a player tampering with their own copy of a game only partly fits. Each rule keeps the closest technique and adds its own `x_game_threat` label.

### License server abuse

Some abuse only shows up as a pattern, so these rules count activity over time using standard [Sigma correlations](https://sigmahq.io/docs/meta/correlations.html). Their logs come from [a small license server](game/license_server.py) that only listens on the local machine, with demo keys that unlock nothing. It logs keys as hashes, so the logs don't hold working keys.

| Threat | Rule watches for | Must ignore | ATT&CK |
| --- | --- | --- | --- |
| **Key guessing** | 20 or more different unknown keys from one address in 5 minutes | A player retrying the same mistyped key | T1110 |
| **Key sharing** | One key used on 3 or more machines in an hour, with 2 seats allowed | A player reinstalling on their two PCs | T1078 |

Both rules count different values, not attempts. Two negative controls show why: the same rules counting attempts fire on those normal players, and the pipeline fails them.

## Evasion scorecard

Passing against one version of an attack doesn't say much about the next version, so [`simulation/variants.yml`](simulation/variants.yml) records ten harmless variations and what each rule does with them. Real runs execute them on a disposable Windows VM. A result that differs from the record fails the run in either direction, and a variation that logged nothing is an error rather than a miss.

Before any fixes, the rules caught **2 of 10** on real logs. They now catch **5 of 10**:

| Attack | Variation | Before | Now | Why |
| --- | --- | --- | --- | --- |
| `hosts` edit | PowerShell's `Add-Content` | Missed | **Caught** | The rule now knows PowerShell's file-writing commands |
| `hosts` edit | From a script file | Missed | Missed | The command line only shows the script's name, so this needs file monitoring |
| DLL planting | Uppercase `WINMM.DLL` | Caught | Caught | Matching ignores case |
| DLL planting | Next to a renamed game | Missed | Missed | The rule and the Sysmon config go by the game's name, because logging every DLL load is too noisy |
| Memory tampering | Full access | Missed | Missed | Launchers also request full access, so this is left out to avoid false alerts |
| Memory tampering | Write-only access | Missed | **Caught** | The rule now covers write access without read access |
| Bootleg copy | Renamed file | Missed | **Caught** | The rule now reads the name stored inside the file |
| Key guessing | Changing machine IDs | Caught | Caught | The rule counts by address |
| Key guessing | Many addresses | Missed | Missed | Counting across addresses needs tuning against real traffic |
| Key sharing | Same machine ID | Missed | Missed | The rule trusts the ID the client reports |

These are the gaps found so far, not all of them. The variations only cover the game and license rules, and each one is a test of this project's fake game.

## Noise score

A rule that fires on normal activity buries analysts in bad alerts, so [`simulation/noise.yml`](simulation/noise.yml) records eleven normal scenarios and which rules each one sets off. Every rule is scored on every scenario, and a result that differs from the record fails the run in either direction.

Before tuning, **4 of 11** scenarios set off no rules on real logs. Now **5 of 11** do:

| Normal activity | Rules set off | Why |
| --- | --- | --- |
| Normal game session | None | Nothing unusual happens |
| Launcher starts the game | None | The memory rule leaves out full access, because launchers get it too |
| Launch day with 60 players | None | Each player has their own key and machine |
| Family sharing a PC | None | The sharing rule counts machines per key |
| Small LAN event, 12 typos | None (**tuned**) | Fired until the guessing threshold went from 10 keys to 20 |
| Large LAN event, 30 typos | Key guessing | Everyone shares one address. Grouping by machine too would stop this, but guessers can change their reported machine ID |
| Official update, not on the hash list yet | Bootleg copy | A release has to publish its hash first |
| Overlay opens the game | Memory tampering | Allowing one by file name would be easy to fake, so this needs signature checks |
| Mod manager adds a DLL | DLL planting | A mod and a crack load the same way, so this needs a list of approved mods |
| Admin tool runs an encoded command | Both encoded PowerShell rules | Needs an allowlist tuned to each environment |
| New PC within the hour | Key sharing | It looks the same as the start of key sharing |

The tuning has a cost: a guesser now gets 19 tries instead of 9 before an alert. The activity is scripted, so this shows which kinds of normal behavior set off each rule, not how often they'd happen with real players.

## Roadmap

1. ~~Validate rules against simulated attacks in CI~~
2. ~~Validate against real Windows logs, and add game tampering rules~~
3. ~~Detect license server abuse by counting events over time~~
4. ~~Spot bootleg copies: game builds that don't match the official release~~
5. ~~Try harmless variations of each attack, and score which ones get past each rule~~
6. ~~Measure each rule's noise against realistic normal activity~~
7. **Real SIEM:** run the rules in a real SIEM as well as the mock
8. **Public dashboard:** publish coverage, the latest results, and known gaps

## Scope and limitations

- **Known noise remains.** The [noise score](#noise-score) lists the normal activity that still sets off rules.
- **Known blind spots remain.** The [evasion scorecard](#evasion-scorecard) lists what the rules still miss.
- **License traffic is scripted.** The server and its logs are real, but the requests come from test scripts on one machine, so every request has the same address. Real thresholds need tuning against real player traffic, and the scorecard records that spreading guesses across addresses gets past the guessing rule.
- **Coverage is small.** The catalog has two Atomic tests, four game tests, and two license tests, and KQL rules can only use `DeviceProcessEvents`.
- **The bootleg rule depends on its list.** An official patch that isn't on the list yet would look like a bootleg. A copy that also changes the name stored inside the file would get past it.
- **Game rules are tied to FakeQuest.** Protecting a real game means changing the game name in each rule, and the access values and DLL names need tuning for that game.
- **A real pass applies to one environment.** It covers a clean Windows Server VM with a minimal Sysmon configuration, not every Windows setup, and it doesn't measure false positives on real user activity.
- **The rule engines are subsets.** Sigma covers the common modifiers, conditions, and `expand` placeholders, plus `event_count` and `value_count` correlations, with no keyword searches. KQL covers single-table filters only. Anything unsupported returns exit `2`, never a guessed verdict.
- **Mock matching is approximate.** `has` approximates Kusto's term index, and regexes run on Python's engine rather than RE2.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design decisions and threat model.
