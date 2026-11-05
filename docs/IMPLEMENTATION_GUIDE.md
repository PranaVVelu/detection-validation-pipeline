# Implementation Guide

Follow these steps to take the project from this folder to a public repo with a working, demonstrable pipeline.

## Phase 0: Run it locally

1. Create a virtual environment and install the tools:

   ```bash
   python3 -m venv .venv
   ```

   ```bash
   source .venv/bin/activate
   ```

   ```bash
   make setup
   ```

2. Run the test suite. All tests should pass:

   ```bash
   make test
   ```

3. Try a good rule and a bad one, and compare the exit codes:

   ```bash
   make validate RULE=detections/sigma/proc_creation_win_powershell_encoded_command.yml
   ```

   ```bash
   make validate RULE=tests/fixtures/rules/fail_too_broad.yml
   ```

4. If you have Docker, run the isolated version that CI uses:

   ```bash
   make validate-docker
   ```

   ```bash
   make clean
   ```

## Phase 1: Publish and turn on the gate

1. **Create the repo and push.** Name it `detection-validation-pipeline`, or update the badge URL to match. Then connect this folder and push it:

   ```bash
   git remote add origin https://github.com/PranaVVelu/detection-validation-pipeline.git
   ```

   ```bash
   git push -u origin main
   ```
2. **Check the first run.** Under **Actions**, trigger **Detection Validation** with **Run workflow** to validate every rule. This first run is the real test of the Docker layer.
3. **Require the gate.** In **Settings > Rules > Rulesets**, create a ruleset for `main` that requires a pull request and the **Detection gate** status check. Don't require the individual `Validate ...` jobs, because their names change with each rule.
4. **Protect the pipeline once you have collaborators.** GitHub doesn't let you approve your own PR, so turning this on as a solo maintainer would block all of your merges. When someone else can review, add `.github/CODEOWNERS`, and enable "Require review from Code Owners" in the same ruleset:
   ```text
   /.github/        @PranaVVelu
   /scripts/        @PranaVVelu
   /src/            @PranaVVelu
   /simulation/     @PranaVVelu
   /Dockerfile      @PranaVVelu
   ```

## Phase 1.5: Create your demo evidence

Open these as real PRs. They're what a reviewer will click on.

1. **A failing PR.** Copy `tests/fixtures/rules/fail_too_broad.yml` to `detections/sigma/`, and give it a new `id`. The gate goes red, and the job summary names the exact benign command it matched.
2. **The fix.** In the same PR, change `' -e'` to `' -e '`. The gate goes green. This pair of commits tells the whole story of the project, so keep it visible rather than closing it silently.
3. **A pipeline error.** In a throwaway PR, add a KQL rule using `summarize`. The run reports ERROR rather than FAIL, which shows the two are kept apart.
4. **Screenshots.** Capture the job summary tables for your README or post.

## Adding a new Atomic test

1. Find the test in `atomics/<technique>/<technique>.yaml` in the [Atomic Red Team repo](https://github.com/redcanaryco/atomic-red-team), and copy its `auto_generated_guid`.
2. Add it under `tests:` in `simulation/catalog.yml`, including `upstream_command`.
3. Model `attack_events` from what the command does when run, including the parent process its executor creates. **Write them before the rule**, so the telemetry can't be shaped to fit it.
4. If the test suggests a realistic look-alike, add it to `benign_baseline`.
5. Reference the GUID from your rule. Then update `upstream.commit` in the catalog if you moved to a newer version of Atomic Red Team.

## Phase 2: Real execution with Invoke-Atomic

`real-telemetry.yml` gives each rule its own disposable `windows-2022` runner, which:

1. Installs Sysmon with the minimal config in `telemetry/sysmon-config.xml`, after checking Microsoft's signature on the download.
2. Downloads the Atomic definition from the commit pinned in the catalog, and stops if the command no longer matches.
3. Runs the benign baseline and then the test, using `Invoke-AtomicTest`.
4. Exports the Sysmon logs and labels events by process tree.
5. Runs the same `ship_events.py` and `validate_alert.py` stages as the simulated flow.

To run it, go to **Actions > Real Telemetry Validation > Run workflow**, or push to a `telemetry/**` branch. To see the evidence, open a run and download its artifact, which contains `sysmon-raw.xml`.

Things to keep in mind:

- **Only run tests you've read.** Stick to harmless ones like these two. Don't run anything that downloads tools or dumps credentials on shared infrastructure.
- **Never trigger this from pull requests.** It executes code, so it's limited to people with write access.
- **Update the simulation when real logs surprise you.** When real behavior differs from the catalog, fix the catalog so that the fast PR check stays accurate.

## Game security detections

Game tests work like Atomic tests, except that each one is a script in `game/scenarios/` with a `benign` and an `attack` side, run against the project's fake game. To add one:

1. **Add the scenario script.** Keep it harmless: no real cracks, cheats, bypass steps, or commercial game files.
2. **Add the test to the catalog** with `kind: game`, its event category, and modeled attack and benign events.
3. **Update `telemetry/sysmon-config.xml`** if the test needs an event type that isn't collected yet.
4. **Write the rule** with `x_game_test` and an `x_game_threat` label.
5. **Push to a `telemetry/**` branch**, then compare the real logs with what you modeled and fix any differences.

### Values that change by environment

The official game hash changes with every build, so it can't be written into a rule. The rule uses Sigma's `expand` modifier with a placeholder such as `%official_fakequest_hashes%` instead, as a real SIEM would use a lookup table. Simulated runs read the values from `simulation/placeholders.yml`. Real runs read the file `game/build.ps1` writes, through the `DVP_PLACEHOLDERS` environment variable. A placeholder with no values returns exit `2`, because an empty allowlist would flag every build.

### Rules that count events

Use a [Sigma correlation](https://sigmahq.io/docs/meta/correlations.html) when one event isn't suspicious but a pattern is. The rule file holds two YAML documents: a base rule that selects events, then the correlation that counts them. The correlation holds the rule's ID, tags, and `x_game_test`. Only `event_count` and `value_count` with `gte` are supported, and anything else returns exit `2`.

The pipeline counts each scenario separately, so benign events can't complete an attack's count. License tests use `kind: license` in the catalog, and their scripts in `game/scenarios/` talk to `game/license_server.py`. Prefer counting different values over counting attempts, because normal users repeat themselves.

## Phase 3: Stretch goals

Roughly in order of portfolio value:

1. **Real KQL engine.** Replace the KQL subset with [Kustainer](https://learn.microsoft.com/en-us/azure/data-explorer/kusto-emulator-overview), Microsoft's Kusto emulator. Validating real KQL semantics, including joins and `summarize`, is a big credibility jump.
2. **Coverage report.** Generate an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer from passing rules on each merge, and publish it to GitHub Pages. It's also the most visual output for a LinkedIn post.
3. **Sigma conversion.** Use a pySigma backend to convert Sigma to KQL and validate both forms. That catches conversion bugs as well as logic bugs.
4. **Evasion variants.** Add several attack variations per technique, such as `-eNc` casing or `/enc`, and report a robustness score per rule.
5. **Scheduled drift runs.** Re-validate all rules nightly to catch regressions.

## Talking about it

Be precise about what it does, because a detection engineer reading your post will check.

- **Accurate:** "CI validates rule logic against telemetry modeled on Atomic Red Team tests, including negative controls."
- **Inaccurate until Phase 2:** "CI executes Atomic Red Team attacks." It simulates them.

A good theme for a post is the `-e` versus `-ExecutionPolicy` false positive: it's a small, concrete bug that's easy to write, a linter won't catch it, and this pipeline does. Link the failing PR from Phase 1.5.

In interviews, expect questions about the limits of mocked telemetry, why FAIL and ERROR are separate, and how the pipeline handles untrusted rules. The answers are in [ARCHITECTURE.md](ARCHITECTURE.md).
