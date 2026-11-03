# Admission report redo: notes

Rewrites devp2p `discv5/admission_parameter_rationale.md` (devp2p#20) against the registrar at datahop/go-ethereum topdisc 703d5a2b9. Plan: ../REPORT-PLAN.md.

Files:
- `run.py`: runs every figure's grid with `go` (C = 5000) and `onur-paper` (C = 1000), seeds 1-3, 12 workers; writes `data/<family>.csv`. Log: `run.log` (606 runs, about 15 min).
- `figures.py`: `--model go` writes `fig*.png` here (the copies in the devp2p report); `--model onur-paper` writes `repro/fig*.png`. Needs matplotlib (`pip install -r requirements.txt`).
- `summary.py`: mean (min-max) tables per figure for both models; output in `summary.md`.
- `rerun_compare_go.py`: reruns the go rows of the compare grid (logs `compare-rerun.log` after #177, `compare-rerun-r1.log` after review round 1); results in ../compare/RESULTS.md.
- `probe_noip.py`: instrumented seed-1 run behind the §7.2 figures for IP score off (2,101 honest quotes at the 24 h cap, all for a topic with an ad; 2,702 of 2,869 fresh honest admissions for a topic with none). Run: `python3 -I -B probe_noip.py $PWD/run.py`.
- `r1.sh`: the review round 1 reruns (go grid, onur-paper benign-ip, compare go rows). Logs `run-r1-go.log`, `run-r1-onur.log`. `data-r0/` keeps the round 0 CSVs.

## Model changes (compare/compare.py)

- `GoTable` no longer overrides `expire` or keeps `prune_at`: the base sim-admission registrar already drops a topic's bound with its last ad (#177, reverting #166) and expires ads at the request's time (#173).
- `GoTable(topic_score=...)`: topic term off for the occupancy-only baseline and Q4. `GoAdapter` passes `cfg.use_topic_score`.
- test_compare.py: the #166 test is now `test_go_topic_bound_dropped_with_last_ad`; new `test_go_expired_ads_pruned_at_request_time`. 9 tests pass.
- Review round 1: an `existing` reply (no ticket, WaitTime E) now counts as registered, as in the Go client (v5_topic.go, HandleRegistered): the request ends as admitted with no second cache entry and no renewal of its own; the ad already in the cache keeps its renewal. Before, it came back after E as a fresh attempt. `test_go_existing_counts_as_registered` covers it. A quote below 1 s is now retried after 1 s, as the client clamps it (none occurred in the grid). Effect on the report grid (go, round 0 against round 1): cache shares move by at most 0.8 pp, delays by at most 4% (7% for one attacker median at C = 500), target-topic attacker attempts by at most 4% (5.8 to 5.6 at 0.4/s).

## Experiment grid per figure

Common flags (Onur's CLI): `--honest-ips data/all.json --honest-rate 0.05 --attacker-rate 0.2 --honest-topic-popularity uniform --attacker-prefix /24 --seed {1,2,3}`. onur-paper at `--capacity 1000`; go at C = 5000 through compare.GoAdapter with the same workload. Occupancy only = `--disable-topic-score --disable-ip-score`.

| Report figure (file) | Experiment |
|---|---|
| 1, 2 (fig1, fig2) | `--attack cache_occupation --sweep-pocc --p-occ-values 1,2,4,6,8,10,12,16,20,24,32`, full and occupancy only |
| 3, 4 (fig3, fig4) | `--attack target_topic --honest-target-topic-fraction 0.5`, same Pocc sweep, full and occupancy only; Fig 3 plots avg_target_attacker_cache_share |
| 5 (fig_q1_target_honest_delay_benign_vs_attack) | benign `--attack none --honest-target-topic-fraction 0.5` Pocc sweep, against Fig 4 full |
| 6 (fig_q1_fifo_vs_admission_target_honest_delay) | benign Pocc sweep against `--policy fifo` (Onur's FIFO registrar, same C) drawn flat; fig_q1_fifo_vs_admission_cache_utilisation is the same run, not referenced in the report |
| 7, 8 (fig5, fig6) | `--sweep-capacity` (100, 250, 500, 1000, 2000, 5000), cache occupation and target topic; left axis honest_starvation_rate, right axis avg_attacker_cache_share. The original plots start at 250 |
| 9, 10 (fig7, fig8) | `--attack cache_occupation --n-attacker-topics 10000 --sweep-attacker-prefix [--disable-ip-score]` |
| 11, 12 (fig9, fig10) | `--attack none --honest-target-topic-fraction {0,0.1,0.25,0.5,0.75,0.9} [--disable-topic-score]`; Fig 12 plots avg_target_honest_cache_share |
| 13-16 (fig11-fig14) | `--attacker-rate {0.02,0.05,0.1,0.2,0.4}`, cache occupation and target topic (fraction 0.5) |

Extra: `giveup.csv` (go at C = 1000 and 5000: honest give-up for co, tt, benign; everyone gives up for co, tt; plus honest give-up for co with 10,000 topics, IP on/off, at C = 5000) for §6.4, §9.4, §10, §11; `benign-ip.csv` (benign, uniform and 50% target demand, IP on/off and both terms off, both models) for §5.4, §7.2, §10; `probe.csv` (onur-paper with synthetic honest IPs, see below).

## Does onur-paper reproduce the original figures?

Yes, every figure, within seed noise or close to it (mean of seeds 1-3 against the original single curve; full tables in summary.md):

- Fig 1: 0.518 / 0.376 / 0.265 at Pocc 1 / 10 / 32 against 0.523 / 0.364 / 0.271. The original sits 1-2 pp below the mean at Pocc 8-16 (e.g. 0.334 against 0.353 at 16). Occupancy only 0.80 in both.
- Fig 2: utilisation within 0.5 pp at every Pocc for both curves.
- Fig 3: within 1.3 pp. Fig 4: within 0.5 h (full) and 0.45 h (occupancy only).
- Fig 5: benign within about 0.7 h (Pocc 8: 3.6 h against 4.27 h). Fig 6: FIFO 0.749 h against 0.75 h.
- Fig 7: starvation 0.831 / 0.686 / 0.517 at C = 250 / 1000 / 5000 against 0.796 / 0.684 / 0.522; attacker share within 2 pp. Fig 8: starvation within 2.3 pp, share within 0.5 pp. The original text quotes 21% attacker share at C = 100 under cache occupation; the reproduction gives 17.9% at C = 100 and 20.2% at C = 250. Its other C = 100 numbers (57,600 s, 69,300 s, 8%) match C = 100.
- Fig 9: IP on 0.373 / 0.371 / 0.372 / 0.803 against 0.364 / 0.364 / 0.365 / 0.798; IP off 0.82-0.83 in both. Fig 10: 82 against 85 attempts (IP on, concentrated), 35.8 both (diverse), 13.5 against 13.6 (IP off).
- Fig 11: within 0.3 h. Fig 12: within 0.7 pp.
- Fig 13-16: shares within 1.2 pp, attempts within 3.5.

Probe: synthetic honest IPs give 33.8% attacker share at the default point, so the all.json input matters; the original figures match all.json.

## Key numbers, go at C = 5000 (original report in brackets, C = 1000)

After review round 1 (summary.md has the full tables).

- Q1 cache occupation: attacker share 69% / 60% / 48% at Pocc 1 / 10 / 32 [52 / 36 / 27%]; occupancy only 80% [80%]; utilisation 78% / 30% / 12% [85 / 28 / 11%]; honest p95 1,935 / 5,877 / 12,680 s.
- Q1 target topic: target attacker share 71% / 61% / 50% [53 / 35 / 24%]; target honest p95 2,517 / 8,502 / 19,519 s [15,300 / 33,300 / 46,800 s]; benign 354 / 2,564 / 6,930 s [1.4 / 4.5 / 9.75 h]; FIFO 0 (the cache never fills at C = 5000; 43% utilisation) [0.75 h at C = 1000].
- Benign cost of the diversity terms (no attack, Pocc 10): uniform topics, honest p95 2,060 s both terms, 589 s IP off, 58 s both off; starvation 13.5% / 0 / 0. At 50% target demand, target p95 2,564 s both, 2,049 s topic off, 5,526 s IP off (utilisation 27% against 19%), 58 s both off.
- Q2: honest p95 51,911 / 18,636 / 5,877 s at C = 100 / 1000 / 5000 [57,600 / 20,825 / 8,140 s]; attacker share 28% / 40% / 60% [21 / 36 / 52%]; tt target p95 63,621 / 27,456 / 8,502 s [69,300 / 33,300 / 13,500 s]; tt attacker share 21% / 43% / 61% [8 / 35 / 52%].
- Q3 (10,000 topics): /24 IP on 60%, off 92% [36%, 82%]; /16 59%, /8 61%; diverse 80% on, 92% off [80%]. Attempts 4.9 on, 2.8 off [85, 14]; median attacker delay 6,298 s on, 521 s off. New honest admitted 94% on, 20% off (diverse: 90% on, 19% off). Honest starvation / p95 with IP on: 47% / 5,938 s (/24 attacker), 85% / 9,186 s (diverse attacker).
- Q4: at 90% demand target p95 2,471 s on, 2,051 s off [16,023 / 13,972 s]; target share 86% on, 90% off [79 / 90%].
- Q5 cache occupation: share 23% / 60% / 68% at 0.02 / 0.2 / 0.4 per s [18 / 36 / 41%]; attempts 3.7 / 4.8 / 5.6 [19 / 85 / 146]; median attacker delay 2,062 / 6,374 / 9,556 s. Target topic: 22% / 61% / 70% [15 / 35 / 39%]; attempts 3.9 / 4.8 / 5.6 [26 / 97 / 174].
- Give-up (attacker share / new honest admitted): cache occupation C = 1000: wait out 40 / 83%, honest give-up 49 / 60%, all give up 6 / 78%; C = 5000: 60 / 95%, 72 / 66%, 25 / 96%. Target topic C = 1000: 43 / 77%, 57 / 37%, 5 / 69%; C = 5000: 61 / 93%, 72 / 50%, 20 / 88%. Benign honest give-up: 70% (C = 1000), 89% (C = 5000) admitted.

## Where the plan turned out wrong or incomplete

- The FIFO baseline at C = 5000 is degenerate: 4,327 honest advertisers in 24 h never fill 5,000 slots, so FIFO admits everything and the comparison reduces to "all admission-control delay comes from the function". The report says so and gives the C = 1000 FIFO value for reference.
- Attempts per admission (Figs 10, 12, 14, 16, kept for continuity) no longer measure attacker cost: a ticket carries the credit and a quote covers the whole wait, so attempts are 3-6 everywhere. The report uses registration delay as the cost measure in the text.
- Fig 9 needs 10,000 attacker topics (REPRO.md); with 300 the IP-off line drops to 54% in the old model because the topic term binds. Fig 1 and the other cache-occupation figures use 300 topics.
- The occupancy-only target-topic delay at Pocc 1 is 0 for go: the cache fills (88%), a full table quotes the 24 h cap, and only requests admitted before that count (23% of new honest requests).
- The original figures look like single runs that sit slightly below the seed-1 numbers in REPRO.md for cache occupation (0.364 against 0.382 at the default point); they are within the seed 1-3 range or 1-2 pp of it.
- Publication: this repository (https://github.com/datahop/topdisc-admission-sim) holds the simulator, the same-traffic harness, the run and figure scripts, the per-seed CSVs and these notes.
- Occupancy-only target-topic delay below Pocc 4 (Figure 4, explained in §5.3 since round 2): occupancy only, the wait is b·G = 0.1·E·G/(k/C)^Pocc with k free slots. With one slot free it is 0.045 s at Pocc 1 (below the 1 s slack), 225 s at Pocc 2 and above E from Pocc 4. At Pocc 1 the cache fills, a full cache quotes the 24 h cap, and renewals, which in this simulator arrive exactly at their own ad's expiry, take each freed slot at once: 23% of new honest requests are admitted, all with zero delay. At Pocc 2 the cache sits a few slots below full and the p95 is 225 s, the quote for the last free slot. From Pocc 4 the cache settles some tens of slots below full where quotes are of order E (about 0.75 h). Diagnosis from the round 2 reviews (Sonnet, Opus); the same pattern holds for cache occupation (0 / 225 / 3,001 s).
