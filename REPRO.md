# Reproducing admission_parameter_rationale.md with Onur's admission_sim.py

Input: data/all.json from ethereum/discv4-dns-lists at cd92276 (2026-08-19, the day the report was added; the file was later removed from master). 30,053 ENRs.
Common flags: --honest-ips ../data/all.json --honest-rate 0.05 --attacker-rate 0.2 --honest-topic-popularity uniform --attacker-prefix /24 (report §4). Seed 1, runtime 24 h.

| Report figure | Flags | Report | Reproduced |
|---|---|---|---|
| §6.2 cache occupation, C=1000 | --attack cache_occupation | p95 20,825 s, attacker 36 % | 21,122 s, 38.2 % (util 28.4 %) |
| §6.2 cache occupation, C=5000 | + --capacity 5000 | 8,140 s, 52 % | 8,100 s, 52.6 % |
| §6.3 target topic, C=1000 | --attack target_topic --honest-target-topic-fraction 0.5 | target p95 33,300 s, 35 % | 32,413 s, 35.0 % |
| §6.3 target topic, C=5000 | + --capacity 5000 | 13,500 s, 52 % | 13,427 s, 52.2 % |
| §7 IP score /24, on / off | --attack cache_occupation --n-attacker-topics 10000 [--disable-ip-score] | 36 % / 82 % | 37.8 % / 83.0 % |
| §7 /16, /8 similar to /24 | --sweep-attacker-prefix | similar | 36.8 %, 36.4 % |

Note: §7 needs many attacker topics (10,000 or more); with the default 300, IP off gives 54 %.
