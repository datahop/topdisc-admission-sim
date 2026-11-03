# topdisc-admission-sim

Simulations behind the TopDisc admission-control report,
[`discv5/admission_parameter_rationale.md`](https://github.com/datahop/devp2p/blob/master/discv5/admission_parameter_rationale.md)
in datahop/devp2p (issue datahop/devp2p#20).

## Contents

- `admission_sim.py`: Onur Ascigil's single-registrar admission simulator, used for the
  original report ([ethereum/devp2p#272](https://github.com/ethereum/devp2p/pull/272)).
  Unchanged; it models the waiting-time function of the DISC-NG paper.
- `registrar.py`: a Python port of the Go registrar (waiting-time function, lower bounds,
  tickets, IP similarity tree) from datahop/go-ethereum, branch `topdisc`.
- `compare/`: drives the same traffic through three models: `onur-paper` (the simulator
  above, unchanged), `onur-current` (its mechanics with the current waiting-time function)
  and `go` (`registrar.py` brought to topdisc 703d5a2b9). `RESULTS.md` holds the comparison.
- `report/`: the experiment grid for the report (`run.py`), the figures (`figures.py`),
  number tables (`summary.py`, `summary.md`), per-seed results (`data/*.csv`), the current
  figures (`fig*.png`), the reproductions of the original figures (`repro/`) and notes
  (`REPORT-NOTES.md`).
- `REPRO.md`: how the original report's numbers were reproduced.

## Reproducing

```
pip install -r requirements.txt
data/fetch_all_json.sh                   # honest advertiser IPs, pinned commit
python3 -I -B -m pytest -q compare/test_compare.py
python3 -I -B report/run.py              # the full grid; see REPORT-NOTES.md for options
python3 -I -B report/figures.py --model go
```

Every run is a single registrar over 24 simulated hours; results are means over seeds 1 to 3.
