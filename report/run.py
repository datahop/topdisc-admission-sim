#!/usr/bin/env python3
"""Run the experiments behind Figures 1-16 of admission_parameter_rationale.md.

Each figure is run with the go model (topdisc 703d5a2, defaults C = 5000) and
with onur-paper (Onur's unmodified registrar, C = 1000) to check that the
original figure is reproduced. Seeds 1-3. Run with python3 -I -B run.py.
"""
import argparse
import csv
import importlib.util
import multiprocessing as mp
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
DATA = HERE / 'data'
spec = importlib.util.spec_from_file_location('compare', HERE.parent / 'compare/compare.py')
compare = importlib.util.module_from_spec(spec)
sys.modules['compare'] = compare
spec.loader.exec_module(compare)
onur = compare.onur

SEEDS = (1, 2, 3)
MODEL_C = {'go': 5000, 'onur-paper': 1000}
POCC = (1, 2, 4, 6, 8, 10, 12, 16, 20, 24, 32)
CAPACITY = (100, 250, 500, 1000, 2000, 5000)
PREFIX = ('/24', '/16', '/8', 'diverse')
FRACTION = (0.0, 0.1, 0.25, 0.5, 0.75, 0.9)
RATE = (0.02, 0.05, 0.1, 0.2, 0.4)

COMMON = dict(honest_rate=0.05, attacker_rate=0.2, honest_topic_popularity='uniform', attacker_prefix='/24')
SCENARIOS = {
    'co': dict(attack='cache_occupation'),
    'tt': dict(attack='target_topic', honest_target_topic_fraction=0.5),
    'benign': dict(attack='none', honest_target_topic_fraction=0.5),
}
OCC_ONLY = dict(use_topic_score=False, use_ip_score=False)


def cases():
    out = []

    def add(family, model, scenario, seed, give_up=None, **over):
        out.append(dict(family=family, model=model, scenario=scenario, seed=seed,
                        give_up=give_up, over=over))

    for model, C in MODEL_C.items():
        for seed in SEEDS:
            # Q1: Figures 1-6.
            for p in POCC:
                for scenario in ('co', 'tt'):
                    add('pocc', model, scenario, seed, capacity=C, p_occ=float(p))
                    add('pocc', model, scenario + '-occ', seed, capacity=C, p_occ=float(p), **OCC_ONLY)
                add('pocc', model, 'benign', seed, capacity=C, p_occ=float(p))
            # Q2: Figures 7-8.
            for c in CAPACITY:
                for scenario in ('co', 'tt'):
                    add('capacity', model, scenario, seed, capacity=c)
            # Q3: Figures 9-10, 10,000 attacker topics.
            for prefix in PREFIX:
                for ip in (True, False):
                    add('prefix', model, 'co', seed, capacity=C, attacker_prefix=prefix,
                        n_attacker_topics=10000, use_ip_score=ip)
            # Q4: Figures 11-12.
            for frac in FRACTION:
                for topic in (True, False):
                    add('popularity', model, 'benign', seed, capacity=C,
                        honest_target_topic_fraction=frac, use_topic_score=topic)
            # Q5: Figures 13-16.
            for rate in RATE:
                for scenario in ('co', 'tt'):
                    add('rate', model, scenario, seed, capacity=C, attacker_rate=rate)
        for seed in SEEDS:
            # Benign cost of the diversity terms: IP score on/off, and both off.
            for frac in (0.0, 0.5):
                for ip, topic in ((True, True), (False, True), (False, False)):
                    add('benign-ip', model, 'benign', seed, capacity=C, honest_target_topic_fraction=frac,
                        use_ip_score=ip, use_topic_score=topic)
    for seed in SEEDS:
        # FIFO baseline (Figure 6), registrar-independent.
        for C in sorted(set(MODEL_C.values())):
            add('pocc', 'fifo', 'benign', seed, capacity=C, admission_policy='fifo')
        # Sensitivity: honest advertisers follow the client's 1.5 E budget
        # (give_up='honest'), or everyone does (give_up='all').
        for C in (1000, 5000):
            for scenario in ('co', 'tt', 'benign'):
                add('giveup', 'go', scenario, seed, give_up='honest', capacity=C)
            for scenario in ('co', 'tt'):
                add('giveup', 'go', scenario, seed, give_up='all', capacity=C)
        for ip in (True, False):
            add('giveup', 'go', 'co', seed, give_up='honest', capacity=5000,
                n_attacker_topics=10000, use_ip_score=ip)
        # Probe: synthetic honest IPs instead of all.json.
        add('probe', 'onur-paper', 'co', seed, capacity=1000, synthetic_ips=True)
    return out


def run_case(case):
    started = time.time()
    over = dict(case['over'])
    synthetic = over.pop('synthetic_ips', False)
    scenario = case['scenario'].removesuffix('-occ')
    cfg = onur.SimConfig(**{**COMMON, **SCENARIOS[scenario], **over}, seed=case['seed'])
    model = 'onur-paper' if case['model'] == 'fifo' else case['model']
    sim = compare.CompareSim(cfg, [] if synthetic else compare.honest_ips(), model,
                             give_up=case['give_up'] or False)
    row = sim.run().summary()
    if isinstance(sim.registrar, compare.GoAdapter):
        row.update(sim.registrar.stats)
    row.update(family=case['family'], model=case['model'], scenario=case['scenario'],
               seed=case['seed'], give_up=case['give_up'] or '', synthetic_ips=synthetic,
               capacity=cfg.capacity, p_occ=cfg.p_occ, attacker_rate=cfg.attacker_rate,
               attacker_prefix=cfg.attacker_prefix, n_attacker_topics=cfg.n_attacker_topics,
               honest_target_topic_fraction=cfg.honest_target_topic_fraction,
               use_topic_score=cfg.use_topic_score, use_ip_score=cfg.use_ip_score,
               admission_policy=cfg.admission_policy, wall_s=round(time.time() - started, 1))
    return row


def write(rows):
    DATA.mkdir(exist_ok=True)
    # Keep earlier rows of (family, model) pairs that this run does not redo.
    redone = {(r['family'], r['model']) for r in rows}
    by_family = {}
    for path in DATA.glob('*.csv'):
        with open(path) as f:
            for r in csv.DictReader(f):
                if (r['family'], r['model']) not in redone:
                    by_family.setdefault(r['family'], []).append(r)
    for r in rows:
        by_family.setdefault(r['family'], []).append(r)
    for family, sel in by_family.items():
        sel.sort(key=lambda r: tuple(str(r[k]) for k in ('model', 'scenario', 'capacity', 'p_occ',
                                                           'attacker_rate', 'attacker_prefix',
                                                           'honest_target_topic_fraction',
                                                           'use_topic_score', 'use_ip_score', 'seed')))
        fields = list(dict.fromkeys(k for r in sel for k in r))
        with open(DATA / f'{family}.csv', 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(sel)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--workers', type=int, default=12)
    p.add_argument('--family', action='append')
    p.add_argument('--model', action='append')
    args = p.parse_args()
    todo = [c for c in cases() if (not args.family or c['family'] in args.family)
            and (not args.model or c['model'] in args.model)]
    # Longest first: go at large C.
    todo.sort(key=lambda c: (c['model'] == 'go', c['over'].get('capacity', 0),
                             -c['over'].get('p_occ', 10)), reverse=True)
    rows = []
    with mp.get_context('fork').Pool(min(args.workers, 12)) as pool:
        for row in pool.imap_unordered(run_case, todo):
            rows.append(row)
            print(f"[{len(rows)}/{len(todo)}] {row['family']} {row['model']} {row['scenario']} "
                  f"C={row['capacity']} p={row['p_occ']:g} s={row['seed']} "
                  f"atk={row['avg_attacker_cache_share']:.3f} wall={row['wall_s']}s", flush=True)
            if len(rows) % 25 == 0:
                write(rows)
    write(rows)
    print('done', flush=True)


if __name__ == '__main__':
    main()
