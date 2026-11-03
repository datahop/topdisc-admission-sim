#!/usr/bin/env python3
"""Print mean (min-max) over seeds for every figure series, for both models."""
import csv
import math
import statistics
import sys
from pathlib import Path

DATA = Path(__file__).resolve().parent / 'data'


def load(f):
    return list(csv.DictReader(open(DATA / f'{f}.csv')))


def cell(rows, key, scale=1, **m):
    v = [float(r[key]) * scale for r in rows if all(str(r[k]) == str(x) for k, x in m.items())]
    v = [x for x in v if not (math.isnan(x) or math.isinf(x))]
    if not v:
        return 'n/a'
    mean = statistics.mean(v)
    fmt = (lambda x: f'{x:,.0f}') if abs(mean) >= 100 else (lambda x: f'{x:.3f}' if abs(mean) < 2 else f'{x:.1f}')
    return f'{fmt(mean)} ({fmt(min(v))}-{fmt(max(v))})'


def table(title, rows, xkey, xs, cols):
    print(f'\n### {title}\n')
    print('| ' + xkey + ' | ' + ' | '.join(c[0] for c in cols) + ' |')
    print('|' + '---|' * (len(cols) + 1))
    for x in xs:
        print(f'| {x} | ' + ' | '.join(cell(rows, c[1], c[2], **{xkey: x, **c[3]}) for c in cols) + ' |')


def main():
    models = sys.argv[1:] or ['onur-paper', 'go']
    pocc, cap, pre, pop, rate, gu_rows = (load(f) for f in ('pocc', 'capacity', 'prefix', 'popularity', 'rate', 'giveup'))
    P = ['1.0', '2.0', '4.0', '6.0', '8.0', '10.0', '12.0', '16.0', '20.0', '24.0', '32.0']
    h = 1 / 3600
    for m in models:
        print(f'\n## {m}')
        table('Q1 cache occupation (Fig 1-2)', pocc, 'p_occ', P, [
            ('atk share full', 'avg_attacker_cache_share', 1, dict(model=m, scenario='co')),
            ('atk share occ-only', 'avg_attacker_cache_share', 1, dict(model=m, scenario='co-occ')),
            ('util full', 'avg_cache_utilisation', 1, dict(model=m, scenario='co')),
            ('util occ-only', 'avg_cache_utilisation', 1, dict(model=m, scenario='co-occ')),
            ('honest p95 s', 'honest_p95_delay', 1, dict(model=m, scenario='co')),
            ('new honest admitted', 'honest_new_admitted_fraction', 1, dict(model=m, scenario='co'))])
        table('Q1 target topic (Fig 3-6)', pocc, 'p_occ', P, [
            ('tgt atk share full', 'avg_target_attacker_cache_share', 1, dict(model=m, scenario='tt')),
            ('tgt atk share occ', 'avg_target_attacker_cache_share', 1, dict(model=m, scenario='tt-occ')),
            ('tgt honest p95 h full', 'target_honest_p95_delay', h, dict(model=m, scenario='tt')),
            ('tgt honest p95 h occ', 'target_honest_p95_delay', h, dict(model=m, scenario='tt-occ')),
            ('benign tgt p95 h', 'target_honest_p95_delay', h, dict(model=m, scenario='benign')),
            ('benign util', 'avg_cache_utilisation', 1, dict(model=m, scenario='benign')),
            ('atk within target', 'avg_target_attacker_share_within_target', 1, dict(model=m, scenario='tt'))])
        table('Q2 capacity (Fig 7-8)', cap, 'capacity', ['100', '250', '500', '1000', '2000', '5000'], [
            ('co starve', 'honest_starvation_rate', 1, dict(model=m, scenario='co')),
            ('co atk share', 'avg_attacker_cache_share', 1, dict(model=m, scenario='co')),
            ('co honest p95 s', 'honest_p95_delay', 1, dict(model=m, scenario='co')),
            ('co new honest adm', 'honest_new_admitted_fraction', 1, dict(model=m, scenario='co')),
            ('tt starve', 'honest_starvation_rate', 1, dict(model=m, scenario='tt')),
            ('tt tgt starve', 'target_honest_starvation_rate', 1, dict(model=m, scenario='tt')),
            ('tt atk share', 'avg_attacker_cache_share', 1, dict(model=m, scenario='tt')),
            ('tt tgt p95 s', 'target_honest_p95_delay', 1, dict(model=m, scenario='tt'))])
        for ip in ('True', 'False'):
            table(f'Q3 prefix, 10k topics, IP score {ip} (Fig 9-10)', pre, 'attacker_prefix', ['/24', '/16', '/8', 'diverse'], [
                ('atk share', 'avg_attacker_cache_share', 1, dict(model=m, use_ip_score=ip)),
                ('atk attempts/adm', 'attacker_attempts_per_admission', 1, dict(model=m, use_ip_score=ip)),
                ('atk p50 delay s', 'attacker_p50_delay', 1, dict(model=m, use_ip_score=ip)),
                ('atk p95 delay s', 'attacker_p95_delay', 1, dict(model=m, use_ip_score=ip)),
                ('honest p95 s', 'honest_p95_delay', 1, dict(model=m, use_ip_score=ip)),
                ('new honest adm', 'honest_new_admitted_fraction', 1, dict(model=m, use_ip_score=ip)),
                ('util', 'avg_cache_utilisation', 1, dict(model=m, use_ip_score=ip))])
        for t in ('True', 'False'):
            table(f'Q4 popularity, topic score {t} (Fig 11-12)', pop, 'honest_target_topic_fraction',
                  ['0.0', '0.1', '0.25', '0.5', '0.75', '0.9'], [
                ('tgt p95 h', 'target_honest_p95_delay', h, dict(model=m, use_topic_score=t)),
                ('tgt honest share', 'avg_target_honest_cache_share', 1, dict(model=m, use_topic_score=t)),
                ('util', 'avg_cache_utilisation', 1, dict(model=m, use_topic_score=t))])
        for sc in ('co', 'tt'):
            table(f'Q5 attacker rate, {sc} (Fig 13-16)', rate, 'attacker_rate', ['0.02', '0.05', '0.1', '0.2', '0.4'], [
                ('atk share', 'avg_attacker_cache_share', 1, dict(model=m, scenario=sc)),
                ('tgt atk share', 'avg_target_attacker_cache_share', 1, dict(model=m, scenario=sc)),
                ('atk attempts/adm', 'attacker_attempts_per_admission', 1, dict(model=m, scenario=sc)),
                ('atk p50 delay s', 'attacker_p50_delay', 1, dict(model=m, scenario=sc)),
                ('atk p95 delay s', 'attacker_p95_delay', 1, dict(model=m, scenario=sc)),
                ('honest p95 s', 'honest_p95_delay', 1, dict(model=m, scenario=sc)),
                ('util', 'avg_cache_utilisation', 1, dict(model=m, scenario=sc))])
    print('\n## FIFO (Fig 6)')
    table('FIFO benign 0.5', pocc, 'capacity', ['1000', '5000'], [
        ('tgt p95 h', 'target_honest_p95_delay', h, dict(model='fifo')),
        ('util', 'avg_cache_utilisation', 1, dict(model='fifo'))])
    print('\n## go with give-up (honest only, or all)')
    for c in ('1000', '5000'):
        for gu in ('honest', 'all'):
            for sc in ('co', 'tt', 'benign'):
                sel = dict(scenario=sc, capacity=c, give_up=gu, n_attacker_topics='300')
                if not any(all(str(r[k]) == v for k, v in sel.items()) for r in gu_rows):
                    continue
                print(f'C={c} {gu} {sc}: ' + ' | '.join(f'{k}={cell(gu_rows, k, 1, **sel)}' for k in (
                    'avg_attacker_cache_share', 'avg_target_attacker_share_within_target', 'honest_p95_delay',
                    'honest_new_admitted_fraction', 'avg_cache_utilisation')))
    for ip in ('True', 'False'):
        sel = dict(scenario='co', n_attacker_topics='10000', use_ip_score=ip)
        print(f'C=5000 honest co10k ip={ip}: ' + ' | '.join(f'{k}={cell(gu_rows, k, 1, **sel)}' for k in (
            'avg_attacker_cache_share', 'honest_p95_delay', 'honest_new_admitted_fraction')))
    bip = load('benign-ip')
    for m in models:
        table(f'Benign cost of the diversity terms, {m}', bip, 'honest_target_topic_fraction', ['0.0', '0.5'], [
            (f'{lab} {col}', key, 1, dict(model=m, use_ip_score=ip, use_topic_score=t))
            for ip, t, lab in (('True', 'True', 'both on'), ('False', 'True', 'IP off'), ('False', 'False', 'both off'))
            for key, col in (('honest_p95_delay', 'p95 s'), ('target_honest_p95_delay', 'tgt p95 s'),
                             ('honest_starvation_rate', 'starve'), ('avg_cache_utilisation', 'util'))])
    probe = load('probe')
    print('\n## probe synthetic IPs onur-paper co C=1000:', cell(probe, 'avg_attacker_cache_share'),
          cell(probe, 'attacker_attempts_per_admission'), cell(probe, 'avg_cache_utilisation'))


if __name__ == '__main__':
    main()
