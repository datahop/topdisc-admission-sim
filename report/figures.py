#!/usr/bin/env python3
"""Figures for admission_parameter_rationale.md from data/*.csv.

Same file names, titles, axes and styles as the original figures; each line is
the mean over seeds with min-max shading. --model go (default) writes
report/fig*.png; --model onur-paper writes report/repro/fig*.png.
"""
import argparse
import csv
import math
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
DATA = HERE / 'data'
BLUE, ORANGE = 'tab:blue', 'tab:orange'


def load(family):
    with open(DATA / f'{family}.csv') as f:
        return list(csv.DictReader(f))


def series(rows, x, y, scale=1.0, **match):
    groups = defaultdict(list)
    for r in rows:
        if all(str(r[k]) == str(v) for k, v in match.items()):
            v = float(r[y])
            if not math.isnan(v) and not math.isinf(v):
                groups[r[x]].append(v * scale)
    xs = sorted(groups, key=lambda k: float(k) if k.replace('.', '').isdigit() else k)
    return (xs, [statistics.mean(groups[k]) for k in xs],
            [min(groups[k]) for k in xs], [max(groups[k]) for k in xs])


def numeric(xs):
    return [float(v) for v in xs]


def line(ax, s, label, color, marker='o', categorical=False):
    xs, mean, lo, hi = s
    xv = list(range(len(xs))) if categorical else numeric(xs)
    h, = ax.plot(xv, mean, marker=marker, color=color, label=label)
    ax.fill_between(xv, lo, hi, color=color, alpha=0.2, linewidth=0)
    if categorical:
        ax.set_xticks(xv, xs)
    return h


def two_lines(name, title, xlabel, ylabel, a, b, legend='best', categorical=False, zero=False):
    fig, ax = plt.subplots()
    line(ax, a[0], a[1], BLUE, categorical=categorical)
    line(ax, b[0], b[1], ORANGE, categorical=categorical)
    if zero:
        ax.set_ylim(bottom=0)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.legend(loc=legend)
    save(fig, name)


def one_line(name, title, xlabel, ylabel, s, zero=False):
    fig, ax = plt.subplots()
    line(ax, s, None, BLUE)
    if zero:
        ax.set_ylim(bottom=0)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    save(fig, name)


def tradeoff(name, rows, scenario, model):
    fig, ax = plt.subplots()
    starve = series(rows, 'capacity', 'honest_starvation_rate', model=model, scenario=scenario)
    share = series(rows, 'capacity', 'avg_attacker_cache_share', model=model, scenario=scenario)
    h1 = line(ax, starve, 'Honest starvation', BLUE)
    ax.set_xlabel('Ad cache capacity C')
    ax.set_ylabel('Honest starvation rate')
    ax2 = ax.twinx()
    h2 = line(ax2, share, 'Attacker cache share', BLUE, marker='s')
    ax2.set_ylabel('Average attacker cache share')
    ax.set_title('Cache size trade-off')
    ax.legend([h1, h2], ['Honest starvation', 'Attacker cache share'], loc='upper right')
    save(fig, name)


OUT = HERE


def save(fig, name):
    fig.tight_layout()
    fig.savefig(OUT / f'{name}.png', dpi=200)
    plt.close(fig)


def main():
    global OUT
    p = argparse.ArgumentParser()
    p.add_argument('--model', default='go', choices=['go', 'onur-paper'])
    args = p.parse_args()
    m = args.model
    OUT = HERE if m == 'go' else HERE / 'repro'
    OUT.mkdir(exist_ok=True)
    C = 1000
    hours = 1 / 3600
    pocc, cap, pre = load('pocc'), load('capacity'), load('prefix')
    pop, rate = load('popularity'), load('rate')
    px, pl = 'Occupancy exponent Pocc', 'p_occ'

    two_lines('fig1_q1_cache_attacker_share', 'Average attacker cache share vs Pocc', px,
              'Average attacker cache share',
              (series(pocc, pl, 'avg_attacker_cache_share', model=m, scenario='co'), 'Full admission control'),
              (series(pocc, pl, 'avg_attacker_cache_share', model=m, scenario='co-occ'), 'Occupancy only'))
    two_lines('fig2_q1_cache_utilisation', 'Average cache utilisation (%) vs Pocc', px,
              'Average cache utilisation (%)',
              (series(pocc, pl, 'avg_cache_utilisation', 100, model=m, scenario='co'), 'Full admission control'),
              (series(pocc, pl, 'avg_cache_utilisation', 100, model=m, scenario='co-occ'), 'Occupancy only'))
    two_lines('fig3_q1_target_attacker_share', 'Target attacker cache share vs Pocc', px,
              'Target attacker cache share',
              (series(pocc, pl, 'avg_target_attacker_cache_share', model=m, scenario='tt'), 'Full admission control'),
              (series(pocc, pl, 'avg_target_attacker_cache_share', model=m, scenario='tt-occ'), 'Occupancy only'))
    two_lines('fig4_q1_target_honest_delay', 'Target honest p95 registration delay (hours) vs Pocc', px,
              'Target honest p95 registration delay (hours)',
              (series(pocc, pl, 'target_honest_p95_delay', hours, model=m, scenario='tt'), 'Full admission control'),
              (series(pocc, pl, 'target_honest_p95_delay', hours, model=m, scenario='tt-occ'), 'Occupancy only'))
    benign = series(pocc, pl, 'target_honest_p95_delay', hours, model=m, scenario='benign')
    two_lines('fig_q1_target_honest_delay_benign_vs_attack', 'Target honest p95 registration delay (hours) vs Pocc',
              px, 'Target honest p95 registration delay (hours)',
              (benign, 'Benign high target-topic demand'),
              (series(pocc, pl, 'target_honest_p95_delay', hours, model=m, scenario='tt'), 'Target-topic attack'))

    def flat(key, scale):
        # FIFO does not depend on Pocc: one value per seed, drawn across the Pocc axis.
        vals = [float(r[key]) * scale for r in pocc if r['model'] == 'fifo' and int(r['capacity']) == C]
        xs = benign[0]
        return xs, [statistics.mean(vals)] * len(xs), [min(vals)] * len(xs), [max(vals)] * len(xs)

    two_lines('fig_q1_fifo_vs_admission_target_honest_delay', 'Target honest p95 registration delay (hours) vs Pocc',
              px, 'Target honest p95 registration delay (hours)',
              (benign, 'Admission control'), (flat('target_honest_p95_delay', hours), 'FIFO cache baseline'))
    two_lines('fig_q1_fifo_vs_admission_cache_utilisation', 'Average cache utilisation (%) vs Pocc', px,
              'Average cache utilisation (%)',
              (series(pocc, pl, 'avg_cache_utilisation', 100, model=m, scenario='benign'), 'Admission control'),
              (flat('avg_cache_utilisation', 100), 'FIFO cache baseline'))

    tradeoff('fig5_q2_cache_capacity_tradeoff', cap, 'co', m)
    tradeoff('fig6_q2_target_capacity_tradeoff', cap, 'tt', m)

    def by_prefix(key, ip):
        s = series(pre, 'attacker_prefix', key, model=m, use_ip_score=ip)
        order = ['/24', '/16', '/8', 'diverse']
        idx = [s[0].index(k) for k in order]
        return tuple([order] + [[col[i] for i in idx] for col in s[1:]])

    two_lines('fig7_q3_ip_attacker_share', 'Average attacker cache share vs attacker prefix diversity',
              'Attacker IP prefix diversity', 'Average attacker cache share',
              (by_prefix('avg_attacker_cache_share', True), 'IP score on'),
              (by_prefix('avg_attacker_cache_share', False), 'IP score off'), categorical=True)
    two_lines('fig8_q3_ip_attacker_attempts', 'Attacker attempts per admission vs attacker prefix diversity',
              'Attacker IP prefix diversity', 'Attacker attempts per admission',
              (by_prefix('attacker_attempts_per_admission', True), 'IP score on'),
              (by_prefix('attacker_attempts_per_admission', False), 'IP score off'), categorical=True,
              zero=m == 'go')

    fx, fl = 'Fraction of honest registrations using target topic', 'honest_target_topic_fraction'
    two_lines('fig9_q4_popular_topic_delay', 'Target-topic honest p95 delay (hours) vs honest target-topic popularity',
              fx, 'Target-topic honest p95 delay (hours)',
              (series(pop, fl, 'target_honest_p95_delay', hours, model=m, use_topic_score=True), 'Topic score on'),
              (series(pop, fl, 'target_honest_p95_delay', hours, model=m, use_topic_score=False), 'Topic score off'))
    two_lines('fig10_q4_popular_topic_share', 'Target-topic honest cache share vs honest target-topic popularity',
              fx, 'Target-topic honest cache share',
              (series(pop, fl, 'avg_target_honest_cache_share', model=m, use_topic_score=True), 'Topic score on'),
              (series(pop, fl, 'avg_target_honest_cache_share', model=m, use_topic_score=False), 'Topic score off'))

    rx, rl = 'Attacker registration rate', 'attacker_rate'
    one_line('fig11_q5_cache_intensity_share', 'Average attacker cache share vs attacker rate', rx,
             'Average attacker cache share', series(rate, rl, 'avg_attacker_cache_share', model=m, scenario='co'))
    one_line('fig12_q5_cache_intensity_cost', 'Attacker attempts per admission vs attacker rate', rx,
             'Attacker attempts per admission',
             series(rate, rl, 'attacker_attempts_per_admission', model=m, scenario='co'), zero=m == 'go')
    one_line('fig13_q5_target_intensity_share', 'Target attacker cache share vs attacker rate', rx,
             'Target attacker cache share',
             series(rate, rl, 'avg_target_attacker_cache_share', model=m, scenario='tt'))
    one_line('fig14_q5_target_intensity_cost', 'Attacker attempts per admission vs attacker rate', rx,
             'Attacker attempts per admission',
             series(rate, rl, 'attacker_attempts_per_admission', model=m, scenario='tt'), zero=m == 'go')


if __name__ == '__main__':
    main()
