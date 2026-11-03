#!/usr/bin/env python3
"""Drive Onur's admission model and our Go-faithful model with the same traffic.

Models: onur-paper (unmodified), onur-current (current waiting-time function in
Onur's mechanics), go (sim-admission registrar + topdisc 703d5a2: #170, #173, #177). Run with
python3 -I compare.py [--smoke | --grid].
"""
import argparse
import bisect
import csv
import importlib.util
import json
import math
import multiprocessing as mp
import statistics
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ONUR_PATH = HERE.parent / 'admission_sim.py'
GO_PATH = HERE.parent / 'registrar.py'
HONEST_IPS = HERE.parent / 'data/all.json'
MODELS = ('onur-paper', 'onur-current', 'go')
MAX_WORKERS = 12
# Loading by path would otherwise write .pyc files next to the read-only sources.
sys.dont_write_bytecode = True


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


onur = _load('admission_sim', ONUR_PATH)
gor = _load('go_registrar', GO_PATH)


def ns(seconds):
    return round(seconds * gor.SECOND)


class CurrentRegistrar(onur.Registrar):
    """Onur's registrar with only the waiting-time function replaced."""

    def required_wait(self, req, now):
        c = len(self.cache)
        C = self.cfg.capacity
        if c >= C:
            return self.cfg.ad_lifetime
        base = 0.1 * self.cfg.ad_lifetime / (1.0 - c / C) ** self.cfg.p_occ
        service = self.topic_counts[req.topic] / (c + 1) if self.cfg.use_topic_score else 0.0
        score = self._ip_penalty(req.ip)
        required = base * service + base * score + base * self.cfg.g_safety
        return max(0.0, required - (now - req.first_attempt_time))


class GoTable(gor.Registrar):
    """sim-admission port plus topdisc 703d5a2: scaleBase (#170) and the ticket
    sealing key lifecycle of ticket.go. The base class already drops a topic's
    bound with its last ad (#177) and expires ads at the request's now (#173)."""

    REKEY = 100000
    KEY_LIFETIME = 6 * 3600 * gor.SECOND

    def __init__(self, config, *, ip_score=True, topic_score=True):
        super().__init__(config, ip_score=ip_score)
        self.topic_score = topic_score
        # Keys in creation order: first ticket serial and last issuance time.
        self.key_starts, self.key_last, self.key_uses, self.live_key = [], [], 0, 0

    def request(self, node, topic, ip, now, ticket=None, attacker=False):
        self._gc_keys(now)
        if isinstance(ticket, gor.Ticket) and bisect.bisect_right(self.key_starts, ticket.serial) - 1 < self.live_key:
            # v5_udp.go: a ticket whose key is gone fails to unpack, so the
            # request is a new attempt without credit.
            self.ticket_timings['unknown_key'] += 1
            ticket = None
        reply = super().request(node, topic, ip, now, ticket, attacker)
        if reply.ticket is not None and reply.ticket is not ticket:
            self._seal(reply.ticket.serial, now)
        return reply

    def _gc_keys(self, now):
        while self.live_key < len(self.key_last) and self.key_last[self.live_key] <= now - self.KEY_LIFETIME:
            self.live_key += 1

    def _seal(self, serial, now):
        if self.live_key == len(self.key_starts) or self.key_uses >= self.REKEY:
            self.key_starts.append(serial)
            self.key_last.append(now)
            self.key_uses = 1
        else:
            self.key_last[-1] = now
            self.key_uses += 1

    def components(self, topic, ip, now):
        count = len(self.ads)
        inverse_occupancy = 1 - count / self.config.capacity
        base = (self.config.base * (self.config.lifetime / gor.SECOND)
                / inverse_occupancy ** self.config.exponent
                if inverse_occupancy > 0 else math.inf)
        topic_mod = self.topics[topic] / (count + 1) if self.topic_score else 0.0
        service = base * topic_mod if topic_mod > 0 else 0.0
        score, lpm, floor = 0.0, None, 0
        if self.ip_score and gor.scored_ip(ip):
            score, lpm = self.tree.score_node(ip)
            floor = self.tree.path_floor(ip, now)
        ip_secs = base * score if score > 0 else 0.0
        charged_service, charged_ip = service, ip_secs
        topic_floor = self.topic_bounds.get(topic)
        if topic_floor and topic_floor.remaining(now) / gor.SECOND > charged_service:
            charged_service = topic_floor.remaining(now) / gor.SECOND
        if floor / gor.SECOND > charged_ip:
            charged_ip = floor / gor.SECOND
        needed = charged_service + charged_ip + base * self.config.safety
        return gor.duration(needed), service, ip_secs, lpm


class GoAdapter:
    """Serves Onur's attempt events with GoTable.request; exposes the cache
    shape that Onur's Metrics.sample reads."""

    def __init__(self, cfg, give_up=False):
        self.cfg = cfg
        self.config = gor.Config(capacity=cfg.capacity, safety=cfg.g_safety,
                                 lifetime=ns(cfg.ad_lifetime), base=0.1, exponent=cfg.p_occ)
        self.table = GoTable(self.config, ip_score=cfg.use_ip_score, topic_score=cfg.use_topic_score)
        self.give_up = give_up
        self.cache = {}
        self.ad_keys = {}
        self.expiry_ns = {}
        self.next_ad_id = 0
        self.fifo_queue = ()
        self.stats = {'abandon_events_honest': 0, 'abandon_events_attacker': 0,
                      'abandoned_req_honest': 0, 'abandoned_req_attacker': 0,
                      'existing_honest': 0, 'existing_attacker': 0, 'early_echoes': 0}
        self.abandoned = set()

    def try_register(self, req, now):
        req.attempt_count += 1
        t = ns(now)
        ticket = getattr(req, 'ticket', None)
        reply = self.table.request(req.advertiser_id, req.topic, gor.ipv4(req.ip), t,
                                   ticket, attacker=req.is_attacker)
        who = 'attacker' if req.is_attacker else 'honest'
        if reply.status == 'admitted':
            ad_id = self.next_ad_id
            self.next_ad_id += 1
            self.cache[ad_id] = onur.CachedAd(ad_id, req, now, now + self.cfg.ad_lifetime)
            self.ad_keys[ad_id] = (req.advertiser_id, req.topic)
            self.expiry_ns[ad_id] = t + self.config.lifetime
            return 'admitted', self.cfg.ad_lifetime, ad_id
        if reply.status == 'existing':
            # Go answers as for an admission (WaitTime E, no ticket) and the
            # client treats it as registered (v5_topic.go HandleRegistered).
            # The ad already in the cache keeps its own renewal, so this
            # request ends here: ad_id None makes its expiry a no-op.
            self.stats['existing_' + who] += 1
            req.ticket, req.total_wait = None, 0
            return 'admitted', self.cfg.ad_lifetime, None
        if ticket is not None and reply.ticket is ticket:
            self.stats['early_echoes'] += 1
        total = getattr(req, 'total_wait', 0)
        if self.give_up == 'all' or (self.give_up == 'honest' and not req.is_attacker):
            wait = gor.retry_wait(reply, total, self.config)
            if wait is None:
                # As in sim-admission: drop this registrar, revisit after E with
                # a fresh attempt; the delay keeps counting from the first attempt.
                self.stats['abandon_events_' + who] += 1
                if req.req_id not in self.abandoned:
                    self.abandoned.add(req.req_id)
                    self.stats['abandoned_req_' + who] += 1
                req.ticket, req.total_wait = None, 0
                return 'wait', self.cfg.ad_lifetime, None
        else:
            wait = max(gor.SECOND, reply.wait)
        req.ticket, req.total_wait = reply.ticket, total + wait
        # The client never retries sooner than 1 s; 2 ns over so float->ns
        # rounding never lands before the window.
        return 'wait', (max(gor.SECOND, reply.wait) + 2) / gor.SECOND, None

    def expire_ad(self, ad_id):
        ad = self.cache.pop(ad_id, None)
        if ad is None:
            return None
        self.table.expire(self.expiry_ns.pop(ad_id))
        del self.ad_keys[ad_id]
        return ad.request


class CompareMetrics(onur.Metrics):
    """Onur's metrics plus admission of new (non-renewal) requests."""

    def __init__(self, cfg):
        super().__init__(cfg)
        self.new_admitted = {False: 0, True: 0}

    def on_admitted(self, req, now, cfg):
        super().on_admitted(req, now, cfg)
        if not req.is_renewal:
            self.new_admitted[req.is_attacker] += 1

    def summary(self):
        row = super().summary()
        for attacker, who in ((False, 'honest'), (True, 'attacker')):
            started = getattr(self, who + '_new_started')
            row[who + '_new_admitted_fraction'] = (self.new_admitted[attacker] / started
                                                   if started else float('nan'))
        row['honest_waiting_at_end'] = self.honest_started - self.honest_admitted
        return row


class CompareSim(onur.Simulator):
    def __init__(self, cfg, honest_ips, model, give_up=False, record_arrivals=False):
        super().__init__(cfg, honest_ips)
        self.metrics = CompareMetrics(cfg)
        if model == 'onur-current':
            self.registrar = CurrentRegistrar(cfg)
        elif model == 'go':
            self.registrar = GoAdapter(cfg, give_up=give_up)
        elif model != 'onur-paper':
            raise ValueError(model)
        self.arrivals = [] if record_arrivals else None

    def _record(self, now, req):
        if self.arrivals is not None:
            # Honest IDs come from a counter that renewals also advance; they stay unique.
            label = req.advertiser_id if req.is_attacker else 'h'
            self.arrivals.append((now, label, req.ip, req.topic, req.is_attacker))
        return req

    def make_honest_request(self, now):
        return self._record(now, super().make_honest_request(now))

    def make_attacker_request(self, now):
        return self._record(now, super().make_attacker_request(now))


_IPS = None


def honest_ips(limit=5000):
    global _IPS
    if _IPS is None:
        _IPS = onur.load_ips_from_json(str(HONEST_IPS), limit=limit)
    return _IPS


COMMON = dict(honest_rate=0.05, attacker_rate=0.2, honest_topic_popularity='uniform', attacker_prefix='/24')
EXPERIMENTS = {
    'co300': dict(attack='cache_occupation'),
    'co10k': dict(attack='cache_occupation', n_attacker_topics=10000),
    'co10k-noip': dict(attack='cache_occupation', n_attacker_topics=10000, use_ip_score=False),
    'tt': dict(attack='target_topic', honest_target_topic_fraction=0.5),
    'co300-p16': dict(attack='cache_occupation', attacker_prefix='/16'),
    'co300-p8': dict(attack='cache_occupation', attacker_prefix='/8'),
    'co300-diverse': dict(attack='cache_occupation', attacker_prefix='diverse'),
}


def make_cfg(experiment, capacity, seed, p_occ=10.0, runtime=24 * 3600):
    return onur.SimConfig(**{**COMMON, **EXPERIMENTS[experiment]}, capacity=capacity,
                          seed=seed, p_occ=p_occ, runtime=runtime)


GIVE_UP_LABELS = {None: '', 'all': '+give-up', 'honest': '+honest-give-up'}


def run_case(case):
    started = time.time()
    cfg = make_cfg(case['experiment'], case['capacity'], case['seed'],
                   case.get('p_occ', 10.0), case.get('runtime', 24 * 3600))
    sim = CompareSim(cfg, honest_ips(), case['model'], give_up=case.get('give_up', False))
    row = sim.run().summary()
    if isinstance(sim.registrar, GoAdapter):
        row.update(sim.registrar.stats)
        row.update({'ticket_' + k: v for k, v in sim.registrar.table.ticket_timings.items()})
    row.update(case)
    row['model_label'] = case['model'] + GIVE_UP_LABELS[case.get('give_up') or None]
    row['p_occ'] = cfg.p_occ
    row['wall_s'] = round(time.time() - started, 1)
    return row


def grid_cases():
    cases = []
    for experiment in EXPERIMENTS:
        for capacity in (1000, 5000):
            for seed in (1, 2, 3):
                for model in MODELS:
                    cases.append(dict(experiment=experiment, capacity=capacity, seed=seed, model=model))
                for give_up in ('all', 'honest'):
                    cases.append(dict(experiment=experiment, capacity=capacity, seed=seed,
                                      model='go', give_up=give_up))
    for experiment in ('co300', 'tt'):
        for p_occ in (1, 2, 4, 6, 8, 12):
            for seed in (1, 2, 3):
                for model in ('onur-current', 'go'):
                    cases.append(dict(experiment=experiment, capacity=5000, seed=seed,
                                      model=model, p_occ=float(p_occ)))
    return cases


def smoke_cases():
    return [dict(experiment='co300', capacity=1000, seed=1, model=m, runtime=3 * 3600)
            for m in MODELS] + [dict(experiment='co300', capacity=1000, seed=1, model='go',
                                     give_up=g, runtime=3 * 3600) for g in ('all', 'honest')]


def run_cases(cases, workers, out=None, log=None):
    rows = []
    # Longest first, so the tail is short.
    order = sorted(cases, key=lambda c: (c['capacity'], c['model'] == 'go'), reverse=True)
    with mp.get_context('fork').Pool(min(workers, MAX_WORKERS, len(cases))) as pool:
        for row in pool.imap_unordered(run_case, order):
            rows.append(row)
            if log:
                print(f"[{len(rows)}/{len(cases)}] {row['experiment']} C={row['capacity']} "
                      f"{row['model_label']} p={row['p_occ']:g} s={row['seed']} "
                      f"atk={row['avg_attacker_cache_share']:.3f} wall={row['wall_s']}s", flush=True)
            if out:
                write_csv(out, rows)
    return rows


def write_csv(path, rows):
    fields = list(dict.fromkeys(k for row in rows for k in row))
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path):
    with open(path) as f:
        return list(csv.DictReader(f))


# ---------------------------------------------------------------------------
# RESULTS.md

METRICS = [
    ('avg_attacker_cache_share', 'attacker cache share', 'pct'),
    ('honest_p95_delay', 'honest p95 delay (s)', 'sec'),
    ('target_honest_p95_delay', 'target-topic honest p95 (s)', 'sec'),
    ('avg_cache_utilisation', 'utilisation', 'pct'),
    ('honest_attempts_per_admission', 'honest attempts/admission', 'num'),
    ('honest_starvation_rate', 'honest starvation > 2E', 'pct'),
    ('honest_success_rate', 'honest admitted / started', 'pct'),
    ('honest_new_admitted_fraction', 'new honest requests admitted', 'pct'),
]
LABELS = ('onur-paper', 'onur-current', 'go', 'go+give-up', 'go+honest-give-up')
TITLES = {
    'co300': 'Cache occupation, 300 attacker topics (/24)',
    'co10k': 'Cache occupation, 10,000 attacker topics (/24, IP score on)',
    'co10k-noip': 'Cache occupation, 10,000 attacker topics (/24, IP score off)',
    'tt': 'Target topic, honest target fraction 0.5',
}


def fmt(values, kind):
    values = [v for v in values if not math.isnan(v)]
    if not values:
        return 'n/a'
    mean, lo, hi = statistics.mean(values), min(values), max(values)
    if kind == 'pct':
        return f'{100 * mean:.1f}% ({100 * lo:.1f}–{100 * hi:.1f})'
    if kind == 'sec':
        return f'{mean:,.0f} ({lo:,.0f}–{hi:,.0f})'
    return f'{mean:.2f} ({lo:.2f}–{hi:.2f})'


def select(rows, **match):
    return [r for r in rows if all(str(r[k]) == str(v) for k, v in match.items())]


def table(rows, experiment, metrics, labels=LABELS, p_occ='10.0'):
    head = '| metric | ' + ' | '.join(f'{lab} C={c}' for c in (1000, 5000) for lab in labels) + ' |'
    lines = [head, '|' + '---|' * (1 + 2 * len(labels))]
    for key, name, kind in metrics:
        cells = []
        for c in (1000, 5000):
            for lab in labels:
                sel = select(rows, experiment=experiment, capacity=c, model_label=lab, p_occ=p_occ)
                cells.append(fmt([float(r[key]) for r in sel], kind) if sel else '–')
        lines.append(f'| {name} | ' + ' | '.join(cells) + ' |')
    return '\n'.join(lines)


def prefix_table(rows):
    lines = ['| prefix | ' + ' | '.join(f'{lab} C={c}' for c in (1000, 5000) for lab in LABELS) + ' |',
             '|' + '---|' * (1 + 2 * len(LABELS))]
    for experiment, prefix in (('co300', '/24'), ('co300-p16', '/16'), ('co300-p8', '/8'),
                               ('co300-diverse', 'diverse')):
        cells = []
        for c in (1000, 5000):
            for lab in LABELS:
                sel = select(rows, experiment=experiment, capacity=c, model_label=lab, p_occ='10.0')
                cells.append(fmt([float(r['avg_attacker_cache_share']) for r in sel], 'pct'))
        lines.append(f'| {prefix} | ' + ' | '.join(cells) + ' |')
    return '\n'.join(lines)


def pocc_table(rows, experiment, key, kind):
    lines = ['| Pocc | onur-current | go |', '|---|---|---|']
    for p in (1, 2, 4, 6, 8, 10, 12):
        cells = [fmt([float(r[key]) for r in select(rows, experiment=experiment, capacity=5000,
                                                     model_label=m, p_occ=f'{p:.1f}')], kind)
                 for m in ('onur-current', 'go')]
        lines.append(f'| {p} | ' + ' | '.join(cells) + ' |')
    return '\n'.join(lines)


def giveup_table(rows):
    lines = ['| experiment | C | model | honest requests abandoned / started | attacker requests abandoned / started '
             '| abandon events honest | abandon events attacker |', '|---|---|---|---|---|---|---|']
    for experiment in EXPERIMENTS:
        for c in (1000, 5000):
            for label in ('go+give-up', 'go+honest-give-up'):
                sel = select(rows, experiment=experiment, capacity=c, model_label=label)
                if sel:
                    lines.append(giveup_row(experiment, c, label, sel))
    return '\n'.join(lines)


def giveup_row(experiment, c, label, sel):
    mean = lambda k: statistics.mean(float(r[k]) for r in sel)
    return (f'| {experiment} | {c} | {label} | {mean("abandoned_req_honest"):,.0f} / {mean("honest_started"):,.0f} | '
            f'{mean("abandoned_req_attacker"):,.0f} / {mean("attacker_started"):,.0f} | '
            f'{mean("abandon_events_honest"):,.0f} | {mean("abandon_events_attacker"):,.0f} |')


NOTES, END_NOTES = '## Notes', '<!-- end notes -->'


def write_results(rows, path):
    parts = ['# Same traffic, two admission models\n',
             'Generated by `python3 -I compare.py --report`. Cells: mean (min–max) over seeds 1, 2, 3. '
             'Traffic: Onur\'s workload (honest 0.05/s, attacker 0.2/s, uniform honest topics, all.json IPs, '
             '24 h). Pocc 10 unless stated.\n',
             'How to read every table:\n\n'
             '- Only new arrivals are shared: the same seed gives every model the same arrival times, IPs, '
             'topics and attacker IDs. Renewals (one per expired ad) and retries depend on each model\'s '
             'admissions, so total traffic differs by model.\n'
             '- "honest admitted / started" (Onur\'s success rate) counts renewals in the denominator, so its '
             'population differs by model. "new honest requests admitted" uses new arrivals only, which are '
             'the same in every model.\n'
             '- Delay percentiles and starvation (> 2E) count admitted requests only. Requests still waiting '
             'at the 24 h horizon appear in neither. go quotes up to 24 h while Onur caps a quote at E, so go '
             'can leave more slow requests out of these rows.\n'
             '- go: attackers wait out every quote. go+give-up: every request, attacker or honest, follows '
             'the client\'s 1.5·E budget. go+honest-give-up: only honest requests follow it.\n']
    for experiment, title in TITLES.items():
        metrics = METRICS if experiment == 'tt' else [m for m in METRICS if m[0] != 'target_honest_p95_delay']
        if experiment == 'tt':
            metrics = metrics + [('avg_target_attacker_share_within_target', 'attacker share within target', 'pct')]
        parts.append(f'## {title}\n\n{table(rows, experiment, metrics)}\n')
    parts.append(f'## Attacker prefix sweep (cache occupation, 300 topics): attacker cache share\n\n{prefix_table(rows)}\n')
    for experiment, title in (('co300', 'cache occupation, 300 topics'), ('tt', 'target topic')):
        for key, name, kind in (('avg_attacker_cache_share', 'attacker cache share', 'pct'),
                                ('honest_p95_delay', 'honest p95 delay (s)', 'sec'),
                                ('avg_cache_utilisation', 'utilisation', 'pct')) + (
                (('target_honest_p95_delay', 'target-topic honest p95 (s)', 'sec'),) if experiment == 'tt' else ()):
            parts.append(f'## Pocc sweep, C=5000, {title}: {name}\n\n{pocc_table(rows, experiment, key, kind)}\n')
    parts.append(f'## go with --give-up: abandoned requests (mean over seeds)\n\n{giveup_table(rows)}\n')
    # Keep the hand-written notes across regenerations.
    old = Path(path).read_text() if Path(path).exists() else ''
    if NOTES in old:
        parts.insert(3, old[old.index(NOTES):old.index(END_NOTES) + len(END_NOTES)] + '\n')
    Path(path).write_text('\n'.join(parts))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--smoke', action='store_true')
    p.add_argument('--grid', action='store_true')
    p.add_argument('--report', action='store_true', help='write RESULTS.md from the grid CSV')
    p.add_argument('--workers', type=int, default=MAX_WORKERS)
    p.add_argument('--output', default=str(HERE / 'grid.csv'))
    p.add_argument('--model', choices=MODELS)
    p.add_argument('--experiment', choices=list(EXPERIMENTS), default='co300')
    p.add_argument('--capacity', type=int, default=1000)
    p.add_argument('--p-occ', type=float, default=10.0)
    p.add_argument('--seed', type=int, default=1)
    p.add_argument('--runtime', type=float, default=24 * 3600)
    p.add_argument('--give-up', nargs='?', const='all', choices=['all', 'honest'])
    args = p.parse_args()
    if args.smoke:
        started = time.time()
        for row in run_cases(smoke_cases(), args.workers):
            print(f"{row['model_label']:16s} atk={row['avg_attacker_cache_share']:.3f} "
                  f"hp95={row['honest_p95_delay']:.0f} util={row['avg_cache_utilisation']:.3f} "
                  f"abandoned={row.get('abandoned_req_honest', '-')}/{row.get('abandoned_req_attacker', '-')} "
                  f"wall={row['wall_s']}s")
        print(f'smoke total {time.time() - started:.1f}s')
    elif args.grid:
        rows = run_cases(grid_cases(), args.workers, out=args.output, log=True)
        write_results(rows, HERE / 'RESULTS.md')
    elif args.report:
        write_results(read_csv(args.output), HERE / 'RESULTS.md')
    elif args.model:
        row = run_case(dict(experiment=args.experiment, capacity=args.capacity, seed=args.seed,
                            model=args.model, p_occ=args.p_occ, runtime=args.runtime,
                            give_up=args.give_up))
        print(json.dumps(row, indent=1, default=str))
    else:
        p.print_help()


if __name__ == '__main__':
    main()
