import sys

sys.dont_write_bytecode = True

import csv
import importlib.util
import math
import subprocess
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('compare', HERE / 'compare.py')
compare = importlib.util.module_from_spec(spec)
sys.modules['compare'] = compare
spec.loader.exec_module(compare)
onur, gor = compare.onur, compare.gor
S = gor.SECOND


def same(a, b):
    a, b = float(a), float(b)
    return (math.isnan(a) and math.isnan(b)) or a == b


def test_onur_paper_matches_script(tmp_path):
    # REPRO.md §6.2 cache occupation, C=1000, seed 1.
    out = tmp_path / 'direct.csv'
    subprocess.run([sys.executable, '-I', str(compare.ONUR_PATH), '--honest-ips', str(compare.HONEST_IPS),
                    '--honest-rate', '0.05', '--attacker-rate', '0.2', '--honest-topic-popularity', 'uniform',
                    '--attacker-prefix', '/24', '--attack', 'cache_occupation', '--seed', '1',
                    '--output', str(out)], check=True, capture_output=True)
    direct = next(csv.DictReader(out.open()))
    ours = compare.run_case(dict(experiment='co300', capacity=1000, seed=1, model='onur-paper'))
    keys = [k for k in onur.Metrics(onur.SimConfig()).summary()]
    assert all(same(direct[k], ours[k]) for k in keys), [k for k in keys if not same(direct[k], ours[k])]
    assert round(float(ours['honest_p95_delay'])) == 21122
    assert round(100 * float(ours['avg_attacker_cache_share']), 1) == 38.2


def expected_wait():
    base = 0.1 * 900 / (1 - 2500 / 5000) ** 10
    return base * 10 / 2501 + base * 0.5 + base * 1e-7


def test_onur_current_matches_go_formula():
    assert expected_wait() == pytest.approx(368.4926029588 + 46080 + 0.009216, abs=1e-6)
    cfg = onur.SimConfig(capacity=5000, p_occ=10.0)
    reg = compare.CurrentRegistrar(cfg)
    req = onur.AdRequest(0, 'n', '8.8.8.8', 'T', False, first_attempt_time=0.0)
    reg.cache = {i: None for i in range(2500)}
    reg.topic_counts['T'] = 10
    reg._ip_penalty = lambda ip: 0.5
    assert reg.required_wait(req, 0.0) == pytest.approx(expected_wait(), rel=1e-12)
    assert reg.required_wait(req, 100.0) == pytest.approx(expected_wait() - 100, rel=1e-12)

    table = compare.GoTable(gor.Config(capacity=5000, safety=1e-7))
    table.ads = {(i, 'X'): None for i in range(2500)}
    table.topics['T'] = 10
    table.tree.score_node = lambda ip: (0.5, None)
    table.tree.path_floor = lambda ip, now: 0
    required = table.components('T', gor.ipv4('8.8.8.8'), 0)[0]
    assert abs(required - expected_wait() * S) <= 1


def arrivals(model, give_up=False):
    cfg = compare.make_cfg('tt', 1000, seed=7, runtime=3 * 3600)
    sim = compare.CompareSim(cfg, compare.honest_ips(), model, give_up=give_up, record_arrivals=True)
    sim.run()
    return sim.arrivals


def test_same_seed_same_arrivals():
    ref = arrivals('onur-paper')
    assert len(ref) > 1000
    for model in ('onur-current', 'go'):
        assert arrivals(model) == ref
    assert arrivals('go', give_up='all') == ref
    assert arrivals('go', give_up='honest') == ref


def test_go_topic_bound_dropped_with_last_ad():
    # #177: the topic's bound goes with its last ad, so the next request for
    # the topic pays only base·G plus its IP component.
    cfg = gor.Config(capacity=2, safety=1e-7)
    ip_a, ip_b = gor.ipv4('8.8.8.8'), gor.ipv4('9.9.9.9')
    t = compare.GoTable(cfg)
    assert t.request('a', 'T', ip_a, 0).status == 'admitted'
    assert t.request('b', 'T', ip_b, S).status == 'quote'
    bound = t.topic_bounds['T']
    assert bound.value == gor.duration(92160 / 2)

    now = 901 * S
    assert bound.remaining(now) > 40000 * S
    t.expire(now)
    assert not t.ads and 'T' not in t.topics and 'T' not in t.topic_bounds
    assert t.components('T', ip_b, now)[0] < S


def test_go_expired_ads_pruned_at_request_time():
    # #173: an ad past its expiry neither counts as registered nor toward
    # occupancy when the next request arrives, even if expire() was not called.
    t = compare.GoTable(gor.Config(capacity=1, safety=1e-7))
    assert t.request('a', 'T', gor.ipv4('8.8.8.8'), 0).status == 'admitted'
    assert t.request('a', 'T', gor.ipv4('8.8.8.8'), S).status == 'existing'
    reply = t.request('a', 'T', gor.ipv4('8.8.8.8'), 900 * S)
    assert reply.status == 'admitted' and len(t.ads) == 1


def test_go_adapter_retries_on_time():
    cfg = compare.make_cfg('co300', 1000, seed=1, runtime=3 * 3600)
    sim = compare.CompareSim(cfg, compare.honest_ips(), 'go')
    sim.run()
    timings = sim.registrar.table.ticket_timings
    assert timings['on_time'] > 0
    assert timings['early'] == timings['late'] == timings['expired'] == 0


def rollover_case(rekey):
    table = compare.GoTable(gor.Config(capacity=3, safety=1e-7))
    table.REKEY = rekey
    ip = lambda k: gor.ipv4(f'8.8.{k}.1')
    table.add('a', 'T', ip(1), 0)
    table.add('x', 'T', ip(2), 0)
    quote = table.request('b', 'T', ip(3), S)
    assert quote.status == 'quote' and quote.ticket.wait > table.KEY_LIFETIME
    start = quote.ticket.start

    def fill(i, at):
        table.add(f'y{i}', 'T', ip(4), at)
        table.add(f'z{i}', 'T', ip(5), at)

    # Issue a ticket every 5 h so a non-rotated key stays alive (6 h lifetime).
    for i, hours in enumerate((5, 10, 15, 20)):
        at = hours * 3600 * S
        fill(i, at - S)
        assert table.request(f'd{i}', 'T', ip(6), at).status == 'quote'
    fill('end', start - S)
    return table, table.request('b', 'T', ip(3), start, quote.ticket), start


def test_ticket_key_rollover_drops_credit():
    table, reply, _ = rollover_case(rekey=100000)
    assert reply.status == 'admitted'
    assert table.ticket_timings['on_time'] == 1 and table.ticket_timings['unknown_key'] == 0

    table, reply, start = rollover_case(rekey=1)
    assert len(table.key_starts) == 6 and table.live_key >= 1
    assert table.ticket_timings['unknown_key'] == 1 and table.ticket_timings['on_time'] == 0
    assert reply.status == 'quote' and reply.ticket.first == start


def test_go_existing_counts_as_registered():
    cfg = compare.make_cfg('co300', 1000, seed=1)
    adapter = compare.GoAdapter(cfg)
    first = onur.AdRequest(1, 'a-1', '8.8.8.8', 'T', True, first_attempt_time=0.0)
    assert adapter.try_register(first, 0.0)[0] == 'admitted'
    dup = onur.AdRequest(2, 'a-1', '9.9.9.9', 'T', True, first_attempt_time=10.0)
    assert adapter.try_register(dup, 10.0) == ('admitted', cfg.ad_lifetime, None)
    assert adapter.stats['existing_attacker'] == 1 and dup.ticket is None
    # No second cache entry, and its expiry neither removes an ad nor renews.
    assert len(adapter.cache) == 1 and adapter.expire_ad(None) is None


def test_honest_only_give_up():
    def stats(give_up):
        cfg = compare.make_cfg('co300', 1000, seed=1, runtime=3 * 3600)
        sim = compare.CompareSim(cfg, compare.honest_ips(), 'go', give_up=give_up)
        sim.run()
        return sim.registrar.stats
    honest, every = stats('honest'), stats('all')
    assert honest['abandon_events_attacker'] == 0 and honest['abandon_events_honest'] > 0
    assert every['abandon_events_attacker'] > 0
