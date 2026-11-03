#!/usr/bin/env python3
"""
Example:

    python3 admission_sim.py \
      --honest-ips all.json \
      --attack target_topic \
      --honest-target-topic-fraction 0.5 \
      --honest-rate 0.005 \
      --attacker-rate 0.02 \
      --attacker-prefix /24 \
      --sweep-pocc \
      --output sweep_pocc_target_topic_lowrate.csv
"""

from __future__ import annotations

import argparse
import base64
import csv
import heapq
import ipaddress
import json
import math
import random
import re
import statistics
import urllib.request
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Iterable, List, Optional, Tuple

use_topic_score: bool = True
use_ip_score: bool = True

# ---------------------------------------------------------------------------
# IP similarity tree
# ---------------------------------------------------------------------------

class IPTreeNode:
    __slots__ = ("left", "right", "counter")

    def __init__(self):
        self.left = None
        self.right = None
        self.counter = 0


class IPTree:
    """
    Python equivalent of the updated Go ipTree.

    score(ip):
      overloaded_prefix_levels / effective_depth

    effective_depth only includes levels where expected balanced occupancy >= 1.
    """

    def __init__(self, bits: int = 32):
        if bits not in (32, 128):
            raise ValueError(f"invalid ipTree bits {bits}")
        self.root = IPTreeNode()
        self.bits = bits

    def _norm_ip_int(self, ip: str) -> int:
        addr = ipaddress.ip_address(ip)

        if self.bits == 32:
            if addr.version != 4:
                raise ValueError("IPTree(bits=32) operation on non-IPv4 address")
            return int(addr)

        if self.bits == 128:
            return int(addr)

        raise ValueError(f"invalid ipTree bits {self.bits}")

    def _ip_bit(self, ip_int: int, depth: int) -> bool:
        shift = self.bits - 1 - depth
        return ((ip_int >> shift) & 1) == 1

    def count(self) -> int:
        return self.root.counter

    def _compute_score(self, overloaded_levels: int, effective_depth: int) -> float:
        if self.count() == 0:
            return 0.0
        if effective_depth == 0:
            return 0.0
        return overloaded_levels / effective_depth

    def score(self, ip: str) -> float:
        ip_int = self._norm_ip_int(ip)

        overloaded_levels = 0
        root_counter = float(self.root.counter)
        effective_depth = 0

        node = self.root
        hit_nil = False

        for depth in range(self.bits):
            balanced = root_counter / (2 ** (depth + 1))
            if balanced < 1:
                break

            effective_depth += 1

            if hit_nil:
                continue

            child = node.left if self._ip_bit(ip_int, depth) else node.right

            if child is None:
                hit_nil = True
                continue

            node = child

            if float(node.counter) > balanced:
                overloaded_levels += 1

        return self._compute_score(overloaded_levels, effective_depth)

    def insert(self, ip: str) -> float:
        ip_int = self._norm_ip_int(ip)

        overloaded_levels = 0
        root_counter = float(self.root.counter)

        self.root.counter += 1
        effective_depth = 0

        node = self.root

        for depth in range(self.bits):
            balanced = root_counter / (2 ** (depth + 1))
            if balanced < 1:
                break

            effective_depth += 1

            if self._ip_bit(ip_int, depth):
                if node.left is None:
                    node.left = IPTreeNode()
                node = node.left
            else:
                if node.right is None:
                    node.right = IPTreeNode()
                node = node.right

            if float(node.counter) > balanced:
                overloaded_levels += 1

            node.counter += 1

        return self._compute_score(overloaded_levels, effective_depth)

    def remove(self, ip: str) -> None:
        ip_int = self._norm_ip_int(ip)

        if self.root.counter <= 0:
            return

        self.root.counter -= 1
        node = self.root

        for depth in range(self.bits):
            go_left = self._ip_bit(ip_int, depth)
            child = node.left if go_left else node.right

            if child is None:
                return

            child.counter -= 1

            if child.counter == 0:
                if go_left:
                    node.left = None
                else:
                    node.right = None
                return

            node = child


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def percentile(values: List[float], p: float) -> float:
    if not values:
        return float("nan")

    xs = sorted(values)
    if len(xs) == 1:
        return xs[0]

    k = (len(xs) - 1) * (p / 100.0)
    lo = int(math.floor(k))
    hi = int(math.ceil(k))

    if lo == hi:
        return xs[lo]

    return xs[lo] * (hi - k) + xs[hi] * (k - lo)


def is_public_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.version == 4 and addr.is_global
    except ValueError:
        return False


def sample_topic(
    rng: random.Random,
    n_topics: int,
    popularity: str,
    zipf_alpha: float,
) -> str:
    if popularity == "uniform":
        return f"topic-{rng.randrange(n_topics)}"

    if popularity == "zipf":
        weights = [1.0 / ((i + 1) ** zipf_alpha) for i in range(n_topics)]
        total = sum(weights)
        x = rng.random() * total

        acc = 0.0
        for i, w in enumerate(weights):
            acc += w
            if acc >= x:
                return f"topic-{i}"

        return f"topic-{n_topics - 1}"

    raise ValueError(f"Unknown topic popularity: {popularity}")


# ---------------------------------------------------------------------------
# ENR / DNS-list IP loading
# ---------------------------------------------------------------------------

def _b64url_decode_nopad(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _rlp_decode_item(data: bytes, pos: int = 0):
    prefix = data[pos]

    if prefix <= 0x7f:
        return bytes([prefix]), pos + 1

    if prefix <= 0xb7:
        length = prefix - 0x80
        start = pos + 1
        return data[start:start + length], start + length

    if prefix <= 0xbf:
        len_of_len = prefix - 0xb7
        length = int.from_bytes(data[pos + 1:pos + 1 + len_of_len], "big")
        start = pos + 1 + len_of_len
        return data[start:start + length], start + length

    if prefix <= 0xf7:
        length = prefix - 0xc0
        start = pos + 1
        items = []
        end = start + length
        while start < end:
            item, start = _rlp_decode_item(data, start)
            items.append(item)
        return items, start

    len_of_len = prefix - 0xf7
    length = int.from_bytes(data[pos + 1:pos + 1 + len_of_len], "big")
    start = pos + 1 + len_of_len
    end = start + length

    items = []
    while start < end:
        item, start = _rlp_decode_item(data, start)
        items.append(item)

    return items, start


def extract_ip_from_enr(enr: str) -> Optional[str]:
    if not enr.startswith("enr:"):
        return None

    try:
        raw = _b64url_decode_nopad(enr[4:])
        rlp, _ = _rlp_decode_item(raw)
    except Exception:
        return None

    if not isinstance(rlp, list) or len(rlp) < 3:
        return None

    # ENR is [signature, seq, k, v, k, v, ...]
    kvs = rlp[2:]

    for i in range(0, len(kvs) - 1, 2):
        key = kvs[i]
        value = kvs[i + 1]

        if key == b"ip" and isinstance(value, bytes) and len(value) == 4:
            ip = str(ipaddress.ip_address(value))
            if is_public_ipv4(ip):
                return ip

    return None


def _walk_json_for_ips(obj) -> Iterable[str]:
    ip_regex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    if isinstance(obj, dict):
        for k, v in obj.items():
            lk = str(k).lower()

            if lk == "record" and isinstance(v, str) and v.startswith("enr:"):
                ip = extract_ip_from_enr(v)
                if ip is not None:
                    yield ip

            elif lk in {"ip", "ip4", "ipv4", "address"} and isinstance(v, str):
                if is_public_ipv4(v):
                    yield v

            yield from _walk_json_for_ips(v)

    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_json_for_ips(item)

    elif isinstance(obj, str):
        for match in ip_regex.findall(obj):
            if is_public_ipv4(match):
                yield match


def load_ips_from_json(path_or_url: str, limit: Optional[int] = None) -> List[str]:
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        with urllib.request.urlopen(path_or_url, timeout=60) as r:
            data = json.loads(r.read().decode("utf-8"))
    else:
        with open(path_or_url, "r", encoding="utf-8") as f:
            data = json.load(f)

    ips = []
    seen = set()

    for ip in _walk_json_for_ips(data):
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)

            if limit and len(ips) >= limit:
                break

    if not ips:
        raise RuntimeError("No public IPv4 addresses found in JSON/ENR records.")

    return ips


def synthetic_public_ips(n: int, rng: random.Random) -> List[str]:
    ips = []

    while len(ips) < n:
        ip = (
            f"{rng.randint(11, 223)}."
            f"{rng.randint(0, 255)}."
            f"{rng.randint(0, 255)}."
            f"{rng.randint(1, 254)}"
        )
        if is_public_ipv4(ip):
            ips.append(ip)

    return ips


def attacker_ips(prefix_mode: str, n: int, rng: random.Random) -> List[str]:
    ips = []

    if prefix_mode == "/24":
        base = "44.55.66"
        for _ in range(n):
            ips.append(f"{base}.{rng.randint(1, 254)}")

    elif prefix_mode == "/16":
        base = "44.55"
        for _ in range(n):
            ips.append(f"{base}.{rng.randint(0, 255)}.{rng.randint(1, 254)}")

    elif prefix_mode == "/8":
        base = "44"
        for _ in range(n):
            ips.append(f"{base}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}")

    elif prefix_mode == "diverse":
        ips = synthetic_public_ips(n, rng)

    else:
        raise ValueError(f"Unknown attacker prefix mode: {prefix_mode}")

    return ips


# ---------------------------------------------------------------------------
# Simulation model
# ---------------------------------------------------------------------------

@dataclass
class SimConfig:
    # Spec-style defaults.
    runtime: float = 24*3600
    capacity: int = 1000
    ad_lifetime: float = 900
    p_occ: float = 10.0
    g_safety: float = 1e-7

    # Workload rates: arrivals per second.
    honest_rate: float = 0.005
    attacker_rate: float = 0.02

    # Topics.
    n_honest_topics: int = 300
    n_attacker_topics: int = 300
    honest_topic_popularity: str = "zipf"
    zipf_alpha: float = 1.0
    target_topic: str = "topic-0"
    honest_target_topic_fraction: float = 0.0

    # Workload mode.
    attack: str = "target_topic"
    attacker_prefix: str = "/24"
    attacker_ip_pool_size: int = 1024
    attacker_id_pool_size: int = 100000

    # Honest IPs.
    honest_ip_pool_size: int = 5000

    # Metrics.
    starve_after: float = 1800
    sample_interval: float = 60

    # Renewal.
    renew_honest: bool = True
    renew_attackers: bool = True

    seed: int = 1

    use_topic_score: bool = True

    use_ip_score: bool = True

    admission_policy: str = "admission"  # admission or fifo

@dataclass
class AdRequest:
    req_id: int
    advertiser_id: str
    ip: str
    topic: str
    is_attacker: bool
    first_attempt_time: float
    attempt_count: int = 0

    is_renewal: bool = False

@dataclass
class CachedAd:
    ad_id: int
    request: AdRequest
    admitted_at: float
    expires_at: float


@dataclass(order=True)
class Event:
    time: float
    seq: int
    kind: str
    payload: object = field(compare=False)


class Registrar:
    def __init__(self, cfg: SimConfig):
        self.cfg = cfg
        self.cache: Dict[int, CachedAd] = {}
        self.next_ad_id = 0
        self.topic_counts = Counter()
        self.ip_tree = IPTree(bits=32)
        self.fifo_queue: Deque[AdRequest] = deque()

    def _admit_now(self, req: AdRequest, now: float) -> int:
        ad_id = self.next_ad_id
        self.next_ad_id += 1

        self.cache[ad_id] = CachedAd(
            ad_id=ad_id,
            request=req,
            admitted_at=now,
            expires_at=now + self.cfg.ad_lifetime,
        )
        self._increment_counters(req)
        return ad_id

    def drain_fifo(self, now: float) -> List[Tuple[AdRequest, int]]:
        admitted = []

        while self.fifo_queue and len(self.cache) < self.cfg.capacity:
            req = self.fifo_queue.popleft()
            ad_id = self._admit_now(req, now)
            admitted.append((req, ad_id))

        return admitted


    def _increment_counters(self, req: AdRequest) -> None:
        self.topic_counts[req.topic] += 1
        self.ip_tree.insert(req.ip)

    def _decrement_counters(self, req: AdRequest) -> None:
        self.topic_counts[req.topic] -= 1
        if self.topic_counts[req.topic] <= 0:
            del self.topic_counts[req.topic]

        self.ip_tree.remove(req.ip)

    def expire_ad(self, ad_id: int) -> Optional[AdRequest]:
        ad = self.cache.pop(ad_id, None)
        if ad is None:
            return None

        self._decrement_counters(ad.request)
        return ad.request

    def _topic_penalty(self, topic: str) -> float:
        if not self.cfg.use_topic_score:
            return 0.0

        c = len(self.cache)
        if c == 0:
            return 0.0

        return self.topic_counts[topic] / c

    def _ip_penalty(self, ip: str) -> float:
        if not self.cfg.use_ip_score:
            return 0.0

        return self.ip_tree.score(ip)

    def required_wait(self, req: AdRequest, now: float) -> float:
        c = len(self.cache)
        C = self.cfg.capacity

        if c >= C:
            return self.cfg.ad_lifetime

        occupancy_factor = 1.0 / ((1.0 - c / C) ** self.cfg.p_occ)

        service_similarity = self._topic_penalty(req.topic)
        ip_similarity = self._ip_penalty(req.ip)

        required = (
            self.cfg.ad_lifetime
            * occupancy_factor
            * (
                service_similarity
                + ip_similarity
                + self.cfg.g_safety
            )
        )

        waited = now - req.first_attempt_time
        return max(0.0, required - waited)

    def try_register(self, req: AdRequest, now: float) -> Tuple[str, float, Optional[int]]:
        req.attempt_count += 1

        if self.cfg.admission_policy == "fifo":
            if len(self.cache) < self.cfg.capacity:
                ad_id = self._admit_now(req, now)
                return "admitted", self.cfg.ad_lifetime, ad_id

            self.fifo_queue.append(req)
            return "queued", 0.0, None

        wait = self.required_wait(req, now)

        if wait <= 1e-9 and len(self.cache) < self.cfg.capacity:
            ad_id = self._admit_now(req, now)
            return "admitted", self.cfg.ad_lifetime, ad_id

        return "wait", min(wait, self.cfg.ad_lifetime), None

class Metrics:
    def __init__(self, cfg: SimConfig):
        self.cfg = cfg

        self.registration_delays_honest: List[float] = []
        self.registration_delays_attacker: List[float] = []
        self.target_honest_delays: List[float] = []
        self.non_target_honest_delays: List[float] = []

        self.honest_started = 0
        self.attacker_started = 0
        self.honest_admitted = 0
        self.attacker_admitted = 0

        self.target_honest_started = 0
        self.target_honest_admitted = 0
        self.non_target_honest_started = 0
        self.non_target_honest_admitted = 0

        self.honest_attempts = 0
        self.attacker_attempts = 0

        self.samples: List[Dict[str, float]] = []

        self.honest_new_started = 0
        self.honest_renewal_started = 0
        self.attacker_new_started = 0
        self.attacker_renewal_started = 0

    def on_new_request(self, req: AdRequest, cfg: SimConfig):
        if req.is_attacker:
            self.attacker_started += 1
            if req.is_renewal:
                self.attacker_renewal_started += 1
            else:
                self.attacker_new_started += 1
            return

        self.honest_started += 1
        if req.is_renewal:
            self.honest_renewal_started += 1
        else:
            self.honest_new_started += 1

        if req.topic == cfg.target_topic:
            self.target_honest_started += 1
        else:
            self.non_target_honest_started += 1

    def on_attempt(self, req: AdRequest):
        if req.is_attacker:
            self.attacker_attempts += 1
        else:
            self.honest_attempts += 1

    def on_admitted(self, req: AdRequest, now: float, cfg: SimConfig):
        delay = now - req.first_attempt_time

        if req.is_attacker:
            self.attacker_admitted += 1
            self.registration_delays_attacker.append(delay)
            return

        self.honest_admitted += 1
        self.registration_delays_honest.append(delay)

        if req.topic == cfg.target_topic:
            self.target_honest_admitted += 1
            self.target_honest_delays.append(delay)
        else:
            self.non_target_honest_admitted += 1
            self.non_target_honest_delays.append(delay)

    def sample(self, now: float, registrar: Registrar):
        c = len(registrar.cache)

        attacker_ads = sum(1 for ad in registrar.cache.values() if ad.request.is_attacker)
        honest_ads = c - attacker_ads

        target_honest_ads = sum(
            1 for ad in registrar.cache.values()
            if ad.request.topic == self.cfg.target_topic and not ad.request.is_attacker
        )
        target_attacker_ads = sum(
            1 for ad in registrar.cache.values()
            if ad.request.topic == self.cfg.target_topic and ad.request.is_attacker
        )

        target_ads = target_honest_ads + target_attacker_ads
        non_target_ads = c - target_ads

        self.samples.append({
            "time": now,
            "occupancy": c,
            "cache_utilisation": c / self.cfg.capacity if self.cfg.capacity else 0.0,

            "honest_cache_share": honest_ads / c if c else 0.0,
            "attacker_cache_share": attacker_ads / c if c else 0.0,

            "target_cache_share": target_ads / c if c else 0.0,
            "target_honest_cache_share": target_honest_ads / c if c else 0.0,
            "target_attacker_cache_share": target_attacker_ads / c if c else 0.0,
            "non_target_cache_share": non_target_ads / c if c else 0.0,
            "fifo_queue_length": len(registrar.fifo_queue),
            "target_attacker_share_within_target": (
                target_attacker_ads / target_ads if target_ads else 0.0
            ),
        })

    def summary(self) -> Dict[str, float]:
        honest = self.registration_delays_honest
        attacker = self.registration_delays_attacker
        target_honest = self.target_honest_delays
        non_target_honest = self.non_target_honest_delays

        honest_starved = sum(1 for d in honest if d > self.cfg.starve_after)
        target_starved = sum(1 for d in target_honest if d > self.cfg.starve_after)
        non_target_starved = sum(1 for d in non_target_honest if d > self.cfg.starve_after)

        def mean_sample(key: str) -> float:
            if not self.samples:
                return float("nan")
            return statistics.mean(s[key] for s in self.samples)

        return {
            "honest_started": self.honest_started,
            "honest_admitted": self.honest_admitted,
            "honest_success_rate": (
                self.honest_admitted / self.honest_started if self.honest_started else 0.0
            ),
            "honest_p50_delay": percentile(honest, 50),
            "honest_p95_delay": percentile(honest, 95),
            "honest_p99_delay": percentile(honest, 99),
            "honest_starvation_rate": honest_starved / len(honest) if honest else 0.0,

            "target_honest_started": self.target_honest_started,
            "target_honest_admitted": self.target_honest_admitted,
            "target_honest_p50_delay": percentile(target_honest, 50),
            "target_honest_p95_delay": percentile(target_honest, 95),
            "target_honest_p99_delay": percentile(target_honest, 99),
            "target_honest_starvation_rate": (
                target_starved / len(target_honest) if target_honest else 0.0
            ),

            "non_target_honest_started": self.non_target_honest_started,
            "non_target_honest_admitted": self.non_target_honest_admitted,
            "non_target_honest_p50_delay": percentile(non_target_honest, 50),
            "non_target_honest_p95_delay": percentile(non_target_honest, 95),
            "non_target_honest_p99_delay": percentile(non_target_honest, 99),
            "non_target_honest_starvation_rate": (
                non_target_starved / len(non_target_honest) if non_target_honest else 0.0
            ),

            "attacker_started": self.attacker_started,
            "attacker_admitted": self.attacker_admitted,
            "attacker_success_rate": (
                self.attacker_admitted / self.attacker_started if self.attacker_started else 0.0
            ),
            "attacker_p50_delay": percentile(attacker, 50),
            "attacker_p95_delay": percentile(attacker, 95),
            "attacker_p99_delay": percentile(attacker, 99),

            "avg_occupancy": mean_sample("occupancy"),
            "avg_cache_utilisation": mean_sample("cache_utilisation"),
            "avg_honest_cache_share": mean_sample("honest_cache_share"),
            "avg_attacker_cache_share": mean_sample("attacker_cache_share"),
            "avg_target_cache_share": mean_sample("target_cache_share"),
            "avg_target_honest_cache_share": mean_sample("target_honest_cache_share"),
            "avg_target_attacker_cache_share": mean_sample("target_attacker_cache_share"),
            "avg_non_target_cache_share": mean_sample("non_target_cache_share"),
            "avg_target_attacker_share_within_target": mean_sample(
                "target_attacker_share_within_target"
            ),

            "honest_attempts_per_admission": (
                self.honest_attempts / self.honest_admitted
                if self.honest_admitted else float("inf")
            ),
            "attacker_attempts_per_admission": (
                self.attacker_attempts / self.attacker_admitted
                if self.attacker_admitted else float("inf")
            ),
            "honest_new_started": self.honest_new_started,
            "honest_renewal_started": self.honest_renewal_started,
            "attacker_new_started": self.attacker_new_started,
            "attacker_renewal_started": self.attacker_renewal_started,

            "honest_total_request_rate": self.honest_started / self.cfg.runtime,
            "honest_new_request_rate": self.honest_new_started / self.cfg.runtime,
            "honest_renewal_request_rate": self.honest_renewal_started / self.cfg.runtime,

            "attacker_total_request_rate": self.attacker_started / self.cfg.runtime,
            "attacker_new_request_rate": self.attacker_new_started / self.cfg.runtime,
            "attacker_renewal_request_rate": self.attacker_renewal_started / self.cfg.runtime,

            "avg_fifo_queue_length": mean_sample("fifo_queue_length"),
        }


class Simulator:
    def __init__(self, cfg: SimConfig, honest_ips: List[str]):
        self.cfg = cfg
        self.rng = random.Random(cfg.seed)
        self.registrar = Registrar(cfg)
        self.metrics = Metrics(cfg)

        if not honest_ips:
            honest_ips = synthetic_public_ips(cfg.honest_ip_pool_size, self.rng)

        self.honest_ips = honest_ips[:cfg.honest_ip_pool_size]
        self.attacker_ips = attacker_ips(cfg.attacker_prefix, cfg.attacker_ip_pool_size, self.rng)

        self.events: List[Event] = []
        self.seq = 0
        self.req_id = 0

    def push(self, time: float, kind: str, payload: object):
        if time > self.cfg.runtime:
            return

        self.seq += 1
        heapq.heappush(self.events, Event(time, self.seq, kind, payload))

    def new_req_id(self) -> int:
        self.req_id += 1
        return self.req_id

    def make_honest_request(self, now: float) -> AdRequest:
        if self.cfg.attack == "popular_honest":
            topic = self.cfg.target_topic

        elif self.rng.random() < self.cfg.honest_target_topic_fraction:
            topic = self.cfg.target_topic

        else:
            topic = sample_topic(
                self.rng,
                self.cfg.n_honest_topics,
                self.cfg.honest_topic_popularity,
                self.cfg.zipf_alpha,
            )

            # Keep target/non-target comparison clean.
            if topic == self.cfg.target_topic:
                topic = f"topic-{1 + self.rng.randrange(max(1, self.cfg.n_honest_topics - 1))}"

        return AdRequest(
            req_id=self.new_req_id(),
            advertiser_id=f"h-{self.req_id}",
            ip=self.rng.choice(self.honest_ips),
            topic=topic,
            is_attacker=False,
            first_attempt_time=now,
        )

    def make_attacker_request(self, now: float) -> AdRequest:
        if self.cfg.attack == "target_topic":
            topic = self.cfg.target_topic
        elif self.cfg.attack == "cache_occupation":
            topic = f"atk-topic-{self.rng.randrange(self.cfg.n_attacker_topics)}"
        else:
            topic = f"atk-topic-{self.rng.randrange(self.cfg.n_attacker_topics)}"

        return AdRequest(
            req_id=self.new_req_id(),
            advertiser_id=f"a-{self.rng.randrange(self.cfg.attacker_id_pool_size)}",
            ip=self.rng.choice(self.attacker_ips),
            topic=topic,
            is_attacker=True,
            first_attempt_time=now,
        )

    def schedule_poisson_arrivals(self, kind: str, rate: float):
        if rate <= 0:
            return

        t = 0.0
        while t < self.cfg.runtime:
            t += self.rng.expovariate(rate)
            if t > self.cfg.runtime:
                break
            self.push(t, kind, None)

    def initialise(self):
        self.schedule_poisson_arrivals("honest_arrival", self.cfg.honest_rate)

        if self.cfg.attack in {"target_topic", "cache_occupation"}:
            self.schedule_poisson_arrivals("attacker_arrival", self.cfg.attacker_rate)

        t = 0.0
        while t <= self.cfg.runtime:
            self.push(t, "sample", None)
            t += self.cfg.sample_interval

    def run(self) -> Metrics:
        self.initialise()

        while self.events:
            ev = heapq.heappop(self.events)
            now = ev.time

            if ev.kind == "honest_arrival":
                req = self.make_honest_request(now)
                self.metrics.on_new_request(req, self.cfg)
                self.push(now, "attempt", req)

            elif ev.kind == "attacker_arrival":
                req = self.make_attacker_request(now)
                self.metrics.on_new_request(req, self.cfg)
                self.push(now, "attempt", req)

            elif ev.kind == "attempt":
                req: AdRequest = ev.payload
                self.metrics.on_attempt(req)

                status, delay, ad_id = self.registrar.try_register(req, now)

                if status == "admitted":
                    self.metrics.on_admitted(req, now, self.cfg)
                    self.push(now + delay, "expire", ad_id)

                elif status == "wait":
                    self.push(now + max(delay, 1.0), "attempt", req)

                elif status == "queued":
                    pass

            elif ev.kind == "expire":
                ad_id = ev.payload
                req = self.registrar.expire_ad(ad_id)

                if req is not None:
                    should_renew = (
                        (req.is_attacker and self.cfg.renew_attackers)
                        or ((not req.is_attacker) and self.cfg.renew_honest)
                    )

                    if should_renew:
                        new_req = AdRequest(
                            req_id=self.new_req_id(),
                            advertiser_id=req.advertiser_id,
                            ip=req.ip,
                            topic=req.topic,
                            is_attacker=req.is_attacker,
                            first_attempt_time=now,
                            is_renewal=True,
                        )
                        self.metrics.on_new_request(new_req, self.cfg)
                        self.push(now, "attempt", new_req)
                        
                if self.cfg.admission_policy == "fifo":
                    admitted_from_queue = self.registrar.drain_fifo(now)
                    for queued_req, queued_ad_id in admitted_from_queue:
                        self.metrics.on_admitted(queued_req, now, self.cfg)
                        self.push(now + self.cfg.ad_lifetime, "expire", queued_ad_id)

            elif ev.kind == "sample":
                self.metrics.sample(now, self.registrar)

            else:
                raise RuntimeError(f"Unknown event kind: {ev.kind}")

        return self.metrics


def parse_float_list(s: str) -> List[float]:

    values = []

    for item in s.split(","):

        item = item.strip()

        if item:

            values.append(float(item))

    if not values:

        raise ValueError("Empty Pocc value list")

    return values

# ---------------------------------------------------------------------------
# Experiment drivers
# ---------------------------------------------------------------------------

def load_honest_ips_arg(path: Optional[str], limit: int, seed: int) -> List[str]:
    rng = random.Random(seed)

    if path:
        return load_ips_from_json(path, limit=limit)

    return synthetic_public_ips(limit, rng)


def run_one(cfg: SimConfig, honest_ips: List[str]) -> Dict[str, float]:
    sim = Simulator(cfg, honest_ips)
    metrics = sim.run()
    summary = metrics.summary()

    summary.update({
        "runtime": cfg.runtime,
        "capacity": cfg.capacity,
        "ad_lifetime": cfg.ad_lifetime,
        "p_occ": cfg.p_occ,
        "g_safety": cfg.g_safety,
        "honest_rate": cfg.honest_rate,
        "attacker_rate": cfg.attacker_rate,
        "attack": cfg.attack,
        "attacker_prefix": cfg.attacker_prefix,
        "honest_topic_popularity": cfg.honest_topic_popularity,
        "zipf_alpha": cfg.zipf_alpha,
        "n_honest_topics": cfg.n_honest_topics,
        "n_attacker_topics": cfg.n_attacker_topics,
        "honest_target_topic_fraction": cfg.honest_target_topic_fraction,
        "seed": cfg.seed,
        "use_topic_score": cfg.use_topic_score,
        "use_ip_score": cfg.use_ip_score,
        "admission_policy": cfg.admission_policy,
    })

    return summary


def write_csv(path: str, rows: List[Dict[str, float]]) -> None:
    if not rows:
        return

    keys = list(rows[0].keys())

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def print_summary(row: Dict[str, float]) -> None:
    interesting = [
        "attack",
        "attacker_prefix",
        "runtime",
        "capacity",
        "ad_lifetime",
        "p_occ",
        "g_safety",
        "honest_rate",
        "attacker_rate",
        "honest_target_topic_fraction",

        "honest_p50_delay",
        "honest_p95_delay",
        "honest_p99_delay",
        "honest_starvation_rate",

        "target_honest_p95_delay",
        "target_honest_p99_delay",
        "target_honest_starvation_rate",

        "non_target_honest_p95_delay",
        "non_target_honest_p99_delay",
        "non_target_honest_starvation_rate",

        "attacker_p95_delay",
        "attacker_p99_delay",
        "attacker_success_rate",

        "avg_cache_utilisation",
        "avg_attacker_cache_share",
        "avg_target_honest_cache_share",
        "avg_target_attacker_cache_share",
        "avg_non_target_cache_share",
        "avg_occupancy",

        "honest_attempts_per_admission",
        "attacker_attempts_per_admission",

        "admission_policy",
        "honest_new_started",
        "honest_renewal_started",
        "honest_total_request_rate",
        "honest_new_request_rate",
        "honest_renewal_request_rate",
        "avg_fifo_queue_length",
    ]

    for k in interesting:
        print(f"{k:40s} {row.get(k)}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()

    p.add_argument("--honest-ips", default=None, help="Path or URL to all.json")
    p.add_argument("--output", default="results.csv")

    p.add_argument("--runtime", type=float, default=24*3600)
    p.add_argument("--capacity", type=int, default=1000)
    p.add_argument("--ad-lifetime", type=float, default=900)
    p.add_argument("--p-occ", type=float, default=10.0)
    p.add_argument("--g-safety", type=float, default=1e-7)

    p.add_argument("--honest-rate", type=float, default=0.005)
    p.add_argument("--attacker-rate", type=float, default=0.02)

    p.add_argument("--attack", choices=["none", "target_topic", "cache_occupation", "popular_honest"],
                   default="target_topic")
    p.add_argument("--attacker-prefix", choices=["/24", "/16", "/8", "diverse"], default="/24")

    p.add_argument("--honest-topic-popularity", choices=["uniform", "zipf"], default="zipf")
    p.add_argument("--zipf-alpha", type=float, default=1.0)
    p.add_argument("--n-honest-topics", type=int, default=300)
    p.add_argument("--n-attacker-topics", type=int, default=300)
    p.add_argument("--target-topic", default="topic-0")
    p.add_argument("--honest-target-topic-fraction", type=float, default=0.0)

    p.add_argument("--honest-ip-pool-size", type=int, default=5000)
    p.add_argument("--attacker-ip-pool-size", type=int, default=1024)
    p.add_argument("--seed", type=int, default=1)

    p.add_argument("--sweep-pocc", action="store_true")
    p.add_argument("--sweep-capacity", action="store_true")
    p.add_argument("--sweep-attacker-prefix", action="store_true")
    p.add_argument("--p-occ-values", type=str, default="1,2,4,6,8,10,12", help="Comma-separated Pocc values used when --sweep-pocc is enabled.")

    p.add_argument("--disable-topic-score", action="store_true")
    p.add_argument("--disable-ip-score", action="store_true")

    p.add_argument("--policy", choices=["admission", "fifo"], default="admission", help="Admission policy: admission uses the waiting-time function; fifo uses a simple FIFO cache baseline.")

    return p.parse_args()


def cfg_from_args(args: argparse.Namespace) -> SimConfig:
    return SimConfig(
        runtime=args.runtime,
        capacity=args.capacity,
        ad_lifetime=args.ad_lifetime,
        p_occ=args.p_occ,
        g_safety=args.g_safety,

        honest_rate=args.honest_rate,
        attacker_rate=args.attacker_rate,

        attack=args.attack,
        attacker_prefix=args.attacker_prefix,

        honest_topic_popularity=args.honest_topic_popularity,
        zipf_alpha=args.zipf_alpha,
        n_honest_topics=args.n_honest_topics,
        n_attacker_topics=args.n_attacker_topics,
        target_topic=args.target_topic,
        honest_target_topic_fraction=args.honest_target_topic_fraction,

        honest_ip_pool_size=args.honest_ip_pool_size,
        attacker_ip_pool_size=args.attacker_ip_pool_size,

        seed=args.seed,

        use_topic_score=not args.disable_topic_score,
        use_ip_score=not args.disable_ip_score,
        admission_policy=args.policy,
    )


def main():
    args = parse_args()
    base_cfg = cfg_from_args(args)

    honest_ips = load_honest_ips_arg(
        args.honest_ips,
        limit=args.honest_ip_pool_size,
        seed=args.seed,
    )

    rows = []

    if args.sweep_pocc:
        for p_occ in parse_float_list(args.p_occ_values):
            cfg = cfg_from_args(args)
            cfg.p_occ = float(p_occ)
            rows.append(run_one(cfg, honest_ips))

    elif args.sweep_capacity:
        for capacity in [100, 250, 500, 1000, 2000, 5000]:
            cfg = cfg_from_args(args)
            cfg.capacity = capacity
            rows.append(run_one(cfg, honest_ips))

    elif args.sweep_attacker_prefix:
        for prefix in ["/24", "/16", "/8", "diverse"]:
            cfg = cfg_from_args(args)
            cfg.attacker_prefix = prefix
            rows.append(run_one(cfg, honest_ips))

    else:
        rows.append(run_one(base_cfg, honest_ips))

    write_csv(args.output, rows)

    for row in rows:
        print("=" * 80)
        print_summary(row)

    print(f"\nWrote {args.output}")


if __name__ == "__main__":
    main()
