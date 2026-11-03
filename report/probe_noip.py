import sys, importlib.util, statistics as st
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('run', sys.argv[1]); run = importlib.util.module_from_spec(spec); spec.loader.exec_module(run)
c = run.compare; onur = run.onur; gor = c.gor
cfg = onur.SimConfig(**{**run.COMMON, **run.SCENARIOS['co']}, capacity=5000, n_attacker_topics=10000, use_ip_score=False, seed=1)
sim = c.CompareSim(cfg, c.honest_ips(), 'go')
tab = sim.registrar.table
log = []
orig = tab.request
def req(node, topic, ip, now, ticket=None, attacker=False):
    tab.expire(now)
    n_topic = tab.topics.get(topic, 0)
    bound = tab.topic_bounds.get(topic)
    r = orig(node, topic, ip, now, ticket, attacker)
    log.append((attacker, ticket is None, r.status, r.wait / gor.SECOND, n_topic, bound.remaining(now) / gor.SECOND if bound else 0, len(tab.ads)))
    return r
tab.request = req
m = sim.run().summary()
fresh_h = [x for x in log if not x[0] and x[1] and x[2] != 'existing']
print('honest fresh', len(fresh_h), 'admitted', sum(1 for x in fresh_h if x[2] == 'admitted'))
q = [x for x in fresh_h if x[2] == 'quote']
print('honest fresh quotes', len(q), 'median', st.median(x[3] for x in q), 'topic had ads', sum(1 for x in q if x[4] > 0), '>=24h', sum(1 for x in q if x[3] >= 86400 - 1))
adm = [x for x in fresh_h if x[2] == 'admitted']
print('fresh honest admitted with topic empty', sum(1 for x in adm if x[4] == 0), 'of', len(adm))
qa = [x for x in log if x[0] and x[1] and x[2] == 'quote']
print('attacker fresh quotes', len(qa), 'median', st.median(x[3] for x in qa), 'topic had ads', sum(1 for x in qa if x[4] > 0))
print('occupancy median at honest fresh', st.median(x[6] for x in fresh_h))
print('new honest admitted', m['honest_new_admitted_fraction'], 'renewal started', m['honest_renewal_started'])
allq = [x for x in log if not x[0] and x[2] == 'quote']
cap = [x for x in allq if x[3] >= 86400 - 1]
print('honest quotes all', len(allq), 'cap', len(cap), 'cap with topic ad', sum(1 for x in cap if x[4] > 0), 'cap with bound only', sum(1 for x in cap if x[4] == 0 and x[5] > 0))
print('honest quotes with topic ad: median', st.median(x[3] for x in allq if x[4] > 0), 'without: median', st.median(x[3] for x in allq if x[4] == 0))
