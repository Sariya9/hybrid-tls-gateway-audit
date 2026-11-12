#!/usr/bin/env python3
"""Build four compact vector figures from retained evidence, without a TLS run.

Requires Matplotlib. Input paths are independent of this script and each other.
--out must not exist. PDFs, 200-dpi PNG previews and a hash manifest are emitted
there. Use --self-check with the three inputs to exercise evidence rejection
without creating an output directory. Native sources and old generators are
never imported or modified.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, Polygon, Rectangle
from matplotlib.path import Path as PlotPath


H, C = 'X25519MLKEM768', 'X25519'
INK, BLUE, TEAL, ORANGE = '#243746', '#245c85', '#176d70', '#995715'
PALE_BLUE, PALE_TEAL, PALE_ORANGE = '#f0f5f9', '#edf6f5', '#fcf3e9'
RULE = '#b8c6ce'
WIDTH = 6.9
HEIGHTS = {'framework': 2.50, 'methodology': 2.50,
           'execution': 3.50, 'http_admission': 2.75}
plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 8.3,
                     'pdf.fonttype': 42, 'ps.fonttype': 42,
                     'svg.fonttype': 'none'})


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def source_hashes(value, required_names):
    require(isinstance(value, dict) and set(required_names) <= set(value),
            'missing retained source hashes')
    require(all(isinstance(h, str) and len(h) == 64 and set(h) <= set('0123456789abcdef')
                for h in value.values()), 'malformed retained source hash')


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, f'duplicate JSON key {key}')
            result[key] = value
        return result

    def bad_constant(value):
        raise ValueError(f'non-finite JSON value {value}')

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad_constant)


def validate_primary(record):
    require(record['status'] == 'passed', 'primary run did not pass')
    source_hashes(record['source_sha256'], ('proxy_probe.c', 'run_policy_matrix.py', 'policy_matrix.json'))
    cases = {case['name']: case for case in record['cases']}
    require(len(cases) == len(record['cases']) == 16, 'primary matrix must have 16 unique cases')
    require(sum(c['observed']['conformance'] == 'violated' for c in cases.values()) == 3,
            'primary matrix violation count differs')
    require(cases['M05']['configuration'] == cases['M06']['configuration'],
            'M05/M06 TLS configurations differ')
    for ident in ('M05', 'M06'):
        case = cases[ident]
        enabled = ident == 'M06'
        require(case['declared_policy'] == 3 and case['guard_enabled'] is enabled,
                f'{ident}: wrong declaration or guard')
        streams = {}
        for role in ('client', 'proxy', 'origin'):
            proc = case['processes'][role]
            require(proc['timed_out'] is False and proc['cleanup_signal'] is None
                    and proc['reaped'] is True, f'{ident}/{role}: incomplete process')
            streams[role] = proc['events']
        origin, proxy = streams['origin'], streams['proxy']
        require([e['iana_ids'] for e in origin if e['event'] == 'offered_groups']
                == [[4588, 29], [4588, 29]], f'{ident}: backend offers differ')
        require([e['iana_ids'] for e in origin if e['event'] == 'offered_key_shares']
                == [[4588], [29]], f'{ident}: backend shares differ')
        require(sum(e['event'] == 'hello_retry_request' for e in origin) == 1,
                f'{ident}: missing or repeated HRR')
        handshakes = []
        for role, leg, group, hostname in (
                ('client', 'front', H, 'proxy.test'),
                ('proxy', 'backend', 'x25519', 'origin.test')):
            hs = [e for e in streams[role] if e['event'] == 'handshake' and e['leg'] == leg]
            require(len(hs) == 1, f'{ident}: missing/duplicate {leg} handshake')
            h = hs[0]
            require(h['ok'] is True and h['protocol'] == 'TLSv1.3'
                    and h['session_reused'] is False and h['group'] == group
                    and h['certificate_status'] == 'verified' and h['verify_code'] == 0
                    and h['verified_hostname'] == hostname,
                    f'{ident}: unauthenticated or unexpected {leg} connection')
            require(case['observed'][leg + '_group'] == group, f'{ident}: group summary differs')
            handshakes.append(h)
        policies = [e for e in proxy if e['event'] == 'release_policy']
        require(len(policies) == 1, f'{ident}: missing/duplicate release decision')
        policy = policies[0]
        require(policy['front_hybrid'] is True and policy['backend_hybrid'] is False
                and policy['guard_mask'] == (3 if enabled else 0)
                and policy['allowed'] is (not enabled), f'{ident}: wrong release decision')
        require(proxy.index(handshakes[1]) < proxy.index(policy),
                f'{ident}: release decision before backend authentication')
        events = [e for stream in streams.values() for e in stream]
        observed = case['observed']
        require(observed['delivered'] is (not enabled), f'{ident}: wrong delivery summary')
        if enabled:
            require(not any(e['event'] in ('payload_write_attempt', 'write_progress', 'frame')
                            for e in events), 'M06: READY or application write present')
            require(all(observed[k] == 0 for k in ('payload_write_attempts',
                        'payload_bytes_accepted', 'framing_bytes_accepted')),
                    'M06: accepted application bytes or write attempts')
            closes = [e for e in proxy if e['event'] == 'alert' and e['direction'] == 'sent']
            require([(e['leg'], e['description']) for e in closes] == [('backend', 0), ('front', 0)],
                    'M06: wrong close_notify sequence')
            require(proxy.index(policy) < proxy.index(closes[0]) < proxy.index(closes[1]),
                    'M06: close before policy decision')
            require(observed['conformance'] == 'satisfied_by_rejection', 'M06: wrong verdict')
        else:
            ready = [e for e in proxy if e['event'] == 'frame' and e['kind'] == 'ready']
            require(len(ready) == 1 and ready[0]['direction'] == 'sent'
                    and ready[0]['hex'] == '5245414459'
                    and proxy.index(policy) < proxy.index(ready[0]), 'M05: missing/early READY')
            for kind, length in (('request', 303), ('response', 319)):
                frames = [e for e in events if e['event'] == 'frame' and e['kind'] == kind]
                require(len(frames) == 4 and all(e['bytes'] == length for e in frames)
                        and len({e['hex'] for e in frames}) == 1
                        and len(bytes.fromhex(frames[0]['hex'])) == length,
                        f'M05: {kind} not correlated across four endpoints')
            require(observed['conformance'] == 'violated', 'M05: wrong verdict')
    return cases


def validate_http(record, audit, record_hash):
    require(record['status'] == 'collected' and audit['status'] == 'audited',
            'HTTP run or audit incomplete')
    require(audit['record_sha256'] == record_hash, 'HTTP audit is not bound to input bytes')
    source_hashes(record['source_sha256'], ('run_http.py', 'origin_http.c', 'declaration.json'))
    source_hashes({'auditor': audit['auditor_sha256']}, ('auditor',))
    cases = [c for c in audit['cases'] if c['id'] == 'A09']
    scenarios = [s for s in record['scenarios'] if s['id'] == 'A09']
    require(len(cases) == len(scenarios) == 1, 'A09 missing or duplicated')
    case, scenario = cases[0], scenarios[0]
    rows, raw_rows = case['requests'], scenario['requests']
    require(case['policy'] == scenario['specification']['policy'] == 'route_aware',
            'A09 is not per-route enforcement')
    require(len(rows) == len(raw_rows) == 6, 'A09 must have six requests')
    require([r['path'] for r in rows] == ['/compat', '/restricted'] * 3,
            'A09 request paths/order differ')
    ports = list(dict.fromkeys(r['local_port'] for r in rows))
    require(len(ports) == 2 and [r['local_port'] for r in rows] == [ports[0]] * 4 + [ports[1]] * 2,
            'A09 must use four then two requests on two frontend connections')
    sessions = [s for s in audit['sessions'] if s['case_id'] == 'A09']
    require(len(sessions) == 2 and {s['origin']: s['group'] for s in sessions}
            == {'legacy': C, 'restricted': H}, 'A09 backend sessions/groups differ')
    require(len({r['request_id'] for r in rows}) == 6, 'A09 duplicate request IDs')
    require(digest(scenario['config'].encode()) == scenario['config_sha256'],
            'A09 configuration hash differs')
    declarations = [s for s in record['declaration']['cases'] if s['id'] == 'A09']
    require(len(declarations) == 1 and declarations[0] == scenario['specification'],
            'A09 scenario/declaration mismatch')
    gateway = {}
    for line in scenario['processes']['gateway']['stdout'].splitlines():
        if line.startswith('AUDIT '):
            entry = dict(field.split('=', 1) for field in line.split()[1:])
            require(entry['id'] not in gateway, 'A09 duplicate gateway request ID')
            gateway[entry['id']] = entry
    for session in sessions:
        # Native connection IDs are only unique within (case, origin).
        key = (session['case_id'], session['origin'], session['connection_id'])
        joined = [r for r in rows if (r['case_id'], r['origin'], r['connection_id']) == key]
        require(len(joined) == 3 and {r['request_id'] for r in joined} == set(session['request_ids'])
                and set(session['local_ports']) == set(ports)
                and {r['local_port'] for r in joined} == set(ports),
                f'A09: invalid case/origin/connection join {key}')
    origin_accepts = {}
    for origin, expected_group in (('legacy', C), ('restricted', H)):
        proc = scenario['processes'][origin]
        require(proc['timed_out'] is False and proc['reaped'] is True and proc['exit'] == 0
                and proc['cleanup_signal'] is None, f'A09/{origin}: incomplete process')
        events = [strict_json(line) for line in proc['stdout'].splitlines() if line.strip()]
        require(events == proc['events'], f'A09/{origin}: raw/structured events differ')
        tls = [e for e in events if e['event'] == 'tls']
        require(len(tls) == 1 and tls[0]['ok'] is True and tls[0]['version'] == 'TLSv1.3'
                and tls[0]['group'].lower() == expected_group.lower()
                and tls[0]['session_reused'] is False and tls[0]['psk_offered'] is False,
                f'A09/{origin}: wrong or resumed TLS connection')
        require(tls[0]['certificate_sha256'] == record['credentials']['origin']['sha256'],
                f'A09/{origin}: origin certificate mismatch')
        for event in events:
            if event['event'] == 'application_accept':
                key = ('A09', event['origin'], event['connection_id'], event['request_id'])
                require(key not in origin_accepts, 'A09: duplicate origin acceptance')
                require(event['origin'] == origin and event['connection_id'] == tls[0]['connection_id'],
                        'A09: acceptance attributed to wrong origin connection')
                origin_accepts[key] = event
    require(len(origin_accepts) == 6, 'A09 must have six native origin admissions')
    for row, raw in zip(rows, raw_rows):
        rid = row['request_id']
        client, gw = raw['client'], gateway[rid]
        origin = 'legacy' if row['path'] == '/compat' else 'restricted'
        group, mask = (C, 0) if origin == 'legacy' else (H, 3)
        require(row['case_id'] == 'A09' and row['origin'] == origin
                and row['classification'] == 'admitted_conforming'
                and row['front_group'] == H and row['backend_group'] == group
                and row['required_mask'] == mask and row['http_status'] == 200,
                f'A09/{rid}: unexpected audited outcome')
        require(raw['request_id'] == rid and raw['path'] == row['path']
                and client['local_port'] == row['local_port'] and client['http_status'] == 200
                and client['certificate_verified'] is True and client['expected_dns_name'] == 'proxy.test'
                and client['peer_certificate_sha256'] == record['credentials']['proxy']['sha256']
                and client['tls_version'] == 'TLSv1.3' and client['session_reused'] is False
                and client['response_request_id'] == rid and client['exception'] is None
                and int(client['response_origin_connection']) == row['connection_id'],
                f'A09/{rid}: raw client/audit mismatch')
        require(gw['path'] == row['path'] and gw['backend'] == origin
                and gw['fc'] == H and gw['bc'] == group and int(gw['cp']) == row['local_port']
                and gw['fp'] == gw['bp'] == 'TLSv1.3' and gw['fr'] == gw['br'] == '0'
                and gw['cert'].lower() == record['credentials']['origin']['sha256']
                and gw['status'] == '200', f'A09/{rid}: raw gateway/audit mismatch')
        acceptance = origin_accepts[('A09', origin, row['connection_id'], rid)]
        require(acceptance['path'] == row['path'] and acceptance['body_hex'] == raw['body_hex']
                == client['response_hex'] and acceptance['body_bytes'] == len(bytes.fromhex(raw['body_hex'])),
                f'A09/{rid}: native origin body or response mismatch')
    return rows, sessions, ports


def canvas(name):
    fig = plt.figure(figsize=(WIDTH, HEIGHTS[name]))
    ax = fig.add_axes((0, 0, 1, 1), xlim=(0, WIDTH), ylim=(0, HEIGHTS[name]))
    ax.set_aspect('equal')
    ax.axis('off')
    return fig, ax


def text(ax, x, y, value, size=8.3, color=INK, weight='normal', ha='center', **kwargs):
    require(size >= 8, 'figure text below 8 pt')
    return ax.text(x, y, value, fontsize=size, color=color, fontweight=weight,
                   ha=ha, va='center', linespacing=1.16, **kwargs)


def box(ax, x, y, w, h, title, body='', color=BLUE, fill=PALE_BLUE, size=8.2, title_size=9):
    ax.add_patch(Rectangle((x, y), w, h, facecolor=fill, edgecolor=color, lw=.85, zorder=2))
    if body:
        text(ax, x + w/2, y + h - .14, title, title_size, color, 'bold', zorder=3)
        text(ax, x + w/2, y + (h - .23)/2, body, size, zorder=3)
    else:
        text(ax, x + w/2, y + h/2, title, title_size, color, 'bold', zorder=3)


def diamond(ax, x, y, w, h, label):
    ax.add_patch(Polygon([(x-w/2, y), (x, y+h/2), (x+w/2, y), (x, y-h/2)],
                         facecolor='white', edgecolor=BLUE, lw=1, zorder=2))
    text(ax, x, y, label, 8.6, BLUE, 'bold', zorder=3)


def route(ax, points, color=INK, dashed=False, both=False):
    path = PlotPath(points, [PlotPath.MOVETO] + [PlotPath.LINETO] * (len(points)-1))
    ax.add_patch(FancyArrowPatch(path=path, arrowstyle='<->' if both else '-|>',
                                mutation_scale=8, lw=.85, color=color,
                                linestyle=(0, (3, 2)) if dashed else '-',
                                capstyle='butt', joinstyle='miter', zorder=1))


def framework():
    fig, ax = canvas('framework')
    box(ax, .16, 1.99, 2.90, .38, 'Operator declaration D',
        'Required hybrid legs: none / F / B / FB', title_size=8.8, size=8)
    box(ax, .16, .99, 1.10, .64, 'Client C', 'Verify P')
    box(ax, 2.50, .90, 1.90, .82, 'Gateway P',
        'Trusted plaintext\nTwo TLS terminations\nOptional release guard', ORANGE, PALE_ORANGE, size=8.2)
    box(ax, 5.64, .99, 1.10, .64, 'Origin S', 'Identity of S', TEAL, PALE_TEAL)
    route(ax, [(1.26, 1.31), (2.50, 1.31)], BLUE, both=True)
    route(ax, [(4.40, 1.31), (5.64, 1.31)], TEAL, both=True)
    text(ax, 1.88, 1.53, 'Front TLS F', 8.4, BLUE, 'bold')
    text(ax, 1.88, 1.06, 'C verifies P\nproxy.test', 8)
    text(ax, 5.02, 1.53, 'Backend TLS B', 8.4, TEAL, 'bold')
    text(ax, 5.02, 1.06, 'P verifies S\norigin.test', 8)
    route(ax, [(2.95, 1.99), (2.95, 1.72)], BLUE, dashed=True)
    route(ax, [(3.06, 2.18), (6.80, 2.18), (6.80, .40), (6.30, .40)], BLUE, dashed=True)
    text(ax, 4.93, 2.28, 'D is checked even with the guard disabled', 8, BLUE)
    for x, y in ((.71, .99), (3.45, .90), (6.19, .99)):
        ax.plot([x, x], [y, .72], color=INK, lw=.8, zorder=1)
    ax.plot([.71, 6.19], [.72, .72], color=INK, lw=.8, zorder=1)
    route(ax, [(3.45, .72), (3.45, .60)])
    text(ax, 4.87, .82, 'Ordered endpoint events', 8)
    box(ax, 1.35, .18, 4.95, .42, 'Independent trace checker',
        'Authentication + negotiated groups + accepted writes + D', TEAL, PALE_TEAL, size=8)
    text(ax, 3.45, .055, 'Separate local CAs; classical P-256 server certificates on F and B.', 8)
    return fig


def methodology():
    fig, ax = canvas('methodology')
    box(ax, .16, 1.63, 1.65, .58, '1  Declare', 'Group lists, D and guard\nFreeze predictions')
    box(ax, 2.43, 1.63, 1.83, .58, '2  Collect',
        'Fresh native execution\nRetain endpoint events')
    diamond(ax, 5.62, 1.92, 1.86, .78, '3  Complete,\nvalid trace?')
    route(ax, [(1.81, 1.92), (2.43, 1.92)])
    text(ax, 2.12, 2.05, 'config', 8)
    route(ax, [(4.26, 1.92), (4.69, 1.92)])
    route(ax, [(5.62, 1.53), (5.62, 1.36), (3.42, 1.36), (3.42, 1.18)], TEAL)
    text(ax, 4.70, 1.45, 'Yes', 8.3, TEAL, 'bold')
    route(ax, [(6.55, 1.92), (6.75, 1.92), (6.75, .92), (6.50, .92)], ORANGE)
    text(ax, 6.61, 1.46, 'No', 8.3, ORANGE, 'bold')
    box(ax, 5.08, .63, 1.42, .58, 'Uncertified', 'Missing / malformed\nFail closed',
        ORANGE, PALE_ORANGE, size=8)
    box(ax, 2.43, .60, 1.98, .58, '4  Classify policy',
        'Observations and D only\nDelivery / refusal / violation', TEAL, PALE_TEAL, size=8)
    box(ax, .16, .60, 1.82, .58, '5  Compare prediction',
        'Expected vs observed\nKeep policy verdict', title_size=8.7)
    route(ax, [(2.43, .89), (1.98, .89)], TEAL)
    route(ax, [(.48, 1.63), (.48, 1.18)], BLUE, dashed=True)
    text(ax, .97, 1.40, 'predictions', 8, BLUE)
    route(ax, [(1.81, 1.72), (2.10, 1.72), (2.10, 1.28), (2.85, 1.28), (2.85, 1.18)],
          BLUE, dashed=True)
    text(ax, 2.21, 1.42, 'D', 8.3, BLUE, 'bold')
    ax.plot([.16, 6.74], [.44, .44], color=RULE, lw=.6)
    text(ax, 3.45, .23, 'Non-delivery alone does not establish compliance.\n'
         'Extracted repeat uses the same host and OpenSSL.', 8.2)
    return fig


def execution():
    fig, ax = canvas('execution')
    text(ax, .16, 3.34, 'M05 / M06   SAME TLS CONFIGURATION   D = FB', 8.7, BLUE, 'bold', ha='left')
    box(ax, .16, 2.52, 1.63, .65, 'Front authentication',
        'C verifies P; F = H\nproxy.test', title_size=8.6)
    box(ax, 2.37, 2.52, 2.18, .65, 'Backend negotiation',
        'Offer H,C; initial H share\nHRR requests C; C share', title_size=8.6)
    box(ax, 5.12, 2.52, 1.62, .65, 'Backend authentication',
        'P verifies S; B = C\norigin.test', TEAL, PALE_TEAL, title_size=8.1)
    route(ax, [(1.79, 2.845), (2.37, 2.845)])
    route(ax, [(4.55, 2.845), (5.12, 2.845)])
    route(ax, [(5.93, 2.52), (5.93, 2.36), (3.45, 2.36), (3.45, 2.23)])
    diamond(ax, 3.45, 1.88, 1.62, .70, 'Guard\nenabled?')
    route(ax, [(2.64, 1.88), (1.53, 1.88), (1.53, 1.64)], ORANGE)
    route(ax, [(4.26, 1.88), (5.36, 1.88), (5.36, 1.64)], TEAL)
    text(ax, 2.06, 1.99, 'No', 8.5, ORANGE, 'bold')
    text(ax, 4.83, 1.99, 'Yes', 8.5, TEAL, 'bold')
    box(ax, .16, 1.06, 2.74, .58, 'M05  Guard disabled',
        'P sends READY to C\n303-byte request; 319-byte response', ORANGE, PALE_ORANGE)
    box(ax, 3.98, 1.06, 2.76, .58, 'M06  Guard enabled',
        'Refuse B = C before READY\nclose_notify to S then C', TEAL, PALE_TEAL)
    route(ax, [(1.53, 1.06), (1.53, .81)], ORANGE)
    route(ax, [(5.36, 1.06), (5.36, .81)], TEAL)
    box(ax, .16, .41, 2.74, .40, 'POLICY VIOLATION',
        'H/C delivery; exact bytes across F and B', ORANGE, PALE_ORANGE, size=8, title_size=8.8)
    box(ax, 3.98, .41, 2.76, .40, 'POLICY SATISFIED BY REFUSAL',
        'No READY; 0 application writes or bytes', TEAL, PALE_TEAL, size=8, title_size=8.5)
    text(ax, 3.45, .16, 'H = X25519MLKEM768; C = X25519. Classical server certificates.\n'
         'Condensed causal order; vertical spacing is not measured time.', 8)
    return fig


def http_admission(rows, sessions, ports):
    fig, ax = canvas('http_admission')
    text(ax, .16, 2.61, 'A09  PER-ROUTE ENFORCEMENT', 8.5, BLUE, 'bold', ha='left')
    text(ax, 3.39, 2.61, 'Unmodified HAProxy', 8.6, ORANGE, 'bold')
    box(ax, .16, 1.92, 1.50, .52, 'Frontend F1', '4 requests; H', title_size=8.8)
    box(ax, .16, 1.13, 1.50, .52, 'Frontend F2', '2 requests; H', title_size=8.8)
    route(ax, [(1.66, 2.18), (2.01, 2.18), (2.01, 1.88), (2.38, 1.88)], BLUE)
    route(ax, [(1.66, 1.39), (2.01, 1.39), (2.01, 1.88)], BLUE)
    diamond(ax, 3.16, 1.88, 1.56, .74, 'Restricted\npath?')
    route(ax, [(3.16, 2.25), (3.16, 2.35), (4.65, 2.35), (4.65, 2.18), (5.02, 2.18)], TEAL)
    route(ax, [(3.16, 1.51), (3.16, 1.20), (4.65, 1.20), (4.65, 1.39), (5.02, 1.39)], BLUE)
    text(ax, 3.39, 2.27, 'No', 8, TEAL, 'bold')
    text(ax, 4.19, 2.45, '/compat; D = none', 8, TEAL)
    text(ax, 3.40, 1.47, 'Yes', 8, BLUE, 'bold')
    text(ax, 4.12, 1.06, '/restricted; D = FB', 8, BLUE)
    for origin, x, y, label, group, color, fill in (
            ('legacy', 5.02, 1.89, 'L1', 'C', TEAL, PALE_TEAL),
            ('restricted', 5.02, 1.10, 'S1', 'H', BLUE, PALE_BLUE)):
        numbers = ', '.join(str(i+1) for i, r in enumerate(rows) if r['origin'] == origin)
        box(ax, x, y, 1.72, .59, f'{origin.title()} origin; {group}',
            f'{label}; requests {numbers}\n3 requests from F1 + F2', color, fill, size=8, title_size=8.5)
    # The strip encodes sequential request order, never elapsed time.
    ax.plot([.16, 6.74], [.93, .93], color=RULE, lw=.6)
    text(ax, .16, .78, 'Request', 8.2, weight='bold', ha='left')
    text(ax, .16, .54, 'Front / back', 8, ha='left')
    for i, row in enumerate(rows):
        x = 1.48 + i*.945
        front = f'F{ports.index(row["local_port"])+1}'
        backend = 'L1' if row['origin'] == 'legacy' else 'S1'
        text(ax, x, .78, str(i+1), 8.4, weight='bold')
        text(ax, x, .54, f'{front} / {backend}', 8.2,
             TEAL if row['origin'] == 'legacy' else BLUE)
    ids = {s['origin']: s['connection_id'] for s in sessions}
    text(ax, 3.45, .28, f'L1 = (A09, legacy, {ids["legacy"]}); S1 = (A09, restricted, {ids["restricted"]}). '
         'Join by case + origin + connection ID.', 8)
    text(ax, 3.45, .09, 'Connections are not users. Persistent reuse; no TLS resumption or measured timing.', 8)
    return fig


def self_check(primary, http, audit, http_hash):
    """Mutations must be rejected, including IDs colliding across two origins."""
    checks = []
    bad = copy.deepcopy(primary)
    next(c for c in bad['cases'] if c['name'] == 'M06')['observed']['payload_bytes_accepted'] = 1
    checks.append(('guarded accepted byte', lambda: validate_primary(bad)))
    wrong_join = copy.deepcopy(audit)
    next(s for s in wrong_join['sessions'] if s['case_id'] == 'A09' and s['origin'] == 'legacy')['connection_id'] += 1
    checks.append(('wrong case/origin/connection join', lambda: validate_http(http, wrong_join, http_hash)))
    checks.append(('unbound HTTP audit', lambda: validate_http(http, audit, '0' * 64)))
    missing = copy.deepcopy(primary)
    hs = next(e for c in missing['cases'] if c['name'] == 'M05'
              for e in c['processes']['client']['events'] if e['event'] == 'handshake')
    del hs['verified_hostname']
    checks.append(('missing authentication evidence', lambda: validate_primary(missing)))
    for name, check in checks:
        try:
            check()
        except (ValueError, KeyError, TypeError):
            continue
        raise ValueError(f'self-check accepted {name}')
    return [name for name, _ in checks]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--primary-results', type=Path, required=True)
    parser.add_argument('--http-results', type=Path, required=True)
    parser.add_argument('--http-audit', type=Path, required=True)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--self-check', action='store_true')
    args = parser.parse_args()
    if not args.self_check and args.out is None:
        parser.error('--out is required unless --self-check is used')
    if args.out is not None and args.out.exists():
        parser.error(f'refusing existing output directory: {args.out}')
    paths = {'primary_results': args.primary_results, 'http_results': args.http_results,
             'http_audit': args.http_audit}
    try:
        raw = {key: path.read_bytes() for key, path in paths.items()}
        primary, http, audit = (strict_json(raw[k]) for k in paths)
        validate_primary(primary)
        rows, sessions, ports = validate_http(http, audit, digest(raw['http_results']))
        checks = self_check(primary, http, audit, digest(raw['http_results']))
    except (ValueError, KeyError, TypeError, IndexError, OSError) as error:
        parser.error(f'invalid figure evidence: {error}')
    if args.self_check:
        print(json.dumps({'status': 'passed', 'rejected_mutations': checks}, indent=2))
        return
    # Every evidence check precedes the first output write. mkdir is also atomic
    # against a second worker claiming the same fresh directory.
    args.out.mkdir(parents=True, exist_ok=False)
    makers = {'framework': framework, 'methodology': methodology, 'execution': execution,
              'http_admission': lambda: http_admission(rows, sessions, ports)}
    outputs = {}
    for name, make in makers.items():
        fig = make()
        fig.canvas.draw()
        renderer = fig.canvas.get_renderer()
        require(all(t.get_fontsize() >= 8 and fig.bbox.contains(*t.get_window_extent(renderer).get_points()[0])
                    and fig.bbox.contains(*t.get_window_extent(renderer).get_points()[1])
                    for ax in fig.axes for t in ax.texts), f'{name}: text outside canvas or below 8 pt')
        for suffix in ('pdf', 'png'):
            target = args.out / f'{name}.{suffix}'
            kwargs = {'metadata': {'CreationDate': None, 'ModDate': None,
                                  'Creator': 'redesign_figures.py; retained evidence'}} if suffix == 'pdf' else {'dpi': 200}
            fig.savefig(target, **kwargs)
            outputs[target.name] = {'sha256': digest(target.read_bytes()), 'width_inches': WIDTH,
                                    'height_inches': HEIGHTS[name], 'aspect_ratio': WIDTH / HEIGHTS[name]}
        plt.close(fig)
    manifest = {
        'schema_version': 1,
        'inputs': {k: {'basename': paths[k].name, 'sha256': digest(value)} for k, value in raw.items()},
        'source': {'path': Path(__file__).name, 'sha256': digest(Path(__file__).read_bytes())},
        'retained_collector_source_hashes': {'primary': primary['source_sha256'], 'http': http['source_sha256'],
                                            'http_auditor': audit['auditor_sha256']},
        'matplotlib': matplotlib.__version__, 'font': 'DejaVu Sans; embedded TrueType',
        'minimum_font_points_at_6_9_inches': 8, 'outputs': outputs,
        'evidence_checks': {'primary_cases': 16, 'execution_cases': ['M05', 'M06'],
                            'http_case': 'A09', 'http_requests': len(rows),
                            'front_local_ports': ports, 'backend_sessions': sessions,
                            'rejected_mutations': checks},
        'scope': 'Retained observations only; no new native run. Connections are not users. '
                 'No measured timing axis. Non-delivery alone does not establish compliance. '
                 'Input validation checks the depicted evidence, not all scientific claims or remote provenance.'}
    (args.out / 'figure_redesign_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'status': 'rendered', 'out': str(args.out), 'figures': list(makers)}, indent=2))


if __name__ == '__main__':
    main()
