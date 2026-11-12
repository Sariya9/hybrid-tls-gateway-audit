#!/usr/bin/env python3
"""Post-collection observation ablations over validated HTTP gateway records.

These diagnostic rules are not prior-work implementations or new native trials.
The full-evidence auditor supplies the reference labels under its trust model.
"""
import argparse
from collections import defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path


def confusion(rows, predict):
    counts = dict(correct_compliance=0, false_compliance=0,
                  false_violation=0, correct_violation=0)
    for row in rows:
        good = row['classification'] == 'admitted_conforming'
        proposed = bool(predict(row))
        key = ('correct_compliance' if good else 'false_compliance') if proposed else (
            'false_violation' if good else 'correct_violation')
        counts[key] += 1
    return counts


def analyse(summary, record):
    """Restrict comparisons to observed complete admissions, never refusals."""
    clients = {r['request_id']: r['client'] for c in record['scenarios'] for r in c['requests']}
    all_rows = [r for c in summary['cases'] for r in c['requests']]
    specifications = {c['id']: c['specification'] for c in record['scenarios']}
    def condition(row):
        spec = specifications[row['case_id']]
        return row['path'], spec['client_mode'], spec['restricted_origin']
    controls = []
    for row in all_rows:
        if row['classification'] == 'rejected_available':
            matches = [r['request_id'] for r in all_rows
                       if condition(r) == condition(row) and r['classification'] == 'admitted_conforming']
            if not matches:
                raise ValueError('Excessive-refusal claim lacks a matched conforming admission')
            controls.append(dict(request_id=row['request_id'], condition=list(condition(row)),
                                 matched_conforming_requests=matches))
    service = {}
    for case in summary['cases']:
        counts = service.setdefault(case['policy'], dict(eligible=0, admitted_eligible=0,
                                                         refused_eligible=0))
        for row in case['requests']:
            if row['allowed_under_declared_requirement']:
                counts['eligible'] += 1
                counts['admitted_eligible'] += row['classification'].startswith('admitted_')
                counts['refused_eligible'] += not row['classification'].startswith('admitted_')
    group_refusals = []
    for scenario in record['scenarios']:
        for origin in ('legacy', 'restricted'):
            refusals = [r for r in all_rows if r['case_id'] == scenario['id'] and r['origin'] == origin
                        and r['http_status'] == 503]
            if refusals:
                events = scenario['processes'][origin]['events']
                failures = [e for e in events if e['event'] == 'tls' and not e['ok']]
                if not failures or not all(e['no_shared_group'] for e in failures):
                    raise ValueError('Scenario-level refusal evidence contains a different TLS failure')
                group_refusals.append(dict(case=scenario['id'], origin=origin,
                                           refused_requests=len(refusals), failed_attempts=len(failures),
                                           attribution='Scenario and selected origin only; no per-request failed-attempt join'))
    rows = [r for c in summary['cases'] for r in c['requests']
            if r['classification'].startswith('admitted_')]
    cells = defaultdict(list)
    for row in rows:
        client = clients[row['request_id']]
        # IDs, ports and timing locate evidence; they do not describe route security.
        key = (row['path'], row['required_mask'], row['front_group'], row['http_status'],
               client['tls_version'], client['certificate_verified'],
               client['peer_certificate_sha256'].lower())
        cells[key].append(row)
    classes = []
    for key, members in sorted(cells.items()):
        good = [r['request_id'] for r in members if r['classification'] == 'admitted_conforming']
        bad = [r['request_id'] for r in members if r['classification'] == 'admitted_violation']
        classes.append(dict(projection=list(key), conforming=good, violating=bad,
                            unavoidable_binary_errors=min(len(good), len(bad))))
    rules = {
        'delivery_only': lambda r: True,
        'declared_front_only': lambda r: not (r['required_mask'] & 1) or bool(r['observed_mask'] & 1),
        'blanket_both_hybrid': lambda r: r['observed_mask'] == 3,
    }
    return dict(admitted=len(rows), excluded_refusals=summary['totals']['requests'] - len(rows),
                reference_conforming=sum(r['classification'] == 'admitted_conforming' for r in rows),
                reference_violating=sum(r['classification'] == 'admitted_violation' for r in rows),
                baselines={name: confusion(rows, rule) for name, rule in rules.items()},
                projection_fields=['path', 'required_mask', 'front_group', 'http_status',
                                   'front_tls_version', 'front_certificate_verified', 'front_certificate_sha256'],
                equivalence_classes=classes,
                minimum_binary_errors=sum(c['unavoidable_binary_errors'] for c in classes),
                mixed_classes=sum(bool(c['conforming'] and c['violating']) for c in classes),
                excessive_refusal_controls=controls, finite_cohort_service=service,
                scenario_group_refusals=group_refusals)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs', nargs='+', type=Path)
    parser.add_argument('--auditor', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('validated_http_auditor', args.auditor)
    auditor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(auditor)
    reports = []
    for run in args.runs:
        record = auditor.load_record(run)
        summary = auditor.audit(record)
        report = analyse(summary, record)
        report['run'] = run.name
        report['record_sha256'] = hashlib.sha256((run / 'results.json').read_bytes()).hexdigest()
        reports.append(report)
    result = dict(design='Post-collection diagnostic analysis; not preregistered native predictions',
                  scope='Complete admissions only; no population error rates or cryptographic indistinguishability claim',
                  analysis_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  auditor_sha256=hashlib.sha256(args.auditor.read_bytes()).hexdigest(), runs=reports)
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / 'observation_results.json').write_text(json.dumps(result, indent=2) + '\n')
    table = [r'\begin{table}[t]\centering\small',
             r'\caption{Post-collection diagnostic rules on the 42 complete HTTP admissions per execution. FC is false compliance; FV is false violation. The validated request-correlated audit supplies reference labels. Refusals are excluded.}',
             r'\label{tab:observation}', r'\begin{tabular}{@{}lrr@{}}\toprule',
             r'Observation / rule & FC & FV \\ \midrule']
    for key, label in [('delivery_only', 'Delivery only'), ('declared_front_only', 'Declared front minimum'),
                       ('blanket_both_hybrid', 'Both H, ignore declaration')]:
        row = reports[0]['baselines'][key]
        table.append(f"{label} & {row['false_compliance']} & {row['false_violation']} " + r'\\')
    table += [r'\bottomrule\end{tabular}', r'\end{table}']
    (args.out / 'observation_results.tex').write_text('\n'.join(table) + '\n')
    print(json.dumps([dict(run=r['run'], admitted=r['admitted'],
                           minimum_binary_errors=r['minimum_binary_errors'], baselines=r['baselines'])
                      for r in reports], indent=2))


if __name__ == '__main__':
    main()
