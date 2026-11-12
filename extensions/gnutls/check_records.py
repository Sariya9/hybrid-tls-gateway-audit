#!/usr/bin/env python3
"""Reparse retained native stdout and recheck the trace/policy contract.
Includes bounded negative checks against tampered copies; never starts TLS.
"""
import argparse, copy, hashlib, importlib.util, json
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load_runner():
    spec=importlib.util.spec_from_file_location('native_gnutls_runner',HERE/'run_gnutls_matrix.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run',type=Path);args=p.parse_args()
    data=args.run/'results.json';j=json.loads(data.read_text());m=load_runner();m.RESULT=j
    request=bytes.fromhex(j['payload']['request_hex'])
    assert j['status']=='passed' and len(j['cases'])==16
    assert j['matrix_sha256']==hashlib.sha256((args.run/'declared_matrix.json').read_bytes()).hexdigest()
    for c in j['cases']:
        for role,proc in c['processes'].items():
            raw=(args.run/'raw'/f'{c["name"]}.{role}.stdout.txt').read_text()
            assert raw==proc['stdout']
            assert (args.run/'raw'/f'{c["name"]}.{role}.stderr.txt').read_text()==proc['stderr']
            assert [json.loads(s) for s in raw.splitlines()]==proc['events']
        m.check_case(c,request)
    tests=[]
    def rejected(label,case,mutate):
        c=copy.deepcopy(next(c for c in j['cases'] if c['name']==case));mutate(c)
        try:m.check_case(c,request)
        except (AssertionError,ValueError):tests.append(label);return
        raise AssertionError('Tamper accepted: '+label)
    def corrupt_payload(c):
        e=next(e for e in c['processes']['origin']['events'] if e['event']=='frame' and e['kind']=='request')
        e['hex']='00'+e['hex'][2:]
    def write_on_block(c):
        c['processes']['proxy']['events'].append({'event':'write_progress','leg':'backend','kind':'request','part':'header','bytes':4})
    def bad_auth(c):
        next(e for e in c['processes']['client']['events'] if e['event']=='verification')['san_exact']=False
    def resumed(c):
        next(e for e in c['processes']['proxy']['events'] if e['event']=='handshake')['session_reused']=True
    rejected('altered correlated payload','M01',corrupt_payload)
    rejected('accepted framing bytes on blocked route','M06',write_on_block)
    rejected('failed exact SAN on successful route','M01',bad_auth)
    rejected('resumed session','M01',resumed)
    print(json.dumps({'status':'passed','cases_reparsed':16,'negative_checks_rejected':tests,'results_sha256':hashlib.sha256(data.read_bytes()).hexdigest()},indent=2))
if __name__=='__main__':main()
