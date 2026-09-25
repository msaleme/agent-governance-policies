#!/usr/bin/env python3
# Copyright (c) 2026 msaleme. Licensed under the MIT License.
"""Private connected-test adapter. Never prints payloads, credentials or raw dumps.

APPROVAL_CONNECTED_FIXTURE points at a private JSON file. See CONNECTED.md.
The API/client/policies and registration must already exist in disposable scope.
"""
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def walk(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


class Lifecycle:
    def __init__(self):
        self.fixture_path = Path(os.environ['APPROVAL_CONNECTED_FIXTURE'])
        self.root = self.fixture_path.parent
        self.fixture = json.loads(self.fixture_path.read_text())
        self.config = json.loads((self.root / 'lifecycle.json').read_text())
        self.org = self.config['organization_id']
        self.env = self.config['environment_id']
        self.api_id = self.config['api_id']
        self.token = None
        self.records_path = self.root / 'lifecycle-evidence.json'
        self.records = json.loads(self.records_path.read_text()) if self.records_path.exists() else []

    def record(self, value):
        self.records.append(dict(at=utc(), **value))
        self.records_path.write_text(json.dumps(self.records, indent=2) + '\n')

    def api(self, method, path, body=None):
        base = 'https://anypoint.mulesoft.com'
        if self.token is None:
            request = urllib.request.Request(base + '/accounts/api/v2/oauth2/token',
                data=json.dumps({'grant_type': 'client_credentials',
                    'client_id': os.environ['ANYPOINT_CLIENT_ID'],
                    'client_secret': os.environ['ANYPOINT_CLIENT_SECRET']}).encode(),
                headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(request, timeout=60) as response:
                self.token = json.load(response)['access_token']
        request = urllib.request.Request(base + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json',
                'X-ANYPNT-ORG-ID': self.org, 'X-ANYPNT-ENV-ID': self.env})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f'control-plane HTTP {exc.code}') from None

    def docker(self, *args):
        result = subprocess.run(['docker', *args], capture_output=True)
        if result.returncode:
            raise RuntimeError('disposable Docker operation failed')
        return result.stdout

    def replicas(self):
        # Inspect only containers carrying the PDK label and the exact test hostnames.
        ids = self.docker('ps', '-q', '--filter', 'label=CreatedBy=pdk-test').decode().split()
        found = {}
        for ident in ids:
            row = json.loads(self.docker('inspect', ident))[0]
            host = row['Config']['Hostname']
            if host in ('approval-replica-a', 'approval-replica-b'):
                found[host] = {'id': ident, 'started_at': row['State']['StartedAt'],
                    'image_id': row['Image'], 'network_ids': list(row['NetworkSettings']['Networks'])}
        if len(found) != 2:
            raise RuntimeError('expected exactly two owned replicas')
        return found

    def deployment_path(self):
        return (f'/proxies/xapi/v1/organizations/{self.org}/environments/{self.env}'
                f'/apis/{self.api_id}/deployments')

    def deploy(self):
        if self.config.get('deployment_id'):
            # Reuse only a previously UI-applied, unchanged disposable deployment.
            confirmation = json.loads((self.root / 'ui-save-apply-confirmed.json').read_text())
            if confirmation.get('api_id') != self.api_id or confirmation.get('method') != 'ui':
                raise RuntimeError('existing deployment lacks matching UI confirmation')
            _, current = self.api('GET', f'/apimanager/api/v1/organizations/{self.org}'
                f'/environments/{self.env}/apis/{self.api_id}')
            code, status = self.api('GET', self.deployment_path() + '/'
                + str(self.config['deployment_id']) + '/status')
            if status.get('status') != 'applied':
                raise RuntimeError('existing deployment is not applied')
            self.record({'event': 'existing_ui_deployment_reused', 'http_status': code,
                'deployment_status': status['status'],
                'updated_date': current.get('deployment', {}).get('updatedDate'),
                'method': 'ui'})
            return
        for _ in range(24):
            _, targets = self.api('GET', f'/apimanager/xapi/v1/organizations/{self.org}'
                f'/environments/{self.env}/gateway-targets')
            matches = [x for x in walk(targets) if isinstance(x, dict)
                and x.get('name') == self.config['gateway_name'] and x.get('id')]
            if matches:
                break
            time.sleep(5)
        else:
            raise RuntimeError('fresh gateway did not appear in inventory')
        target = matches[0]
        status, deployment = self.api('POST', self.deployment_path(), {
            'type': 'HY', 'gatewayVersion': '1.14.0', 'targetId': target['id'],
            'targetName': self.config['gateway_name'], 'targetType': 'gateway',
            'environmentId': self.env, 'environmentName': 'Sandbox'})
        ident = deployment['id']
        self.config.update(deployment_id=ident, gateway_id=target['id'])
        (self.root / 'lifecycle.json').write_text(json.dumps(self.config, indent=2))
        self.record({'event': 'deployment_created', 'http_status': status, 'id': ident,
            'target_id': target['id']})
        _, before = self.api('GET', f'/apimanager/api/v1/organizations/{self.org}'
            f'/environments/{self.env}/apis/{self.api_id}')
        before_stamp = before.get('deployment', {}).get('updatedDate')
        mode = self.config['deployment_mode']
        if mode == 'api':
            # Must be explicitly authorized for this run. Equivalent deployment
            # redeploy operation, not a policy/API configuration PATCH alone.
            _, current = self.api('GET', self.deployment_path() + '/' + str(ident))
            body = {k: v for k, v in current.items()
                if k not in ('masterOrganizationId', 'organizationId', 'remoteSystemId')}
            body['expectedStatus'] = 'deployed'
            pushed, _ = self.api('PATCH', self.deployment_path() + '/' + str(ident), body)
            self.record({'event': 'deployment_api_push', 'http_status': pushed})
        elif mode == 'ui':
            # Operator writes this marker only after the requested UI Save & Apply.
            for _ in range(180):
                if (self.root / 'ui-save-apply-confirmed.json').exists():
                    break
                time.sleep(5)
            else:
                raise RuntimeError('UI Save & Apply confirmation not received')
        else:
            raise RuntimeError('deployment method was not authorized')
        for _ in range(36):
            code, status = self.api('GET', self.deployment_path() + '/' + str(ident) + '/status')
            _, after = self.api('GET', f'/apimanager/api/v1/organizations/{self.org}'
                f'/environments/{self.env}/apis/{self.api_id}')
            stamp = after.get('deployment', {}).get('updatedDate')
            if status.get('status') == 'applied' and stamp and stamp != before_stamp:
                self.record({'event': 'deployment_applied', 'http_status': code,
                    'before_updated_date': before_stamp, 'after_updated_date': stamp,
                    'deployment_status': status.get('status'), 'api_status': after.get('status'),
                    'method': mode})
                return
            time.sleep(5)
        raise RuntimeError('applied deployment/timestamp change not confirmed')

    def verify_runtime(self, replica):
        expected = json.loads((self.root / 'expected-configs.json').read_text())
        for _ in range(24):
            # Dump contains identity material: inspect only in memory; never print/save it.
            try:
                raw = self.docker('exec', replica['id'], 'flexctl', 'dump', '--output', '-')
            except RuntimeError:
                # The container is running before flexctl's internal endpoint is ready.
                time.sleep(5)
                continue
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                resources = json.loads(archive.read('resources/ApiInstance.json'))
                configs_present = all(any(isinstance(x, dict) and all(x.get(k) == v for k, v in conf.items())
                    for x in walk(resources)) for conf in expected)
                binaries = [name for name in archive.namelist()
                    if name.startswith('wasm/')]
                hashes = [hashlib.sha256(archive.read(name)).hexdigest() for name in binaries]
                wasm_matches = self.config['wasm_sha256'] in hashes
                conditions = [x for x in walk(resources) if isinstance(x, dict)
                    and x.get('type') == 'Ready' and 'status' in x]
                ready = bool(conditions) and all(str(x['status']).lower() == 'true' for x in conditions)
            if configs_present and wasm_matches and ready:
                self.record({'event': 'runtime_verified', 'container_id': replica['id'],
                    'configuration_match_on_all_supplied_fields': True, 'wasm_sha256': self.config['wasm_sha256'],
                    'ready': True})
                return
            time.sleep(5)
        raise RuntimeError('loaded configs, WASM and Ready conditions did not match')

    def warm_auth(self, url):
        # Invalid JSON-RPC method goes to a dedicated upstream readiness mock.
        body = json.dumps({'jsonrpc': '2.0', 'id': 900, 'method': 'tools/list'}).encode()
        for _ in range(36):
            req = urllib.request.Request(url, data=body,
                headers={'Content-Type': 'application/json', 'client_id': self.fixture['client_id'],
                         'client_secret': self.fixture['client_secret']})
            try:
                with urllib.request.urlopen(req, timeout=15) as response:
                    status = response.status
                    raw = response.read()
            except urllib.error.HTTPError as exc:
                status = exc.code
                raw = exc.read()
            except (urllib.error.URLError, TimeoutError):
                status, raw = None, b''
            self.record({'event': 'auth_readiness_probe', 'http_status': status})
            if status == 200 and b'approval-connected-ready' in raw:
                return
            time.sleep(5)
        raise RuntimeError('real authentication policy did not become ready')

    def execute(self, action, urls):
        if self.config.get('deployment_mode') not in ('api', 'ui'):
            raise RuntimeError('explicit deployment method required')
        replicas = self.replicas()
        if action == 'ready':
            for replica in replicas.values():
                self.docker('update', '--memory', '2g', '--memory-swap', '2g', replica['id'])
            self.record({'event': 'replicas_started', 'replicas': replicas})
            self.deploy()
            for replica in replicas.values():
                self.verify_runtime(replica)
            for url in urls:
                self.warm_auth(url)
        elif action == 'flush_metrics':
            # Keep both replicas alive across the gateway's periodic telemetry flush.
            self.record({'event': 'telemetry_drain_started', 'seconds': 90})
            time.sleep(90)
            self.record({'event': 'telemetry_drain_completed', 'seconds': 90})
        elif action == 'restart':
            old = replicas['approval-replica-a']
            self.docker('restart', old['id'])
            new = self.replicas()['approval-replica-a']
            if old['started_at'] == new['started_at']:
                raise RuntimeError('restart did not change process start timestamp')
            self.record({'event': 'replica_restarted', 'container_id': old['id'],
                'before_started_at': old['started_at'], 'after_started_at': new['started_at']})
            self.verify_runtime(new)
            self.warm_auth(urls[0])
        else:
            raise RuntimeError('unknown lifecycle action')


if __name__ == '__main__':
    try:
        Lifecycle().execute(sys.argv[1], sys.argv[2:])
    except Exception as exc:
        # Even unexpected exceptions must not echo a signed URL/configuration.
        root = Path(os.environ['APPROVAL_CONNECTED_FIXTURE']).parent
        (root / 'lifecycle-failure.json').write_text(json.dumps({
            'at': utc(), 'exception_type': type(exc).__name__,
            'reason': str(exc) if isinstance(exc, RuntimeError) else 'private operation failed'}))
        sys.exit(1)
