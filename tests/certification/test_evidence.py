import base64
import copy
import datetime as dt
import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest
from evidence import EvidenceError, KINDS, SURFACES, attachment, canonical, evaluate, strict_json

class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='pgproxy-evidence-unit-')
        cls.root = pathlib.Path(cls.directory.name)
        for name in ['root', 'builder', 'auditor', 'operator']:
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', str(cls.root / (name+'.key'))], check=True, capture_output=True)
            subprocess.run(['openssl', 'pkey', '-in', str(cls.root / (name+'.key')), '-pubout', '-out', str(cls.root / (name+'.pem'))], check=True, capture_output=True)
        cls.now = dt.datetime.now(dt.timezone.utc)
        cls.created = (cls.now-dt.timedelta(minutes=1)).isoformat()
        cls.expires = (cls.now+dt.timedelta(days=1)).isoformat()
        cls.source, cls.binary = 'a'*64, 'b'*64

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def asset(self, name, body=None):
        path=self.root/name
        if body is not None:path.write_bytes(body)
        return {'path':name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}

    def sign(self, payload, name):
        body=self.root/'signing-payload'; signature=self.root/'signing-signature'
        body.write_bytes(canonical(payload))
        subprocess.run(['openssl','dgst','-sha256','-sign',str(self.root/(name+'.key')),'-sigopt','rsa_padding_mode:pss','-sigopt','rsa_pss_saltlen:digest','-out',str(signature),str(body)],check=True,capture_output=True)
        return {'payload':payload,'signature':base64.b64encode(signature.read_bytes()).decode()}

    def fixture(self):
        limits={name:{'min_duration_secs':3600,'min_samples':100,'max_p99_ms':10,'min_throughput_ops_per_sec':.01} for name in ['simple_select','prepared_select','transaction_rollback']}
        policy={'schema_version':1,'policy_id':'synthetic-unit-policy','deployment_id':'synthetic-unit-deployment','source_sha256':self.source,'release_binary_sha256':self.binary,'build_organization':'FixtureBuilder','created_at':self.created,'expires_at':self.expires,'max_evidence_age_days':30,'required_providers':['aws_rds','vault'],'performance_limits':limits,'issuers':{}}
        for name,org,roles in [('builder','FixtureBuilder',['release_builder']),('auditor','FixtureAudit',['security_reviewer']),('operator','FixtureOps',['deployment_operator','provider_operator','performance_lab'])]:
            policy['issuers'][name]={'organization':org,'roles':roles,'deployments':['synthetic-unit-deployment'],'public_key':self.asset(name+'.pem')}
        trace=self.asset('trace.txt',b'SYNTHETIC UNIT TEST; NOT REAL PRODUCTION EVIDENCE')
        gates=[{'name':name,'status':'pass','tests_passed':323,'checks_passed':260} for name in ['workspace-tests','strict-lint','release-build','build','replicated-failover','linux-tests-lint','source-stability','postgres-14-18-compatibility','postgres-14-18-tls-mtls-plus-rsa-pss']]
        report=self.asset('automated.json',canonical({'source_sha256_start':self.source,'source_sha256_end':self.source,'source_sha256_after_all_gates':self.source,'binary_sha256':{'release':self.binary},'gates':gates}))
        claims={
            'release_verification':{'automated_report_sha256':report['sha256']},
            'independent_security_review':{'tested_surfaces':sorted(SURFACES),'findings':[],'review_report_sha256':trace['sha256']},
            'deployment_fencing':{'faults_tested':['primary_loss','network_partition','old_primary_rejoin'],'transitions':[{'epoch':2,'old_server':'old','new_server':'new','fence_confirmed_at':self.created,'new_writer_enabled_at':self.created,'authority_audit_sha256':trace['sha256'],'observers':[{'vantage_id':name,'old_write_probe':'read_only_rejected','new_write_probe':'committed','trace_sha256':trace['sha256']} for name in ['east','west']]}]},
            'real_provider_integration':{'providers':[{'kind':name,'endpoint':'fixture-only','identity':'fixture-only','observations':['authenticated','backend_tls_verified','lease_expiry_rotation','expired_lease_rejected','provider_failure_closed'],'trace_sha256':trace['sha256']} for name in ['aws_rds','vault']]},
            'bare_metal_performance_soak':{'hardware_id':'synthetic-unit-hardware','platform_class':'bare_metal','hardware_inventory_sha256':trace['sha256'],'workloads':[{'name':name,'duration_secs':3600,'sample_count':100,'dropped_samples':0,'errors':0,'p99_ms':1,'throughput_ops_per_sec':2,'measurement_sha256':trace['sha256']} for name in limits]},
        }
        attachments={kind:[trace] for kind in KINDS}
        attachments['release_verification']=[report]
        audit=self.asset('authority.json',canonical({'deployment_id':policy['deployment_id'],'epoch':2,'old_server':'old','fencing_method':'power_off','operation_id':'SYNTHETIC-UNIT-ONLY','result':'confirmed','fence_confirmed_at':self.created}))
        claims['deployment_fencing']['transitions'][0]['authority_audit_sha256']=audit['sha256']
        attachments['deployment_fencing']=[audit]
        for observer in claims['deployment_fencing']['transitions'][0]['observers']:
            observed=self.asset(observer['vantage_id']+'.json',canonical({'deployment_id':policy['deployment_id'],'epoch':2,'vantage_id':observer['vantage_id'],'old_server':'old','new_server':'new','old_write_probe':'read_only_rejected','new_write_probe':'committed'}))
            observer['trace_sha256']=observed['sha256'];attachments['deployment_fencing'].append(observed)
        attachments['real_provider_integration']=[]
        for provider in claims['real_provider_integration']['providers']:
            observed=self.asset(provider['kind']+'.json',canonical({'source_sha256':self.source,'release_binary_sha256':self.binary,'deployment_id':policy['deployment_id'],**provider}))
            provider['trace_sha256']=observed['sha256'];attachments['real_provider_integration'].append(observed)
        inventory=self.asset('hardware.json',canonical({'hardware_id':'synthetic-unit-hardware','platform_class':'bare_metal','virtualization_detected':False,'physical_inventory_ref':'SYNTHETIC-UNIT-ONLY'}))
        claims['bare_metal_performance_soak']['hardware_inventory_sha256']=inventory['sha256']
        attachments['bare_metal_performance_soak']=[inventory]
        for workload in claims['bare_metal_performance_soak']['workloads']:
            raw={'source_sha256':self.source,'release_binary_sha256':self.binary,'hardware_id':'synthetic-unit-hardware','name':workload['name'],'started_ns':0,'finished_ns':3600*10**9,'dropped_samples':0,'events':[[index*36*10**9,10**6,True] for index in range(100)]}
            observed=self.asset(workload['name']+'.json',canonical(raw))
            workload['measurement_sha256']=observed['sha256'];workload['throughput_ops_per_sec']=100/3600
            attachments['bare_metal_performance_soak'].append(observed)
        bundle={'attestations':[]}
        for kind in KINDS:
            signer='builder' if kind=='release_verification' else 'auditor' if kind=='independent_security_review' else 'operator'
            payload={'schema_version':1,'policy_id':policy['policy_id'],'kind':kind,'issuer_id':signer,'source_sha256':self.source,'release_binary_sha256':self.binary,'deployment_id':policy['deployment_id'],'created_at':self.created,'expires_at':self.expires,'attachments':attachments[kind],'claims':claims[kind]}
            bundle['attestations'].append(self.sign(payload,signer))
        return policy,bundle

    def decide(self,policy,bundle):
        return evaluate(self.sign(policy,'root'),bundle,self.root,self.root/'root.pem',self.source,self.binary,self.now)

    def test_complete_synthetic_chain_authorized_by_test_root(self):
        policy,bundle=self.fixture()
        self.assertTrue(self.decide(policy,bundle)['production_certified'])

    def test_missing_external_evidence_is_incomplete(self):
        policy,bundle=self.fixture();bundle['attestations'].pop()
        decision=self.decide(policy,bundle)
        self.assertFalse(decision['production_certified'])
        self.assertEqual(decision['missing'],['bare_metal_performance_soak'])

    def test_tampered_signed_claim_rejected(self):
        policy,bundle=self.fixture();bundle['attestations'][0]['payload']['source_sha256']='c'*64
        with self.assertRaises(EvidenceError):self.decide(policy,bundle)

    def test_wrong_source_and_internal_reviewer_rejected(self):
        policy,bundle=self.fixture();policy['source_sha256']='c'*64
        with self.assertRaises(EvidenceError):self.decide(policy,bundle)
        policy,bundle=self.fixture();policy['issuers']['auditor']['organization']='FixtureBuilder'
        with self.assertRaises(EvidenceError):self.decide(policy,bundle)

    def test_stale_even_correctly_signed_evidence_rejected(self):
        policy,bundle=self.fixture();payload=bundle['attestations'][0]['payload'];payload['expires_at']=(self.now-dt.timedelta(seconds=1)).isoformat();bundle['attestations'][0]=self.sign(payload,'builder')
        with self.assertRaises(EvidenceError):self.decide(policy,bundle)

    def test_attachment_mutation_and_traversal_rejected(self):
        policy,bundle=self.fixture();(self.root/'trace.txt').write_text('tampered')
        with self.assertRaises(EvidenceError):self.decide(policy,bundle)
        with self.assertRaises(EvidenceError):attachment(self.root,{'path':'../outside','sha256':'a'*64})

    def test_symlink_and_nonfinite_json_rejected(self):
        link=self.root/'link';link.unlink(missing_ok=True);link.symlink_to(self.root/'builder.pem')
        with self.assertRaises(EvidenceError):attachment(self.root,{'path':'link','sha256':self.asset('builder.pem')['sha256']})
        path=self.root/'invalid.json';path.write_text('{"one":1,"one":2}')
        with self.assertRaises(EvidenceError):strict_json(path)
        path.write_text('{"value":NaN}')
        with self.assertRaises(EvidenceError):strict_json(path)

    def test_attachment_snapshot_survives_later_file_mutation(self):
        item=self.asset('snapshot',b'captured');captured=attachment(self.root,item)
        (self.root/'snapshot').write_bytes(b'changed')
        self.assertEqual(captured,b'captured')

    def test_unsafe_fence_order_high_findings_and_short_soak_rejected(self):
        for kind,mutate in [
            ('deployment_fencing',lambda c:c['transitions'][0].update(fence_confirmed_at=self.expires)),
            ('independent_security_review',lambda c:c['findings'].append({'id':'high','severity':'high','disposition':'open'})),
            ('bare_metal_performance_soak',lambda c:c['workloads'][0].update(duration_secs=5)),
        ]:
            policy,bundle=self.fixture();envelope=next(e for e in bundle['attestations'] if e['payload']['kind']==kind);mutate(envelope['payload']['claims']);bundle['attestations'][bundle['attestations'].index(envelope)]=self.sign(envelope['payload'],envelope['payload']['issuer_id'])
            with self.assertRaises(EvidenceError):self.decide(policy,bundle)

if __name__=='__main__':unittest.main()
