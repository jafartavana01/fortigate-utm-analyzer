import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from html.parser import HTMLParser
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import utm

class Inspector(HTMLParser):
    def __init__(self):
        super().__init__();self.external=[];self.ids=[]
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if 'id' in a:self.ids.append(a['id'])
        for k in ('src','href'):
            if a.get(k,'').startswith(('http:','https:','//')):self.external.append(a[k])

class HTMLTests(unittest.TestCase):
    def generate(self,findings=None,config='',references=None):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'report.html'
            data=utm.generate_html_report(findings or {},config,'firewall.conf',path,references)
            page=path.read_text()
        return page,data
    def test_embedded_roundtrip(self):
        page,data=self.generate({'VPN':['HIGH: VPN issue','INFO: Detail']})
        embedded=re.search(r'<script id="report-data" type="application/json">(.*?)</script>',page,re.S).group(1)
        self.assertEqual(json.loads(embedded),data)
        self.assertEqual(data['summary']['score'],5.5)
        self.assertEqual(data['summary']['total'],2)
    def test_empty_not_a_pass(self):
        _,data=self.generate();self.assertEqual(data['findings'],[])
        self.assertTrue(all(d['status']=='Not selected' for d in data['domains']))
    def test_audited_empty_domain(self):
        _,data=self.generate({'WAF Profiles':[]})
        self.assertIn('not a pass',next(d for d in data['domains'] if d['name']=='WAF Profiles')['status'])
    def test_shared_summary(self):
        f={'A':['CRITICAL: x','HIGH: y','MEDIUM: z','INFO: w'],'B':[]}
        _,data=self.generate(f);self.assertEqual(data['summary'],utm.compute_summary(f))
    def test_script_breakout_unicode(self):
        attack='</script><img src=x onerror=alert(1)> & " \' \u2028 Ελληνικά فارسی'
        page,data=self.generate({'A':['HIGH: '+attack]})
        self.assertNotIn(attack,page);self.assertIn(attack,data['findings'][0]['title'])
        self.assertEqual(page.count('</script>'),2)
    def test_secrets_everywhere(self):
        secrets=['S3cret!xyz','R4dius!xyz','pr1vate!xyz','API!xyz']
        cfg='\n'.join('set {} "{}"'.format(k,s) for k,s in zip(['password','secret','private-key','api-key'],secrets))
        page,_=self.generate({'A':['HIGH: '+' '.join(secrets)]},cfg,{'report':'\n'.join(secrets)})
        for secret in secrets:self.assertNotIn(secret,page)
        self.assertIn('[REDACTED]',page)
    def test_multiline_and_encrypted_secrets(self):
        cfg='set password ENC abcdefghijkl\nset private-key "-----BEGIN PRIVATE KEY-----\nZm9vYmFy\n-----END PRIVATE KEY-----"'
        page,_=self.generate({'A':['INFO: abcdefghijkl Zm9vYmFy']},cfg)
        self.assertNotIn('abcdefghijkl',page);self.assertNotIn('Zm9vYmFy',page)
    def test_secret_cannot_corrupt_fixed_schema(self):
        page,data=self.generate({'Firewall Policies':['HIGH: HIGH value']},'set password "HIGH"')
        self.assertEqual(data['summary']['counts']['HIGH'],1)
        self.assertEqual(data['findings'][0]['severity'],'HIGH')
        self.assertNotIn('HIGH value',data['findings'][0]['title'])
        self.assertIn('evidence',data['findings'][0])
    def test_single_character_secret_cannot_corrupt_field_names(self):
        _,data=self.generate({'A':['HIGH: name']},'set password "a"')
        self.assertIn('domain',data['findings'][0])
        self.assertIn('recommendation',data['findings'][0])
    def test_no_external_assets_unique_ids(self):
        page,_=self.generate();p=Inspector();p.feed(page)
        self.assertEqual(p.external,[]);self.assertEqual(len(p.ids),len(set(p.ids)))
        self.assertNotIn('innerHTML',utm.HTML_SCRIPT)
        self.assertIn("connect-src 'none'",page.replace('&#x27;',"'"))
    def test_csp_program_hash(self):
        import base64
        page,_=self.generate();digest=base64.b64encode(hashlib.sha256(utm.HTML_SCRIPT.encode()).digest()).decode()
        self.assertIn('sha256-'+digest,page)
    def test_structured_remediation(self):
        cli='config user ldap\n    edit "corp"\n        set secure ldaps\n    next\nend'
        item=utm.Finding('HIGH','LDAP issue',cli=cli,object='corp',vdom='customer-a')
        _,data=self.generate({'LDAP':[item]});f=data['findings'][0]
        self.assertEqual(f['cli'],cli);self.assertEqual(f['vdom'],'customer-a');self.assertEqual(f['object'],'corp')
    def test_duplicate_ids(self):
        _,data=self.generate({'A':['INFO: duplicate']*2});self.assertEqual(len({f['id'] for f in data['findings']}),2)
    def test_unknown_metadata(self):
        _,data=self.generate();self.assertEqual(data['metadata']['fortios'],'Unknown')
        self.assertEqual(data['metadata']['hostname'],'Unknown')
    def test_metadata_header(self):
        cfg='#config-version=FGVM64-7.4.8-FW-build2795\nconfig system global\nset hostname "edge"\nend'
        _,data=self.generate(config=cfg);self.assertEqual(data['metadata']['fortios'],'7.4.8');self.assertEqual(data['metadata']['hostname'],'edge')
    def test_large_report(self):
        _,data=self.generate({'A':['INFO: object {}'.format(i) for i in range(5000)]});self.assertEqual(len(data['findings']),5000)
    def test_guidance_without_file_reads(self):
        refs={}
        with tempfile.TemporaryDirectory() as tmp:
            p=utm.ReportOutput(Path(tmp)/'test.txt',refs)
            utm.write_report(p,'Title',[('Remediation','config system global\nend')])
            self.assertIn('config system global\nend',refs['test.txt'])
    def test_dashboard_runtime_dom_harness(self):
        if not shutil.which('node'):self.skipTest('Node unavailable (development check only)')
        findings={}
        for i in range(240):
            domain='LDAP' if i%3 else 'RADIUS'
            item=utm.Finding(('HIGH','INFO')[i%2], 'Finding {}'.format(i),
                             vdom=('tenant-a','tenant-b')[i%5==0],
                             cli='config user ldap\nend' if i==0 else '')
            findings.setdefault(domain,[]).append(item)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'report.html'
            utm.generate_html_report(findings,'','safe.conf',path,{'domain.txt':'Existing CLI reference'})
            r=subprocess.run(['node',str(ROOT/'tests/dashboard_runtime.cjs'),str(path)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr)
    def test_javascript_syntax(self):
        if not shutil.which('node'):self.skipTest('Node unavailable (development check only)')
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'report.js';p.write_text(utm.HTML_SCRIPT)
            r=subprocess.run(['node','--check',str(p)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)

class CLITests(unittest.TestCase):
    def run_cli(self,*flags):
        with tempfile.TemporaryDirectory() as tmp:
            r=subprocess.run([sys.executable,str(ROOT/'utm.py'),'-c',str(ROOT/'sample_config.conf'),*flags],cwd=tmp,capture_output=True,text=True)
            files={p.name:p.read_bytes() for p in (Path(tmp)/'sample_config').iterdir()}
        self.assertEqual(r.returncode,0,r.stderr);return r,files
    def test_html_adds_only_html(self):
        _,old=self.run_cli('-f','--summary');_,new=self.run_cli('-f','--summary','--html')
        for name,content in old.items():self.assertEqual(new[name],content)
        self.assertEqual(set(new)-set(old),{'sample_config.conf_REPORT.html'})
    def test_html_only_no_audits(self):
        r,files=self.run_cli('--html');self.assertEqual(set(files),{'sample_config.conf_REPORT.html'})
        self.assertIn('No audit flags specified',r.stdout)
    def test_summary_only_unchanged(self):
        r,files=self.run_cli('--summary');self.assertEqual(files,{})
        self.assertIn('no audit flags',r.stdout)
    def test_selected_scope(self):
        _,files=self.run_cli('-vpn','--html');page=files['sample_config.conf_REPORT.html'].decode()
        data=json.loads(re.search(r'type="application/json">(.*?)</script>',page,re.S).group(1))
        self.assertEqual(set(data['summary']['by_section']),{'VPN Phase1','VPN Phase2'})
    def test_all_baseline(self):
        _,files=self.run_cli('--all');data=json.loads(files['sample_config.conf_SUMMARY.json'])
        self.assertEqual(data['summary']['score'],876.5);self.assertEqual(data['summary']['total'],310)
        self.assertNotIn('sample_config.conf_REPORT.html',files)

if __name__=='__main__':unittest.main()
