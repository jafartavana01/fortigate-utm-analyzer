import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import utm


def entry(block,name,settings):
    return 'config {}\n edit "{}"\n{}\n next\nend\n'.format(block,name,settings)


def bgp(peer='',extra='',local='65000'):
    return 'config router bgp\n set as {}\n config neighbor\n edit "192.0.2.2"\n set remote-as 65001\n{}\n next\n end\n{}\nend'.format(local,peer,extra)


def extended(text,*domains):
    return utm.run_extended_audits(text,list(domains))


def rules(finds):
    return {f.details['rule_id'] for f in finds}


class ParserTests(unittest.TestCase):
    def test_nested_and_quoted_names(self):
        root,errors=utm.parse_config_tree(entry('user ldap','corp directory',' set secure ldaps'))
        self.assertEqual(errors,[])
        self.assertEqual(utm.tree_objects(root,'user ldap')[0]['name'],'corp directory')
    def test_empty_block(self):
        root,errors=utm.parse_config_tree('config router bgp\nend')
        self.assertEqual(errors,[]);self.assertEqual(len(utm.tree_blocks(root,'router bgp')),1)
    def test_incomplete_is_unavailable(self):
        found,status,notes=extended('config user ldap\nedit "a"\nset secure disable','LDAP')
        self.assertEqual(found['LDAP'],[]);self.assertIn('Unavailable',status['LDAP'])
        self.assertTrue(any('unclosed' in n for n in notes))
    def test_unmatched_next(self):
        _,errors=utm.parse_config_tree('next');self.assertTrue(errors)
    def test_unterminated_quote(self):
        _,errors=utm.parse_config_tree('config user ldap\nedit "a');self.assertTrue(errors)
    def test_multiline_cannot_inject(self):
        cfg='config vpn certificate local\nedit "cert"\nset private-key "foo\nend\nconfig user ldap\nbar"\nnext\nend'
        root,errors=utm.parse_config_tree(cfg);self.assertEqual(errors,[])
        self.assertEqual(utm.tree_blocks(root,'user ldap'),[])
    def test_unset(self):
        cfg=entry('user ldap','a','set secure disable\nunset secure')
        root,errors=utm.parse_config_tree(cfg);self.assertEqual(errors,[])
        self.assertNotIn('secure',utm.tree_objects(root,'user ldap')[0]['settings'])
    def test_scope_repeated_declarations(self):
        cfg='config vdom\nedit "root"\nnext\nend\nconfig vdom\nedit "root"\n'+entry('user ldap','a','set secure disable')+'next\nend'
        found,_,_=extended(cfg,'LDAP');self.assertEqual(len(found['LDAP']),1)
        self.assertEqual(found['LDAP'][0].details['vdom'],'root')
    def test_global_and_vdom_same_name_do_not_merge(self):
        cfg='config global\n'+entry('user ldap','a','set secure disable')+'end\nconfig vdom\nedit "Global"\n'+entry('user ldap','b','set secure ldaps\nset ca-cert "CA"')+'next\nend'
        root,errors=utm.parse_config_tree(cfg);self.assertEqual(errors,[])
        scopes=utm.configuration_scopes(root);self.assertEqual(len(scopes),2)
        self.assertEqual([len(utm.tree_objects(n,'user ldap')) for _,n in scopes],[1,1])
    def test_tabs_are_valid_whitespace(self):
        f,_,_=extended('config user ldap\nedit "a"\nset\tsecure\tdisable\nnext\nend','LDAP')
        self.assertEqual(rules(f['LDAP']),{'LDAP-TRANSPORT'})
    def test_unknown_statement_is_unavailable(self):
        f,status,_=extended('config user ldap\nmalformed\nend','LDAP')
        self.assertEqual(f['LDAP'],[]);self.assertIn('Unavailable',status['LDAP'])
    def test_absent_is_not_applicable(self):
        f,s,_=extended('','BGP Security','RADIUS','LDAP','SAML','Admin MFA')
        self.assertTrue(all(not v for v in f.values()))
        self.assertTrue(all('Not applicable' in v for v in s.values()))


class BGPTests(unittest.TestCase):
    def audit(self,text):return extended(text,'BGP Security')[0]['BGP Security']
    def test_unprotected_peer(self):
        self.assertEqual(rules(self.audit(bgp())),{'BGP-AUTH','BGP-FILTER-IN','BGP-FILTER-OUT','BGP-LIMIT'})
    def test_protected_peer(self):
        cfg=bgp('set password ENC ciphertext\nset prefix-list-in IN\nset route-map-out OUT\nset maximum-prefix 100\nset activate6 disable')
        self.assertEqual(self.audit(cfg),[])
    def test_ibgp_filter_suggestions_suppressed(self):
        cfg=bgp('set password ENC ciphertext',local='65001');self.assertEqual(self.audit(cfg),[])
    def test_unknown_as_no_external_assumptions(self):
        cfg=bgp('set password ENC ciphertext',local='bogus');self.assertEqual(self.audit(cfg),[])
    def test_shutdown_peer(self):self.assertEqual(self.audit(bgp('set shutdown enable')),[])
    def test_ipv6_family(self):
        cfg=bgp('set password ENC cipher\nset activate disable\nset activate6 enable\nset prefix-list-in6 IN\nset route-map-out6 OUT\nset maximum-prefix6 100')
        self.assertEqual(self.audit(cfg),[])
    def test_ipv6_missing_filters(self):
        f=self.audit(bgp('set password ENC cipher\nset activate disable\nset activate6 enable'))
        self.assertEqual(len(f),3);self.assertTrue(all('IPv6' in str(x) for x in f))
    def test_dynamic_group_settings_evaluated_once(self):
        extra='config neighbor-group\nedit G\nset remote-as 65001\nset password ENC cipher\nset prefix-list-in IN\nset prefix-list-out OUT\nset maximum-prefix 100\nnext\nend\nconfig neighbor-range\nedit 1\nset neighbor-group G\nnext\nedit 2\nset neighbor-group G\nnext\nend'
        cfg='config router bgp\nset as 65000\n'+extra+'\nend'
        f,_,_=extended(cfg,'BGP Security');self.assertEqual(f['BGP Security'],[])
    def test_group_missing(self):
        cfg='config router bgp\nconfig neighbor-range\nedit 1\nset neighbor-group MISSING\nnext\nend\nend'
        self.assertEqual(rules(self.audit(cfg)),{'BGP-GROUP'})
    def test_unused_group_does_not_create_findings(self):
        cfg='config router bgp\nconfig neighbor-group\nedit UNUSED\nset remote-as 65001\nnext\nend\nend'
        self.assertEqual(self.audit(cfg),[])
    def test_redist(self):
        cfg='config router bgp\nconfig redistribute\nedit connected\nset status enable\nnext\nend\nend'
        self.assertEqual(rules(self.audit(cfg)),{'BGP-REDIST'})
        self.assertEqual(self.audit(cfg.replace('set status enable','set status enable\nset route-map SELECTED')),[])
    def test_multihop_and_warning(self):
        f=self.audit(bgp('set ebgp-enforce-multihop enable\nset ebgp-multihop-ttl 255\nset maximum-prefix-warning-only enable'))
        self.assertTrue({'BGP-MULTIHOP','BGP-LIMIT-WARN'}<=rules(f))
    def test_vdom_isolation(self):
        safe=bgp('set password ENC cipher\nset prefix-list-in IN\nset prefix-list-out OUT\nset maximum-prefix 10')
        cfg='config vdom\nedit A\n'+bgp()+'\nnext\nedit B\n'+safe+'\nnext\nend'
        f=self.audit(cfg);self.assertEqual(len(f),4);self.assertEqual({x.details['vdom'] for x in f},{'A'})
    def test_asdot(self):
        self.assertEqual(utm.asn_number('1.10'),65546)
        cfg=bgp('set password ENC cipher',local='0.65001');self.assertEqual(self.audit(cfg),[])
    def test_secret_never_in_evidence(self):
        f=self.audit(bgp('set password ENC SECRET'))
        self.assertNotIn('SECRET',json.dumps([x.details for x in f]))


class AuthTests(unittest.TestCase):
    def audit(self,domain,settings):
        return extended(entry('user '+domain.lower(),'corp',settings),domain)[0][domain]
    def test_radius_transport(self):
        self.assertIn('RADIUS-TRANSPORT',rules(self.audit('RADIUS','set transport-protocol udp')))
    def test_radius_identity(self):
        self.assertIn('RADIUS-IDENTITY',rules(self.audit('RADIUS','set transport-protocol tls\nset server-identity-check disable')))
    def test_radius_legacy_method(self):
        self.assertIn('RADIUS-METHOD',rules(self.audit('RADIUS','set auth-type chap')))
    def test_radius_integrity_disabled(self):
        self.assertIn('RADIUS-MESSAGE-AUTH',rules(self.audit('RADIUS','set require-message-authenticator disable')))
    def test_radius_hardened(self):
        f=self.audit('RADIUS','set transport-protocol tls\nset server-identity-check enable\nset require-message-authenticator enable\nset auth-type pap\nset secondary-server 192.0.2.3')
        self.assertEqual(f,[])
    def test_radius_unknown_no_inferred_transport(self):
        self.assertEqual(rules(self.audit('RADIUS','')),{'RADIUS-REDUNDANCY'})
    def test_ldap_transport(self):self.assertEqual(rules(self.audit('LDAP','set secure disable')),{'LDAP-TRANSPORT'})
    def test_ldap_unknown_not_insecure_default(self):self.assertEqual(self.audit('LDAP',''),[])
    def test_ldap_secure(self):
        for mode in ('ldaps','starttls'):
            with self.subTest(mode=mode):self.assertEqual(self.audit('LDAP','set secure '+mode+'\nset ca-cert CA\nset server-identity-check enable\nset ssl-min-proto-version TLSv1-2'),[])
    def test_ldap_identity_tls_ca(self):
        f=self.audit('LDAP','set secure ldaps\nset server-identity-check disable\nset ssl-min-proto-version TLSv1')
        self.assertEqual(rules(f),{'LDAP-IDENTITY','LDAP-TLS','LDAP-CA'})
    def test_ldap_absent_identity_not_reported_disabled(self):
        self.assertEqual(self.audit('LDAP','set secure ldaps\nset ca-cert CA'),[])
    def test_saml_http_and_digest(self):
        f=self.audit('SAML','set idp-single-sign-on-url http://idp.example/sso\nset digest-method sha1')
        self.assertEqual(rules(f),{'SAML-HTTP','SAML-DIGEST','SAML-IDP-CERT'})
    def test_saml_hardened_and_entity_id_not_transport(self):
        self.assertEqual(self.audit('SAML','set idp-cert IDP\nset digest-method sha256\nset entity-id http://identifier.example/\nset idp-entity-id http://another.identifier/\nset idp-single-sign-on-url https://idp.example/sso'),[])
    def test_saml_unknown_digest_not_assumed_sha1(self):
        self.assertEqual(self.audit('SAML','set idp-cert IDP'),[])
    def test_auth_vdom_reused_names(self):
        cfg='config vdom\nedit A\n'+entry('user ldap','corp','set secure disable')+'next\nedit B\n'+entry('user ldap','corp','set secure ldaps\nset ca-cert CA')+'next\nend'
        f,_,_=extended(cfg,'LDAP');self.assertEqual(len(f['LDAP']),1);self.assertEqual(f['LDAP'][0].details['vdom'],'A')
    def test_mfa_local_missing(self):
        self.assertEqual(rules(utm.admin_mfa_findings({'_id':'admin'})),{'MFA-LOCAL'})
    def test_mfa_configured(self):
        for value in ('fortitoken','email','sms','fortitoken-cloud'):
            self.assertEqual(utm.admin_mfa_findings({'_id':'admin','two-factor':value}),[])
    def test_mfa_external_unknown(self):
        f=utm.admin_mfa_findings({'_id':'admin','remote-auth':'enable','two-factor':'disable'})
        self.assertEqual(rules(f),{'MFA-EXTERNAL'});self.assertTrue(str(f[0]).startswith('INFO:'))
        self.assertFalse(any('not enabled' in s for s in utm.admin_weaknesses({'_id':'admin','remote-auth':'enable'})))
    def test_mfa_peer_auth_not_reported_missing(self):
        self.assertEqual(rules(utm.admin_mfa_findings({'_id':'admin','peer-auth':'enable'})),{'MFA-EXTERNAL'})
    def test_mfa_unknown_mode(self):
        self.assertEqual(rules(utm.admin_mfa_findings({'_id':'admin','two-factor':'future'})),{'MFA-UNKNOWN'})


class CryptoTests(unittest.TestCase):
    def test_four_new_explicit_fields(self):
        f=utm.crypto_transport_weaknesses({'ssh-enc-algo':'aes128-cbc','ssh-kex-algo':'diffie-hellman-group14-sha1','ssh-mac-algo':'hmac-md5','admin-https-ssl-versions':'tlsv1-1 tlsv1-2'})
        self.assertEqual(len(f),4)
    def test_current_algorithms(self):
        self.assertEqual(utm.crypto_transport_weaknesses({'ssh-enc-algo':'aes256-ctr','ssh-kex-algo':'diffie-hellman-group14-sha256','ssh-mac-algo':'hmac-sha2-256','admin-https-ssl-versions':'tlsv1-2 tlsv1-3'}),[])
    def test_unknown_settings_not_weak(self):self.assertEqual(utm.crypto_transport_weaknesses({}),[])
    def test_legacy_kex_false_positive_fixed(self):
        f=utm.ssh_config_weaknesses({'encryption':'aes256-ctr','kex':'diffie-hellman-group14-sha256'})
        self.assertFalse(any('weak key-exchange' in s for s in f))
    def test_integration_global_and_ssh(self):
        for fn in (utm.global_hardening_weaknesses,utm.ssh_config_weaknesses):
            self.assertTrue(any('legacy SSH cipher' in s for s in fn({'ssh-enc-algo':'aes128-cbc'})))


class ExtraSecurityTests(unittest.TestCase):
    def test_snmp_community_name_redacted(self):
        cfg=entry('system snmp community','1','set name "CommunitySecret"')
        data=utm.build_html_data({'SNMP':['HIGH: CommunitySecret']},cfg,'fw.conf')
        self.assertNotIn('CommunitySecret',json.dumps(data))
    def test_url_credentials_query(self):
        redactor=utm.ReportRedactor('')
        self.assertNotIn('secret',redactor.text('https://u:secret@host/feed?api_key=secret&x=1'))
    def test_selected_extended_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg=Path(tmp)/'fw.conf';cfg.write_text(bgp()+'\n'+entry('user ldap','corp','set secure disable'))
            r=subprocess.run([sys.executable,str(ROOT/'utm.py'),'-c',str(cfg),'-bgp','-auth','--summary','--html'],cwd=tmp,capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            data=json.loads((Path(tmp)/'fw.conf_SUMMARY.json').read_text())
            self.assertEqual(data['summary']['total'],5)
            self.assertEqual(set(data),{'summary','findings'})
            self.assertTrue((Path(tmp)/'fw.conf_REPORT.html').exists())
    def test_all_legacy_flags_parse(self):
        flags=['-f','-i','-av','-ips','-wf','-app','-dns','-waf','-email','-video','-file','-vpatch','-llm','-utm','-vpn','-sslvpn','-ha','-log','-dos','-antidos','-intel','-unused','-vip','-sdwan','-iface','-cert','-fabric','-ai','-s']
        with tempfile.TemporaryDirectory() as tmp:
            for flag in flags:
                with self.subTest(flag=flag):
                    r=subprocess.run([sys.executable,str(ROOT/'utm.py'),'-c',str(ROOT/'sample_config.conf'),flag],cwd=tmp,capture_output=True,text=True)
                    self.assertEqual(r.returncode,0,r.stderr)

if __name__=='__main__':unittest.main()
