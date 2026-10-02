import unittest, json, base64, hashlib, tempfile, pathlib, datetime, copy, subprocess, sys, os, struct
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID,ObjectIdentifier
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ed25519,ec,rsa
from jks_truststore_review import audit
from jks_truststore_review.common import ReviewError,load,read
UTC=datetime.timezone.utc
def enc(b):return base64.b64encode(b).decode()
def url(b):return base64.urlsafe_b64encode(b).decode().rstrip('=')
def pemkey(k):return k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
def certs(leaf_extensions=(),issuer_extensions=()):
    now=datetime.datetime.now(UTC).replace(microsecond=0);issuer_key=rsa.generate_private_key(public_exponent=65537,key_size=2048);leaf_key=ed25519.Ed25519PrivateKey.generate()
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic Review CA')])
    ku=x509.KeyUsage(True,False,False,False,False,True,True,False,False)
    builder=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(issuer_key.public_key()).serial_number(1).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=30)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).add_extension(ku,True).add_extension(x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()),False)
    for ext,critical in issuer_extensions:builder=builder.add_extension(ext,critical)
    issuer=builder.sign(issuer_key,hashes.SHA256())
    builder=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'synthetic.invalid')])).issuer_name(subject).public_key(leaf_key.public_key()).serial_number(10).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=3)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),True)
    for ext,critical in leaf_extensions:builder=builder.add_extension(ext,critical)
    leaf=builder.sign(issuer_key,hashes.SHA256());return now,issuer_key,issuer,leaf_key,leaf
def cpem(c):return c.public_bytes(serialization.Encoding.PEM).decode()
def save_example(d):
    if os.environ.get('GENERATE_REVIEW_EXAMPLES')!='1':return
    out=pathlib.Path(__file__).resolve().parents[1]/'examples';out.mkdir(exist_ok=True)
    (out/'valid.json').write_text(json.dumps(d,indent=2)+'\n')
class CommonTests(unittest.TestCase):
    def test_duplicate_and_nonfinite_input(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'[]'):
            with self.assertRaises(ReviewError):load(raw)
    def test_input_symlink_and_fifo(self):
        with tempfile.TemporaryDirectory() as t:
            p=pathlib.Path(t);(p/'file').write_text('x');(p/'link').symlink_to(p/'file');os.mkfifo(p/'pipe')
            for q in (p/'link',p/'pipe'):
                with self.assertRaises((ReviewError,OSError)):read(str(q))
    def test_missing_fields_and_cli_exit(self):
        with self.assertRaises((ReviewError,KeyError)):audit({})
        proc=subprocess.run([sys.executable,'-m','jks_truststore_review','-'],input=b'{}',capture_output=True,timeout=10)
        self.assertEqual(proc.returncode,1);self.assertEqual(json.loads(proc.stdout)['status'],'FAIL');self.assertFalse(json.loads(proc.stdout)['complete'])

class JksTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.file=pathlib.Path(self.t.name)/'truststore.jks';now,key,issuer,_,_=certs();self.now=now;self.der=issuer.public_bytes(serialization.Encoding.DER);self.entry=struct.pack('>I',2)+self.utf('synthetic-ca')+struct.pack('>Q',int((now-datetime.timedelta(hours=1)).timestamp()*1000))+self.utf('X.509')+struct.pack('>I',len(self.der))+self.der;self.raw=struct.pack('>III',0xFEEDFEED,2,1)+self.entry+bytes(20);self.file.write_bytes(self.raw);self.d={'file':str(self.file),'expected_sha256':hashlib.sha256(self.raw).hexdigest(),'now':now.isoformat()}
    def utf(self,s):b=s.encode();return struct.pack('>H',len(b))+b
    def tearDown(self):self.t.cleanup()
    def test_valid_public_only(self):self.assertEqual(audit(self.d)['status'],'PASS');self.assertFalse(audit(self.d)['jks_password_integrity_verified'])
    def test_weak_curve_is_failure(self):
        k=ec.generate_private_key(ec.SECP192R1());subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic weak CA')]);c=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(k.public_key()).serial_number(5).not_valid_before(self.now-datetime.timedelta(days=1)).not_valid_after(self.now+datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(k,hashes.SHA256());der=c.public_bytes(serialization.Encoding.DER);entry=struct.pack('>I',2)+self.utf('weak-ca')+struct.pack('>Q',int((self.now-datetime.timedelta(hours=1)).timestamp()*1000))+self.utf('X.509')+struct.pack('>I',len(der))+der;raw=struct.pack('>III',0xFEEDFEED,2,1)+entry+bytes(20);self.file.write_bytes(raw);result=audit({**self.d,'expected_sha256':hashlib.sha256(raw).hexdigest()});self.assertEqual(result['status'],'FAIL');self.assertFalse(result['verified']);self.assertIn('weak or unsupported elliptic curve',result['findings'])
    def test_truncated_private_duplicate_and_digest(self):
        for raw in (self.raw[:-1],struct.pack('>III',0xFEEDFEED,2,1)+struct.pack('>I',1),struct.pack('>III',0xFEEDFEED,2,2)+self.entry*2+bytes(20)):
            self.file.write_bytes(raw);d={**self.d,'expected_sha256':hashlib.sha256(raw).hexdigest()}
            with self.assertRaises(ReviewError):audit(d)
        self.file.write_bytes(self.raw);d={**self.d,'expected_sha256':'0'*64}
        with self.assertRaises(ReviewError):audit(d)
    def test_saved_example(self):
        if os.environ.get('GENERATE_REVIEW_EXAMPLES')!='1':
            project=pathlib.Path(__file__).resolve().parents[1];d=json.loads((project/'examples/valid.json').read_text());d['file']=str(project/d['file']);self.assertEqual(audit(d)['status'],'PASS');return
        out=pathlib.Path(__file__).resolve().parents[1]/'examples';out.mkdir(exist_ok=True);(out/'truststore.jks').write_bytes(self.raw);d={**self.d,'file':'examples/truststore.jks'};save_example(d)

if __name__=="__main__":unittest.main()
