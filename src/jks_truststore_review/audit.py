from .common import *
from .crypto import *
import struct
class Cursor:
    def __init__(self,b):self.b=b;self.pos=0
    def take(self,n):
        need(n>=0 and self.pos+n<=len(self.b),"truncated JKS structure");v=self.b[self.pos:self.pos+n];self.pos+=n;return v
    def uint(self,n):return int.from_bytes(self.take(n),'big')
    def blob(self):return self.take(integer(self.uint(4),0,262144))
    def utf(self):
        b=self.take(self.uint(2)); units=[];i=0
        while i<len(b):
            c=b[i];i+=1
            if 1<=c<=127:units.append(c)
            elif 0xC0<=c<=0xDF:
                need(i<len(b) and b[i]&0xC0==0x80,"invalid modified UTF-8")
                v=((c&31)<<6)|(b[i]&63);i+=1;need(v>=128 or (c==0xC0 and v==0),"overlong modified UTF-8");units.append(v)
            elif 0xE0<=c<=0xEF:
                need(i+1<len(b) and b[i]&0xC0==0x80 and b[i+1]&0xC0==0x80,"invalid modified UTF-8")
                v=((c&15)<<12)|((b[i]&63)<<6)|(b[i+1]&63);i+=2;need(v>=2048,"overlong modified UTF-8");units.append(v)
            else:raise ReviewError("invalid modified UTF-8 byte")
        try:return b''.join(struct.pack('>H',x) for x in units).decode('utf-16-be')
        except UnicodeError:raise ReviewError("unpaired UTF-16 surrogate") from None
def audit(d):
    fields(d,['file','expected_sha256','now'])
    raw=read(d['file']);expected=string(d['expected_sha256'],64);digest=hashlib.sha256(raw).hexdigest();need(expected==digest,"externally pinned truststore digest mismatch")
    now=instant(d['now']);c=Cursor(raw);need(c.uint(4)==0xFEEDFEED and c.uint(4)==2,"only JKS version 2 supported")
    count=integer(c.uint(4),1,1024);seen=set();certs=set();out=[];findings=[]
    for _ in range(count):
        need(c.uint(4)==2,"private/secret entries and other store formats unsupported")
        alias=c.utf();need(alias and alias not in seen,"empty or duplicate alias");seen.add(alias);timestamp=c.uint(8);need(timestamp<=int(now.timestamp()*1000),"entry timestamp is in the future")
        need(c.utf()=='X.509',"unsupported certificate type")
        der=c.blob()
        try:cert=x509.load_der_x509_certificate(der)
        except ValueError:raise ReviewError("invalid truststore certificate") from None
        fp=cert.fingerprint(hashes.SHA256()).hex();need(fp not in certs,"duplicate trust certificate");certs.add(fp)
        if not cert.not_valid_before_utc<=now<cert.not_valid_after_utc:findings.append('certificate outside validity interval')
        try:
            if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:findings.append('trusted entry is not a CA certificate')
        except x509.ExtensionNotFound:findings.append('CA constraint absent')
        signed_der(cert.public_bytes(serialization.Encoding.DER),'certificate');k=valid_public_key(cert.public_key())
        if isinstance(k,rsa.RSAPublicKey) and k.key_size<2048:findings.append('weak RSA public key')
        elif isinstance(k,ec.EllipticCurvePublicKey) and not isinstance(k.curve,(ec.SECP256R1,ec.SECP384R1,ec.SECP521R1)):findings.append('weak or unsupported elliptic curve')
        elif not isinstance(k,(rsa.RSAPublicKey,ec.EllipticCurvePublicKey,ed25519.Ed25519PublicKey)):findings.append('unsupported public key type')
        if cert.signature_hash_algorithm is not None and cert.signature_hash_algorithm.name not in ('sha256','sha384','sha512'):findings.append('weak or unsupported certificate signature digest')
        out.append({'alias_sha256':hashlib.sha256(alias.encode()).hexdigest(),'certificate_sha256':fp,'not_after':cert.not_valid_after_utc.isoformat()})
    need(len(raw)-c.pos==20,"invalid JKS digest trailer or trailing bytes");c.take(20)
    return {**report(verified=False,pinned_file_digest_matched=True,jks_password_integrity_verified=False,entries=out,findings=findings),'status':'FAIL' if findings else 'PASS'}
