#!/usr/bin/env python3
"""
ncsc_tls_check.py - toetst een TLS-dienst aan de NCSC TLS-beveiligingsrichtlijnen (versie 2025-05)

Draait testssl.sh plus een paar aanvullende OpenSSL- en DNS-probes, beoordeelt elke
instelling met de vier NCSC-niveaus (goed / voldoende / uit te faseren / onvoldoende)
en schrijft per host een ingevulde checklist (Markdown) en een JSON-bestand weg.

Gebruik:
    ./ncsc_tls_check.py example.com
    ./ncsc_tls_check.py mail.example.nl:25 --starttls smtp
    ./ncsc_tls_check.py example.com --json bestaande-testssl.json      # alleen beoordelen
    ./ncsc_tls_check.py -f targets.txt -o resultaten/

Benodigd:  testssl.sh (3.2 of nieuwer), openssl (3.5+ voor post-quantum probes), dig (DANE/TLSA)
Alleen gebruiken op systemen waarvoor je toestemming hebt om te testen.
"""

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

__version__ = "1.0.0"
GUIDELINE = "NCSC Transport Layer Security (TLS) - Beveiligingsrichtlijnen versie 2025-05"

# --------------------------------------------------------------------------------------
# NCSC-niveaus
# --------------------------------------------------------------------------------------
GOED, VOLDOENDE, UIT_TE_FASEREN, ONVOLDOENDE = 4, 3, 2, 1
LEVEL_NAME = {GOED: "goed", VOLDOENDE: "voldoende", UIT_TE_FASEREN: "uit te faseren",
              ONVOLDOENDE: "onvoldoende", None: "-"}

# Status van een checklistpunt
PASS = "pass"          # goed / voldoende / n.v.t.  -> afgevinkt
FAIL = "fail"          # uit te faseren / onvoldoende -> bevinding
ADVICE = "advies"      # aanbeveling uit de richtlijn, geen harde eis
MANUAL = "navraag"     # niet extern meetbaar, navragen bij beheerder
UNKNOWN = "onbekend"   # niet (betrouwbaar) gemeten
INFO = "info"

STATUS_LABEL = {PASS: "OK", FAIL: "BEVINDING", ADVICE: "ADVIES", MANUAL: "NAVRAAG",
                UNKNOWN: "ONBEKEND", INFO: "INFO"}


def worst(levels):
    levels = [lv for lv in levels if lv is not None]
    return min(levels) if levels else None


def status_for(level):
    if level is None:
        return UNKNOWN
    return PASS if level >= VOLDOENDE else FAIL


# --------------------------------------------------------------------------------------
# Classificatie volgens de tabellen in hoofdstuk 3 van de richtlijn
# --------------------------------------------------------------------------------------
# Tabel 9 - hashfuncties
HASH_LEVEL = {"SHA512": GOED, "SHA384": GOED, "SHA256": GOED, "SHA224": UIT_TE_FASEREN,
              "SHA1": ONVOLDOENDE, "SHA": ONVOLDOENDE, "MD5": ONVOLDOENDE}

# Tabel 3 / Tabel 6 - groepen voor (EC)DHE, incl. hybride PQ
GROUP_LEVEL = {
    "x25519mlkem768": GOED, "secp256r1mlkem768": GOED, "secp384r1mlkem1024": GOED,
    "secp521r1": VOLDOENDE, "secp384r1": VOLDOENDE, "secp256r1": VOLDOENDE,
    "x448": VOLDOENDE, "x25519": VOLDOENDE,
    "brainpoolp512r1": VOLDOENDE, "brainpoolp384r1": VOLDOENDE, "brainpoolp256r1": VOLDOENDE,
    "secp224r1": UIT_TE_FASEREN,
}
GROUP_ALIASES = {"prime256v1": "secp256r1", "p-256": "secp256r1", "p-384": "secp384r1",
                 "p-521": "secp521r1", "brainpoolp256r1tls13": "brainpoolp256r1",
                 "brainpoolp384r1tls13": "brainpoolp384r1", "brainpoolp512r1tls13": "brainpoolp512r1",
                 "p-224": "secp224r1", "secp256r1mlkem768": "secp256r1mlkem768"}
PQ_HYBRIDS = ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024")

# Tabel 3 - curves voor ECDSA-certificaten (X25519/X448 zijn alleen voor ECDHE)
ECDSA_CURVE_LEVEL = {"secp256r1": VOLDOENDE, "secp384r1": VOLDOENDE, "secp521r1": VOLDOENDE,
                     "brainpoolp256r1": VOLDOENDE, "brainpoolp384r1": VOLDOENDE,
                     "brainpoolp512r1": VOLDOENDE, "secp224r1": UIT_TE_FASEREN}

# Tabel 7 - DHE finite field groups (DHE zelf is al 'uit te faseren')
FFDHE_LEVEL = {"ffdhe2048": ONVOLDOENDE, "ffdhe3072": UIT_TE_FASEREN, "ffdhe4096": UIT_TE_FASEREN,
               "ffdhe6144": UIT_TE_FASEREN, "ffdhe8192": UIT_TE_FASEREN}


def norm_group(name):
    n = name.strip().lower()
    return GROUP_ALIASES.get(n, n)


def group_level(name):
    n = norm_group(name)
    if n in GROUP_LEVEL:
        return GROUP_LEVEL[n]
    if n in FFDHE_LEVEL:
        return FFDHE_LEVEL[n]
    return ONVOLDOENDE  # "Andere curves: onvoldoende"


def dh_bits_level(bits):
    # Tabel 7: >= 3072 bit uit te faseren, 2048 en kleiner onvoldoende
    if bits is None:
        return None
    return UIT_TE_FASEREN if bits >= 3072 else ONVOLDOENDE


def bulk_level(enc):
    """Tabel 8. enc = deel van de suite-naam na _WITH_ zonder MAC, bv. AES_256_GCM."""
    e = enc.upper()
    if e.endswith("CCM_8") or "CCM8" in e:
        return ONVOLDOENDE
    if e in ("AES_256_GCM", "CHACHA20_POLY1305"):
        return GOED
    if e in ("AES_256_CCM", "AES_128_GCM", "AES_128_CCM"):
        return VOLDOENDE
    if e.startswith("AES_") and e.endswith("_CBC"):
        return UIT_TE_FASEREN
    if e.startswith("CAMELLIA") or e.startswith("ARIA"):
        return UIT_TE_FASEREN
    return ONVOLDOENDE  # 3DES, SEED, IDEA, DES, RC4, NULL, RC2, GOST, ...


MAC_TOKENS = ("SHA512", "SHA384", "SHA256", "SHA224", "SHA", "MD5")


def classify_suite(iana):
    """Geeft dict met componenten en NCSC-niveau van een cipher suite (IANA-naam)."""
    name = iana.upper()
    if name.startswith("SSL_"):
        name = "TLS_" + name[4:]
    res = {"suite": iana, "kx": None, "auth": None, "enc": None, "mac": None, "notes": []}

    if "_WITH_" not in name:  # TLS 1.3 stijl: TLS_<AEAD>_<HASH>
        body = name[4:]
        parts = body.split("_")
        mac = parts[-1] if parts[-1] in MAC_TOKENS else None
        enc = "_".join(parts[:-1]) if mac else body
        res.update(enc=enc, mac=mac, tls13=True)
        levels = {"bulk": bulk_level(enc), "hash": HASH_LEVEL.get(mac, ONVOLDOENDE) if mac else None}
    else:
        pre, post = name[4:].split("_WITH_", 1)
        parts = post.split("_")
        mac = None
        if parts[-1] in MAC_TOKENS:
            mac = parts[-1]
            enc = "_".join(parts[:-1])
        else:
            enc = post
        # Sleuteluitwisseling en authenticatie
        p = pre
        export = "EXPORT" in p
        p = p.replace("_EXPORT1024", "").replace("_EXPORT", "")
        if p.startswith("ECDHE_"):
            kx, auth = "ECDHE", p[6:]
        elif p.startswith("DHE_"):
            kx, auth = "DHE", p[4:]
        elif p.startswith("ECDH_"):
            kx, auth = "ECDH", p[5:]
        elif p.startswith("DH_"):
            kx, auth = "DH", p[3:]
        elif p.startswith("SRP"):
            kx, auth = "SRP", p.split("_")[-1] if "_" in p else "SRP"
        elif p.startswith("KRB5"):
            kx, auth = "KRB5", "KRB5"
        elif p.startswith("RSA_PSK"):
            kx, auth = "RSA", "PSK"
        elif p.startswith("PSK"):
            kx, auth = "PSK", "PSK"
        elif p == "RSA":
            kx, auth = "RSA", "RSA"
        elif p == "NULL":
            kx, auth = "NULL", "NULL"
        else:
            kx, auth = p, p
        if auth.upper() == "ANON":
            auth = "anon"
        res.update(kx=kx, auth=auth, enc=enc, mac=mac, tls13=False)
        kx_lv = {"ECDHE": VOLDOENDE, "DHE": UIT_TE_FASEREN}.get(kx, ONVOLDOENDE)
        auth_lv = {"RSA": VOLDOENDE, "ECDSA": VOLDOENDE}.get(auth, ONVOLDOENDE)
        if export:
            kx_lv = auth_lv = ONVOLDOENDE
            res["notes"].append("EXPORT")
        levels = {"kx": kx_lv, "auth": auth_lv, "bulk": bulk_level(enc),
                  "hash": HASH_LEVEL.get(mac, ONVOLDOENDE) if mac else None}
    res["levels"] = levels
    res["level"] = worst(levels.values())
    return res


def classify_sigalg(sa):
    """testssl-notatie: RSA-PSS-RSAE+SHA256, RSA+SHA1, ECDSA+SHA384, Ed25519, ..."""
    s = sa.strip()
    u = s.upper()
    if u in ("ED25519", "ED448"):
        return VOLDOENDE, "EdDSA"
    h = None
    m = re.search(r"SHA(\d+)|SHA1|MD5", u)
    if m:
        tok = m.group(0)
        h = "SHA1" if tok in ("SHA1",) else tok
    hl = HASH_LEVEL.get(h) if h else None
    if u.startswith("RSA-PSS") or u.startswith("RSA_PSS"):
        return worst([VOLDOENDE, hl]), "RSA-PSS"
    if u.startswith("RSA"):
        return ONVOLDOENDE, "RSA-PKCS#1 v1.5"
    if u.startswith("ECDSA"):
        return worst([VOLDOENDE, hl]), "ECDSA"
    if u.startswith("DSA"):
        return ONVOLDOENDE, "DSA"
    return None, "onbekend"


def classify_cert_key(finding):
    """cert_keySize: 'RSA 2048 bits (exponent is 65537)', 'EC 256 bits (curve P-256)', 'EdDSA 253 bits'."""
    f = finding
    m = re.search(r"RSA\s+(\d+)\s*bits", f)
    if m:
        bits = int(m.group(1))
        if bits >= 3072:
            return VOLDOENDE, f"RSA {bits} bit (minimaal 3072 bit = voldoende)"
        if bits >= 2048:
            return UIT_TE_FASEREN, f"RSA {bits} bit (2048-3071 bit = uit te faseren)"
        return ONVOLDOENDE, f"RSA {bits} bit (< 2048 bit = onvoldoende)"
    if re.search(r"Ed25519|Ed448|EdDSA", f, re.I):
        if re.search(r"Ed448|456 bits|448 bits", f, re.I):
            return VOLDOENDE, "EdDSA Ed448"
        return VOLDOENDE, "EdDSA Ed25519"
    m = re.search(r"EC\w*\s+(\d+)\s*bits.*?curve\s+([\w-]+)", f, re.I)
    if m:
        curve = norm_group(m.group(2))
        lv = ECDSA_CURVE_LEVEL.get(curve, ONVOLDOENDE)
        return lv, f"ECDSA {m.group(2)} ({m.group(1)} bit)"
    m = re.search(r"EC\w*\s+(\d+)\s*bits", f, re.I)
    if m:
        bits = int(m.group(1))
        curve = {256: "secp256r1", 384: "secp384r1", 521: "secp521r1", 224: "secp224r1"}.get(bits)
        lv = ECDSA_CURVE_LEVEL.get(curve, ONVOLDOENDE) if curve else ONVOLDOENDE
        return lv, f"ECDSA {bits} bit"
    if re.search(r"DSA", f):
        return ONVOLDOENDE, "DSA (DSS)"
    return None, f


# --------------------------------------------------------------------------------------
# Hulpfuncties voor het draaien van tools
# --------------------------------------------------------------------------------------
def run(cmd, input_data=None, timeout=60):
    try:
        p = subprocess.run(cmd, input=input_data, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.decode(errors="replace") + p.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode(errors="replace") + (e.stderr or b"").decode(errors="replace")
        return 124, out
    except FileNotFoundError:
        return 127, ""


def find_testssl(explicit):
    if explicit:
        return explicit
    for name in ("testssl.sh", "testssl"):
        p = shutil.which(name)
        if p:
            return p
    for p in ("/usr/share/testssl/testssl.sh", "/opt/testssl.sh/testssl.sh",
              os.path.expanduser("~/testssl.sh/testssl.sh")):
        if os.path.isfile(p):
            return p
    return None


def openssl_version(openssl):
    rc, out = run([openssl, "version"], timeout=10)
    m = re.search(r"OpenSSL (\d+)\.(\d+)\.(\d+)", out)
    if rc != 0 or not m:
        return None, out.strip()
    return tuple(int(x) for x in m.groups()), out.strip().splitlines()[0]


def load_testssl_json(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        txt = fh.read().strip()
    try:
        data = json.loads(txt)
    except json.JSONDecodeError:
        # afgebroken scan: probeer de lijst netjes af te sluiten
        txt = txt.rstrip().rstrip(",")
        if not txt.endswith("]"):
            txt += "\n]"
        data = json.loads(txt)
    if isinstance(data, dict) and "scanResult" in data:  # --jsonfile-pretty
        flat = []
        for sr in data["scanResult"]:
            for key, val in sr.items():
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict) and "id" in item:
                            flat.append(item)
        data = flat
    return data


class Findings:
    def __init__(self, items):
        self.items = items
        self.by_id = {}
        for it in items:
            self.by_id.setdefault(it.get("id", ""), []).append(it)

    def get(self, id_):
        lst = self.by_id.get(id_)
        return lst[0] if lst else None

    def finding(self, id_, default=None):
        it = self.get(id_)
        return it.get("finding", default) if it else default

    def severity(self, id_):
        it = self.get(id_)
        return it.get("severity") if it else None

    def startswith(self, prefix):
        return [it for it in self.items if it.get("id", "").startswith(prefix)]

    def has(self, id_):
        return id_ in self.by_id


# --------------------------------------------------------------------------------------
# Aanvullende probes
# --------------------------------------------------------------------------------------
class Prober:
    def __init__(self, openssl, host, port, sni, starttls=None, ip=None):
        self.openssl = openssl
        self.host, self.port, self.sni = host, port, sni
        self.connect = f"{ip or host}:{port}"
        self.starttls = starttls

    def s_client(self, extra, stdin=b"", timeout=20):
        cmd = [self.openssl, "s_client", "-connect", self.connect]
        if self.sni:
            cmd += ["-servername", self.sni]
        if self.starttls:
            cmd += ["-starttls", self.starttls]
        cmd += extra
        return run(cmd, input_data=stdin, timeout=timeout)

    def handshake_ok(self, out):
        return bool(re.search(r"^\s*(New|Reused), TLSv|Protocol version: TLS|CONNECTION ESTABLISHED|Cipher is (?!\(NONE\))",
                              out, re.M)) and "Cipher is (NONE)" not in out

    def negotiated_group(self, out):
        m = re.search(r"Negotiated TLS1\.3 group:\s*(\S+)", out)
        if m:
            return m.group(1)
        m = re.search(r"(?:Server|Peer) Temp Key:\s*([^,\n]+)", out)
        return m.group(1).strip() if m else None

    def pq_groups(self):
        """Welke hybride PQ-groepen accepteert de server? (OpenSSL >= 3.5)"""
        res = {}
        for g in PQ_HYBRIDS:
            rc, out = self.s_client(["-tls1_3", "-groups", g, "-brief"], stdin=b"Q\n")
            neg = self.negotiated_group(out) or ""
            res[g] = self.handshake_ok(out) and g.lower() in neg.lower()
        return res

    def large_clienthello(self):
        """Handshake met ML-KEM key share (ClientHello > 1 TCP-segment); moet slagen."""
        rc, out = self.s_client(["-groups", "*X25519MLKEM768:*X25519:secp256r1", "-brief"], stdin=b"Q\n")
        ok = self.handshake_ok(out)
        return ok, ("handshake geslaagd" if ok else "handshake mislukt: " +
                    " ".join(out.strip().splitlines()[-2:])[:200])

    def early_data(self, http):
        """0-RTT: haal sessie op, kijk naar max_early_data en probeer early data te sturen."""
        tmp = tempfile.mkdtemp(prefix="ncsc0rtt-")
        sess = os.path.join(tmp, "sess.pem")
        req = os.path.join(tmp, "req.txt")
        payload = (f"HEAD / HTTP/1.1\r\nHost: {self.sni or self.host}\r\nConnection: close\r\n\r\n"
                   if http else "\r\n")
        with open(req, "w") as fh:
            fh.write(payload)
        try:
            rc, out = self.s_client(["-tls1_3", "-sess_out", sess, "-ign_eof"],
                                    stdin=payload.encode(), timeout=15)
            if not os.path.exists(sess) or os.path.getsize(sess) == 0:
                return None, "geen sessieticket ontvangen; 0-RTT niet te bepalen"
            rc, txt = run([self.openssl, "sess_id", "-in", sess, "-noout", "-text"], timeout=10)
            m = re.search(r"Max Early Data:\s*(\d+)", txt)
            max_ed = int(m.group(1)) if m else 0
            rc, out2 = self.s_client(["-tls1_3", "-sess_in", sess, "-early_data", req],
                                     stdin=b"", timeout=15)
            accepted = "Early data was accepted" in out2
            if accepted:
                return True, f"server accepteert early data (max_early_data={max_ed})"
            if max_ed > 0:
                return True, f"server adverteert early data (max_early_data={max_ed}), " \
                             f"verzonden early data niet geaccepteerd"
            return False, "server staat geen early data toe"
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def dns_tlsa(host, port):
    dig = shutil.which("dig")
    if not dig:
        return None, "dig niet gevonden"
    name = f"_{port}._tcp.{host}"
    rc, out = run([dig, "+short", "TLSA", name], timeout=20)
    recs = [line for line in out.splitlines() if line.strip() and not line.startswith(";")]
    if not recs:
        return False, f"geen TLSA-record op {name}"
    detail = f"TLSA op {name}: " + "; ".join(recs[:3])
    delv = shutil.which("delv")
    if delv:
        rc, v = run([delv, "TLSA", name], timeout=20)
        detail += " | DNSSEC: " + ("gevalideerd" if "fully validated" in v else "NIET gevalideerd")
    return True, detail


# --------------------------------------------------------------------------------------
# Checklist
# --------------------------------------------------------------------------------------
SECTIONS = [
    ("prep", "Voorbereiding en tooling"),
    ("versions", "TLS-versies"),
    ("cert", "Certificaat en authenticatie"),
    ("kx", "Sleuteluitwisseling"),
    ("bulk", "Bulkversleuteling, hashing en cipher suites"),
    ("opts", "Overige opties"),
    ("impl", "Implementatie en randvoorwaarden"),
    ("pq", "Quantumgereedheid"),
]


class Checklist:
    def __init__(self):
        self.items = []

    def add(self, section, title, status, level=None, evidence="", advice="", ref=""):
        self.items.append({"section": section, "title": title, "status": status,
                           "level": LEVEL_NAME[level] if level in LEVEL_NAME else level,
                           "level_num": level if isinstance(level, int) else None,
                           "evidence": evidence, "advice": advice, "ref": ref})

    def leveled(self, section, title, level, evidence="", advice="", ref=""):
        self.add(section, title, status_for(level), level, evidence,
                 advice if status_for(level) != PASS else "", ref)


def assess(f, ctx):
    """f = Findings (testssl), ctx = dict met probe-resultaten en metadata."""
    cl = Checklist()
    P = lambda *a, **k: cl.add(*a, **k)  # noqa: E731

    # ---------------------------------------------------------------- voorbereiding
    P("prep", "testssl.sh-scan uitgevoerd", PASS if f.items else FAIL, None,
      f"{ctx.get('testssl_version', 'testssl.sh')} - {len(f.items)} resultaten")
    disc = ctx.get("discovery")
    if disc:
        P("prep", "Alle (STARTTLS-)poorten van de host in scope", PASS, None,
          f"nmap ({disc['ports_arg']}): {len(disc['services'])} TLS-dienst(en) gevonden en getoetst: " +
          ", ".join(f"{s['port']}/{s['name']}" + (f" (STARTTLS {s['starttls']})" if s["starttls"] else "")
                    for s in disc["services"]))
    else:
        P("prep", "Alle (STARTTLS-)poorten van de host in scope", MANUAL, None,
          "Alleen deze poort getoetst. Gebruik --discover om met nmap alle TLS- en STARTTLS-poorten "
          "te vinden en te toetsen.")
    P("prep", "OpenSSL-versie geschikt voor aanvullende probes",
      PASS if ctx.get("openssl_pq") else ADVICE, None, ctx.get("openssl_version", "?"),
      "" if ctx.get("openssl_pq") else "Gebruik OpenSSL 3.5+ (--openssl) voor de post-quantum probes.")

    # ---------------------------------------------------------------- versies (Tabel 1)
    proto = {}
    for pid, label in (("SSLv2", "SSL 2.0"), ("SSLv3", "SSL 3.0"), ("TLS1", "TLS 1.0"),
                       ("TLS1_1", "TLS 1.1"), ("TLS1_2", "TLS 1.2"), ("TLS1_3", "TLS 1.3")):
        fd = f.finding(pid)
        proto[pid] = None if fd is None else (fd.lower().startswith("offered") and "not offered" not in fd.lower())
    ctx["proto"] = proto

    t13 = proto.get("TLS1_3")
    if t13 is None:
        P("versions", "TLS 1.3 wordt ondersteund", UNKNOWN, None, "niet getest")
    elif t13:
        cl.leveled("versions", "TLS 1.3 wordt ondersteund", GOED, f"TLS 1.3: {f.finding('TLS1_3')}", "", "§3.3.1 Tabel 1")
    else:
        # TLS 1.3 heeft de voorkeur, maar alleen TLS 1.2 is nog 'voldoende' (Tabel 1)
        P("versions", "TLS 1.3 wordt ondersteund", ADVICE, VOLDOENDE, f"TLS 1.3: {f.finding('TLS1_3')}",
          "Schakel TLS 1.3 in: voorkeursversie en voorwaarde voor de PQ-migratie (§3.3.1, §4.5).", "§3.3.1 Tabel 1")
    t12 = proto.get("TLS1_2")
    P("versions", "TLS 1.2 alleen als nodig voor oudere clients", PASS,
      VOLDOENDE if t12 else None, f"TLS 1.2: {f.finding('TLS1_2', 'niet getest')}",
      "TLS 1.2 is voldoende; leg vast welke clients het nog nodig hebben." if t12 else "", "§3.3.1 Tabel 1")
    old = [lbl for pid, lbl in (("TLS1_1", "TLS 1.1"), ("TLS1", "TLS 1.0")) if proto.get(pid)]
    cl.leveled("versions", "TLS 1.1 en TLS 1.0 uitgeschakeld", ONVOLDOENDE if old else GOED,
               ("aangeboden: " + ", ".join(old)) if old else "niet aangeboden",
               "Schakel TLS 1.0 en 1.1 uit (onvoldoende sinds deze versie van de richtlijn).", "§3.3.1 Tabel 1")
    ssl = [lbl for pid, lbl in (("SSLv3", "SSL 3.0"), ("SSLv2", "SSL 2.0")) if proto.get(pid)]
    cl.leveled("versions", "SSL 3.0, SSL 2.0 en SSL 1.0 uitgeschakeld", ONVOLDOENDE if ssl else GOED,
               ("aangeboden: " + ", ".join(ssl)) if ssl else "niet aangeboden",
               "Schakel alle SSL-versies uit.", "§3.3.1 Tabel 1")
    fb = f.get("fallback_SCSV")
    if fb:
        bad =fb.get("severity") in ("MEDIUM", "HIGH", "CRITICAL")
        P("versions", "Geen downgrade mogelijk (TLS_FALLBACK_SCSV of geen oudere versies)",
          FAIL if bad else PASS, None, f"fallback_SCSV: {fb['finding']}",
          "Ondersteun TLS_FALLBACK_SCSV of schakel oudere versies uit." if bad else "")

    # ---------------------------------------------------------------- cipher suites verzamelen
    suites = []  # (proto, iana, classificatie, dh_bits)
    for it in f.items:
        iid = it.get("id", "")
        if not (iid.startswith("cipher-") or re.match(r"cipher_x[0-9a-f]+$", iid)):
            continue
        fd = it.get("finding", "")
        if "not a/v" in fd:
            continue
        m = re.search(r"\b((?:TLS|SSL)_[A-Za-z0-9_]+)\s*(?:available)?\s*$", fd.strip())
        if not m:
            continue
        pm = re.match(r"(SSLv2|SSLv3|TLSv1(?:\.[123])?)", fd.strip())
        pr = pm.group(1) if pm else (iid.split("_x")[0].replace("cipher-", "") if iid.startswith("cipher-") else "?")
        dh = re.search(r"\bDH\s+(\d+)\b", fd)
        suites.append((pr, m.group(1), classify_suite(m.group(1)), int(dh.group(1)) if dh else None))
    ctx["suites"] = suites
    tls12_suites = [s for s in suites if not s[2].get("tls13")]
    tls13_suites = [s for s in suites if s[2].get("tls13")]
    have_cipher_data = bool(suites)

    # ---------------------------------------------------------------- certificaat (Tabel 2-5, 9)
    anon = sorted({s[1] for s in tls12_suites if s[2]["auth"] in ("anon", "NULL")})
    anon_flag = f.severity("cipherlist_aNULL") in ("HIGH", "CRITICAL") and "not" not in f.finding("cipherlist_aNULL", "not")
    if have_cipher_data or f.has("cipherlist_aNULL"):
        cl.leveled("cert", "Authenticatie met X.509-certificaat; geen anonieme (anon/NULL) suites",
                   ONVOLDOENDE if (anon or anon_flag) else VOLDOENDE,
                   ("anonieme suites: " + ", ".join(anon)) if anon else
                   ("aNULL aangeboden" if anon_flag else "geen anonieme suites aangeboden"),
                   "Verwijder alle aNULL/anon-suites.", "§3.3.2 Tabel 2")

    key_items = f.startswith("cert_keySize")
    if key_items:
        for it in key_items:
            lv, desc = classify_cert_key(it["finding"])
            tag = it["id"].replace("cert_keySize", "").strip()
            cl.leveled("cert", f"Sleutel servercertificaat {tag}".strip(), lv, f"{desc} ({it['finding']})",
                       "Gebruik RSA >= 3072 bit, ECDSA op P-256/P-384/P-521 of Ed25519/Ed448.",
                       "§3.3.2.1 Tabel 3-5")
    else:
        P("cert", "Sleutel servercertificaat", UNKNOWN, None, "cert_keySize ontbreekt in testssl-uitvoer")

    for pid, label, ref in (("FS_TLS13_sig_algs", "TLS 1.3", "§3.3.2.1 Tabel 4"),
                            ("FS_TLS12_sig_algs", "TLS 1.2", "§3.3.2.1 Tabel 4, Tabel 9")):
        fd = f.finding(pid)
        if fd is None:
            if proto.get("TLS1_3" if label == "TLS 1.3" else "TLS1_2"):
                P("cert", f"Handtekeningalgoritmes {label} (TLS-authenticatie)", UNKNOWN, None,
                  f"{pid} niet in testssl-uitvoer (gebruik testssl.sh 3.2+)")
            continue
        algs = [a for a in fd.replace(",", " ").split() if a and a != "-"]
        rated = [(a,) + classify_sigalg(a) for a in algs]
        lv = worst([r[1] for r in rated])
        bad = [f"{a} ({LEVEL_NAME[l]}, {k})" for a, l, k in rated if l is not None and l < VOLDOENDE]
        cl.leveled("cert", f"Handtekeningalgoritmes {label} (TLS-authenticatie)", lv,
                   ("aangeboden: " + " ".join(algs)) + (("  |  probleem: " + "; ".join(bad)) if bad else ""),
                   "Bied alleen RSA-PSS, ECDSA (SHA-256+) of EdDSA aan; schakel RSA-PKCS#1 v1.5, SHA-1 en "
                   "SHA-224 uit. Let op: sommige oudere TLS 1.2-clients kennen alleen PKCS#1 v1.5.", ref)

    for it in f.startswith("cert_signatureAlgorithm"):
        m = re.search(r"SHA-?(\d+)|SHA1|MD5", it["finding"], re.I)
        h = None
        if m:
            h = "SHA1" if m.group(0).upper().replace("-", "") in ("SHA1",) else ("SHA" + m.group(1) if m.group(1) else m.group(0).upper())
        lv = HASH_LEVEL.get(h) if h else None
        cl.leveled("cert", "Hash in handtekening van het certificaat >= SHA-256", lv, it["finding"],
                   "Laat het certificaat opnieuw uitgeven met SHA-256 of sterker.", "§3.3.5 Tabel 9")

    chain = f.get("cert_chain_of_trust")
    if chain:
        sev = chain.get("severity")
        ok = sev in ("OK", "INFO")
        partial = not ok and re.search(r"OK:.*(Mozilla|Microsoft|Apple|Linux)", chain["finding"])
        ordering = f.finding("certs_list_ordering_problem", "")
        P("cert", "Volledige en geldige certificaatketen (incl. intermediates)",
          PASS if ok else (ADVICE if partial else FAIL), None,
          f"{chain['finding']}" + (f"; ordering problem: {ordering}" if ordering and ordering != "no" else ""),
          "" if ok else ("Keten is geldig in de gangbare truststores; alleen enkele stores (bv. Java) falen, "
                         "vaak doordat de root-CA wordt meegestuurd. Verwijder de root uit de keten."
                         if partial else "Configureer de volledige keten (leaf + intermediates) van een vertrouwde CA."))
    exp = f.get("cert_expirationStatus")
    trust = f.get("cert_trust")
    if exp or trust:
        bad = [x for x in (exp, trust) if x and x.get("severity") in ("MEDIUM", "HIGH", "CRITICAL")]
        P("cert", "Certificaat geldig (niet verlopen) en naam past bij de host", FAIL if bad else PASS, None,
          " | ".join(f"{x['id']}: {x['finding']}" for x in (exp, trust) if x),
          "Vernieuw het certificaat of corrigeer CN/SAN." if bad else "")
    stap = f.finding("OCSP_stapling")
    if stap is not None:
        ocsp_url = (f.finding("cert_ocspURL", "") or "").strip()
        if "offered" in stap.lower() and "not" not in stap.lower():
            P("cert", "OCSP-stapling geconfigureerd", PASS, None, stap)
        elif ocsp_url in ("", "--"):
            P("cert", "OCSP-stapling geconfigureerd", PASS, None,
              f"{stap}; certificaat bevat geen OCSP-URI, dus stapling niet mogelijk (CA gebruikt alleen CRL)")
        else:
            P("cert", "OCSP-stapling geconfigureerd", ADVICE, None, f"{stap}; OCSP-URI: {ocsp_url}",
              "Schakel OCSP-stapling in (aanbeveling §3.4.5).", "§3.4.5")
    tlsa_ok, tlsa_txt = ctx.get("tlsa", (None, "niet getest"))
    P("cert", "TLSA-records voor DANE (optioneel)",
      PASS if tlsa_ok else ((INFO if "n.v.t." in tlsa_txt else UNKNOWN) if tlsa_ok is None else ADVICE),
      None, tlsa_txt, "" if tlsa_ok else "Overweeg DANE/TLSA, vooral voor mailservers.", "Hoofdstuk 2, stap 3")

    # ---------------------------------------------------------------- sleuteluitwisseling (Tabel 3, 6, 7)
    if have_cipher_data:
        nofs = sorted({s[1] for s in tls12_suites if s[2]["kx"] not in ("ECDHE", "DHE")})
        cl.leveled("kx", "Alle cipher suites bieden forward secrecy (geen statische RSA/DH/ECDH, PSK, SRP, KRB5)",
                   ONVOLDOENDE if nofs else VOLDOENDE,
                   ("zonder forward secrecy: " + ", ".join(nofs)) if nofs else "alle suites gebruiken (EC)DHE",
                   "Verwijder alle suites zonder ephemeral sleuteluitwisseling.", "§3.3.3 Tabel 6")
    else:
        P("kx", "Alle cipher suites bieden forward secrecy", UNKNOWN, None, "geen cipherlijst in testssl-uitvoer")

    kems = f.finding("FS_KEMs")
    pq_probe = ctx.get("pq_probe")
    pq_found = []
    if kems is not None:
        pq_found = [g for g in PQ_HYBRIDS if g.lower() in kems.lower()]
    if pq_probe:
        pq_found = sorted(set(pq_found) | {g for g, ok in pq_probe.items() if ok})
    if kems is None and pq_probe is None:
        P("kx", "Hybride post-quantum sleuteluitwisseling (X25519MLKEM768 e.a.)", UNKNOWN, None,
          "niet getest: testssl.sh te oud (geen FS_KEMs) en geen OpenSSL 3.5+ beschikbaar")
    else:
        ev = (f"testssl FS_KEMs: {kems}" if kems is not None else "") + \
             (f" | OpenSSL-probe: " + ", ".join(f"{g}={'ja' if ok else 'nee'}" for g, ok in pq_probe.items())
              if pq_probe else "")
        P("kx", "Hybride post-quantum sleuteluitwisseling (X25519MLKEM768 e.a.)",
          PASS if pq_found else ADVICE, GOED if pq_found else VOLDOENDE, ev.strip(" |"),
          "" if pq_found else "Niet verplicht; zonder hybride KEM is het hoogst haalbare niveau 'voldoende'. "
                              "Overweeg X25519MLKEM768 (store-now-decrypt-later).", "§3.3.3, §4.5")

    curves = f.finding("FS_ECDHE_curves")
    if curves is not None and curves.strip() and "not" not in curves.lower()[:4]:
        cs = curves.split()
        rated = [(c, group_level(c)) for c in cs]
        lv = worst([r[1] for r in rated])
        bad = [f"{c} ({LEVEL_NAME[l]})" for c, l in rated if l < VOLDOENDE]
        cl.leveled("kx", "ECDHE-curves", lv, "aangeboden: " + curves + (("  |  probleem: " + ", ".join(bad)) if bad else ""),
                   "Beperk tot secp256r1/384r1/521r1, X25519, X448 (of brainpool).", "§3.3.3.1 Tabel 3")
    elif any(s[2]["kx"] == "ECDHE" for s in tls12_suites) or proto.get("TLS1_3"):
        P("kx", "ECDHE-curves", UNKNOWN, None, "FS_ECDHE_curves ontbreekt in testssl-uitvoer")

    dhe_suites = sorted({s[1] for s in tls12_suites if s[2]["kx"] == "DHE"})
    dh_bits = sorted({s[3] for s in tls12_suites if s[2]["kx"] == "DHE" and s[3]})
    dh_groups = f.finding("DH_groups", "") or ""
    ffdhe = [g for g in re.findall(r"ffdhe\d+", dh_groups)]
    if dhe_suites or ffdhe:
        levels = [UIT_TE_FASEREN]
        notes = []
        if dhe_suites:
            notes.append(f"{len(dhe_suites)} DHE-suite(s): " + ", ".join(dhe_suites))
        if dh_bits:
            levels.append(dh_bits_level(min(dh_bits)))
            notes.append("DH-grootte: " + ", ".join(f"{b} bit" for b in dh_bits))
        if ffdhe:
            levels += [FFDHE_LEVEL.get(g, ONVOLDOENDE) for g in ffdhe]
            notes.append("finite field groups (o.a. TLS 1.3): " + " ".join(ffdhe))
        if dh_groups and not ffdhe:
            notes.append(f"DH-groep: {dh_groups}")
            if "RFC7919" not in dh_groups and "ffdhe" not in dh_groups:
                notes.append("let op: geen RFC 7919-groep (Tabel 7 noemt alleen ffdhe-groepen)")
        cl.leveled("kx", "Geen DHE (uit te faseren); zo ja, groep >= 3072 bit", worst(levels), " | ".join(notes),
                   "Faseer DHE uit (DHE = uit te faseren, ffdhe2048/<= 2048 bit = onvoldoende); stel een "
                   "uitfaseerplan op met meetbare criteria.", "§3.3.3.1 Tabel 6, Tabel 7")
    elif have_cipher_data:
        P("kx", "Geen DHE (uit te faseren)", PASS, None, "geen DHE aangeboden")

    lch = ctx.get("large_ch")
    if lch is None:
        P("kx", "Server verwerkt grote ClientHello (PQ key share)", UNKNOWN, None,
          "niet getest (OpenSSL 3.5+ nodig of --no-probes)", "", "§4.5 stap 2")
    else:
        P("kx", "Server verwerkt grote ClientHello (PQ key share)", PASS if lch[0] else FAIL, None, lch[1],
          "" if lch[0] else "Server faalt op grote ClientHello; zie https://tldr.fail", "§4.5 stap 2")

    # ---------------------------------------------------------------- bulk en hash (Tabel 8, 9, Bijlage B)
    if have_cipher_data:
        def names(pred):
            return sorted({s[1] for s in suites if pred(s[2])})
        weak = names(lambda c: c["levels"].get("bulk") == ONVOLDOENDE and not c["enc"].upper().endswith("CCM_8"))
        cl.leveled("bulk", "Geen RC4, DES, 3DES, IDEA, SEED, NULL of EXPORT", ONVOLDOENDE if weak else GOED,
                   ("aangeboden: " + ", ".join(weak)) if weak else "niet aangeboden", "Verwijder deze suites.",
                   "§3.3.4 Tabel 8")
        ccm8 = names(lambda c: (c["enc"] or "").upper().endswith("CCM_8"))
        cl.leveled("bulk", "Geen AES-CCM_8 (ingekorte authenticatietag)", ONVOLDOENDE if ccm8 else GOED,
                   ("aangeboden: " + ", ".join(ccm8)) if ccm8 else "niet aangeboden", "Verwijder CCM_8-suites.",
                   "§3.3.4 Tabel 8")
        cbc = names(lambda c: (c["enc"] or "").upper().endswith("_CBC") and c["levels"]["bulk"] == UIT_TE_FASEREN)
        cl.leveled("bulk", "Alleen AEAD-ciphers (GCM, CCM, ChaCha20-Poly1305); geen CBC", UIT_TE_FASEREN if cbc else GOED,
                   (f"{len(cbc)} CBC-suite(s): " + ", ".join(cbc)) if cbc else "geen CBC-suites",
                   "Faseer CBC-suites uit (vereist encrypt-then-MAC, beperkt afdwingbaar).", "§3.3.4")
        sha1 = names(lambda c: c.get("mac") in ("SHA", "SHA1", "MD5"))
        cl.leveled("bulk", "Geen suites met SHA-1 of MD5 als MAC", ONVOLDOENDE if sha1 else GOED,
                   (f"{len(sha1)} suite(s): " + ", ".join(sha1)) if sha1 else "geen", "Verwijder ..._SHA- en MD5-suites.",
                   "§3.3.5 Tabel 9")
        cam = names(lambda c: (c["enc"] or "").upper().startswith(("CAMELLIA", "ARIA")))
        cl.leveled("bulk", "Geen CAMELLIA of ARIA (tenzij onderbouwd)", UIT_TE_FASEREN if cam else GOED,
                   ("aangeboden: " + ", ".join(cam)) if cam else "niet aangeboden",
                   "Verwijder CAMELLIA/ARIA tenzij er een interoperabiliteitsreden is.", "§3.3.4")
        co = f.get("cipher_order")
        if co:
            bad = co.get("severity") in ("MEDIUM", "HIGH", "CRITICAL") or "NOT" in co.get("finding", "")
            P("bulk", "Servervoorkeur voor cipher suites ingeschakeld", FAIL if bad else PASS, None, co["finding"],
              "Laat de server de volgorde bepalen, sterkste suites eerst." if bad else "", "Hoofdstuk 2, stap 3")
        for label, group in (("TLS 1.3", tls13_suites), ("TLS 1.2", [s for s in tls12_suites if s[0] == "TLSv1.2"])):
            if not group:
                continue
            seen, rows = set(), []
            for s in group:
                if s[1] in seen:
                    continue
                seen.add(s[1])
                rows.append(f"{s[1]} = {LEVEL_NAME[s[2]['level']]}")
            lv = worst([s[2]["level"] for s in group])
            cl.leveled("bulk", f"Cipher suites {label} (niveau = zwakste onderdeel)", lv, "; ".join(rows),
                       "Beperk tot de suites uit Bijlage B (goed/voldoende).", "Bijlage B")
        old = [s for s in suites if s[0] in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")]
        if old:
            P("bulk", "Cipher suites op TLS 1.0/1.1/SSL", FAIL, ONVOLDOENDE,
              f"{len({s[1] for s in old})} suite(s) op verouderde protocolversies", "Verdwijnt met het uitschakelen van die versies.")
    else:
        P("bulk", "Cipher suites", UNKNOWN, None, "geen per-cipher uitvoer (draai testssl met -P of -E)")

    # ---------------------------------------------------------------- overige opties
    crime = f.get("CRIME_TLS")
    if crime:
        bad = crime.get("severity") in ("MEDIUM", "HIGH", "CRITICAL")
        cl.leveled("opts", "TLS-compressie uitgeschakeld (CRIME)", ONVOLDOENDE if bad else GOED, crime["finding"],
                   "Schakel TLS-compressie uit.", "§3.4.1 Tabel 10")
    breach = f.get("BREACH")
    if breach:
        bad = breach.get("severity") in ("MEDIUM", "HIGH", "CRITICAL")
        P("opts", "HTTP-compressie beoordeeld op BREACH (alleen '/' getest)", FAIL if bad else INFO, None,
          breach["finding"], "Controleer pagina's met gevoelige data/tokens handmatig." if not bad else
          "HTTP-compressie op gevoelige pagina's: beoordeel BREACH-risico.", "§3.4.1")
    if proto.get("TLS1_2") or proto.get("TLS1_1") or proto.get("TLS1"):
        sr = f.get("secure_renego")
        if sr:
            ok = "not" not in sr["finding"].lower() or sr.get("severity") == "OK"
            cl.leveled("opts", "Secure renegotiation (RFC 5746); geen insecure renegotiation",
                       VOLDOENDE if ok else ONVOLDOENDE, sr["finding"], "Update de TLS-bibliotheek (RFC 5746).",
                       "§3.4.2 Tabel 11")
        cr = f.get("secure_client_renego")
        if cr:
            fd = cr["finding"].lower()
            sev = cr.get("severity")
            # testssl: MEDIUM/HIGH = onbeperkt; "mitigated"/"timed out" = gelimiteerd; overige OK = geweigerd
            if sev in ("MEDIUM", "HIGH", "CRITICAL"):
                lv, ev = UIT_TE_FASEREN, "client-initiated renegotiation onbeperkt toegestaan"
            elif "mitigated" in fd or "timed out" in fd:
                lv, ev = VOLDOENDE, "client-initiated renegotiation toegestaan maar gelimiteerd"
            elif "tls 1.3 only" in fd:
                lv, ev = GOED, "n.v.t. (alleen TLS 1.3)"
            elif sev == "OK" and "not vulnerable" in fd:
                lv, ev = GOED, "client-initiated renegotiation uitgeschakeld"
            else:
                lv, ev = None, "niet eenduidig"
            cl.leveled("opts", "Client-initiated renegotiation uitgeschakeld", lv, f"{ev} (testssl: {cr['finding']})",
                       "Schakel client-initiated renegotiation uit, of limiteer het aantal pogingen.", "§3.4.2 Tabel 11")
    elif proto.get("TLS1_3") and all(proto.get(p) is False for p in ("TLS1_2", "TLS1_1", "TLS1")):
        P("opts", "Renegotiation", PASS, GOED, "n.v.t.: alleen TLS 1.3 (geen renegotiation)")
    else:
        P("opts", "Renegotiation", UNKNOWN, None, "protocolversies niet (volledig) getest")

    tick = f.finding("sessionresumption_ticket")
    sid = f.finding("sessionresumption_ID")
    if tick is not None or sid is not None:
        resum12 = (proto.get("TLS1_2") or proto.get("TLS1_1") or proto.get("TLS1")) and \
                  any(x and "supported" in x.lower() and "not" not in x.lower() for x in (tick, sid))
        ev = f"tickets: {tick}; sessie-ID's: {sid}; ticket: {f.finding('TLS_session_ticket', '-')}"
        if resum12:
            P("opts", "Sessiehervatting in TLS 1.2: ticketsleutel/sessieopslag afgeschermd en geroteerd",
              MANUAL, VOLDOENDE, ev,
              "Voldoende alleen mét aanvullende maatregelen: vraag na hoe de ticketsleutel/sessiecache wordt "
              "beschermd en hoe vaak hij wordt vervangen; anders onvoldoende.", "§3.4.3 Tabel 12")
        else:
            P("opts", "Sessiehervatting", PASS, GOED, ev + " (alleen TLS 1.3 of geen hervatting)", "", "§3.4.3 Tabel 12")
    ed = f.get("early_data")
    probe_ed = ctx.get("early_data_probe")
    decided = False
    if ed:
        fd = ed["finding"].lower()
        if fd == "supported" or ed.get("severity") == "HIGH":
            cl.leveled("opts", "0-RTT / early data uitgeschakeld", ONVOLDOENDE, f"testssl: {ed['finding']}",
                       "Schakel 0-RTT uit (replay-risico), tenzij een applicatiespecifiek profiel wordt gevolgd.",
                       "§3.4.4 Tabel 13")
            decided = True
        elif "no early data" in fd or "no tls 1.3" in fd:
            cl.leveled("opts", "0-RTT / early data uitgeschakeld", GOED, f"testssl: {ed['finding']}", "", "§3.4.4 Tabel 13")
            decided = True
    if not decided:
        if probe_ed and probe_ed[0] is not None:
            cl.leveled("opts", "0-RTT / early data uitgeschakeld", ONVOLDOENDE if probe_ed[0] else GOED,
                       f"OpenSSL-probe: {probe_ed[1]}", "Schakel 0-RTT uit (replay-risico).", "§3.4.4 Tabel 13")
        elif proto.get("TLS1_3") is False:
            P("opts", "0-RTT / early data uitgeschakeld", PASS, GOED, "n.v.t. (geen TLS 1.3)")
        else:
            P("opts", "0-RTT / early data uitgeschakeld", UNKNOWN, None,
              (f"testssl: {ed['finding']}; " if ed else "") + (probe_ed[1] if probe_ed else "niet getest"))

    # ---------------------------------------------------------------- implementatie
    ext = f.finding("TLS_extensions", "") or ""
    only13 = proto.get("TLS1_3") and not any(proto.get(p) for p in ("TLS1_2", "TLS1_1", "TLS1", "SSLv3", "SSLv2"))
    if ext or only13:
        has_ems = "extended master secret" in ext.lower()
        P("impl", "Extended Master Secret (RFC 7627)", PASS if (has_ems or only13) else FAIL, None,
          "aanwezig" if has_ems else ("n.v.t. (alleen TLS 1.3)" if only13 else "extensie ontbreekt"),
          "" if (has_ems or only13) else "Update/configureer de TLS-bibliotheek voor RFC 7627.", "§4.1")
        cbc_present = any((s[2]["enc"] or "").upper().endswith("_CBC") for s in tls12_suites)
        if cbc_present:
            has_etm = "encrypt-then-mac" in ext.lower()
            P("impl", "Encrypt-then-MAC (RFC 7366) bij CBC-suites", PASS if has_etm else FAIL, None,
              "aanwezig" if has_etm else "CBC-suites zonder encrypt-then-mac",
              "" if has_etm else "Activeer encrypt-then-MAC of verwijder CBC-suites.", "§3.3.4, Bijlage A")
        hb = "heartbeat" in ext.lower()
        P("impl", "Geen onnodige functionaliteit (heartbeat-extensie)", FAIL if hb else PASS, None,
          "heartbeat-extensie actief" if hb else "geen heartbeat-extensie",
          "Schakel heartbeat uit." if hb else "", "§4.1")

    vuln_ids = ["heartbleed", "CCS", "ticketbleed", "ROBOT", "POODLE_SSL", "POODLE_TLS", "SWEET32", "FREAK",
                "DROWN", "LOGJAM", "BEAST", "LUCKY13", "winshock", "RC4", "opossum", "starttls_injection"]
    hits, tested = [], 0
    for vid in vuln_ids:
        it = f.get(vid)
        if not it:
            continue
        tested += 1
        if it.get("severity") in ("MEDIUM", "HIGH", "CRITICAL"):
            hits.append(f"{vid}: {it['finding']}")
    if tested:
        P("impl", "Geen bekende implementatiekwetsbaarheden (Heartbleed, ROBOT, POODLE, SWEET32, ...)",
          FAIL if hits else PASS, None, "; ".join(hits) if hits else f"{tested} tests zonder bevinding",
          "Patch de TLS-bibliotheek / pas configuratie aan." if hits else "", "§4.1")
    else:
        P("impl", "Geen bekende implementatiekwetsbaarheden", UNKNOWN, None, "kwetsbaarheidstests niet uitgevoerd (-U)")
    banner = f.finding("banner_server")
    P("impl", "TLS-bibliotheek en versie bekend en up-to-date", MANUAL, None,
      f"server-banner: {banner}" if banner else "niet extern vast te stellen",
      "Vraag na welke bibliotheek (en versie) de dienst gebruikt.", "§4.1")
    for title, ref in (("Cryptografisch veilige PRNG (geen Dual EC DRBG)", "§4.2"),
                       ("TLS-proxy/anti-DDoS: privésleutels niet (zonder risicoanalyse) bij derden", "§4.3"),
                       ("Certificaatbeheer ingericht (vernieuwing, sleutelbeheer)", "§4.4")):
        P("impl", title, MANUAL, None, "niet extern meetbaar", "Navragen bij de beheerder.", ref)

    # ---------------------------------------------------------------- quantum
    if proto.get("TLS1_3") is not None:
        P("pq", "TLS 1.3 beschikbaar (voorwaarde voor PQ-algoritmes)", PASS if proto.get("TLS1_3") else ADVICE, None,
          "ja" if proto.get("TLS1_3") else "nee", "" if proto.get("TLS1_3") else "Schakel TLS 1.3 in.", "§4.5 stap 1")
    P("pq", "Hybride sleuteluitwisseling of risicoanalyse waaruit blijkt dat dit nog niet nodig is",
      PASS if pq_found else MANUAL, None,
      ("aangeboden: " + ", ".join(pq_found)) if pq_found else "geen hybride KEM gemeten",
      "" if pq_found else "Vraag naar de PQ-risicoanalyse (store-now-decrypt-later).", "§4.5 stap 6")
    if have_cipher_data:
        strong = sorted({s[1] for s in suites if s[2]["levels"].get("bulk") == GOED and s[2].get("mac") in ("SHA384", "SHA512", None)
                         or (s[2].get("tls13") and s[2]["levels"].get("bulk") == GOED)})
        P("pq", "Bulkversleuteling en hashing met 256-bit sterkte beschikbaar", PASS if strong else FAIL, None,
          ", ".join(strong[:4]) if strong else "geen AES-256-GCM/ChaCha20-Poly1305-suite",
          "" if strong else "Bied AES-256-GCM of ChaCha20-Poly1305 aan.", "§4.5 stap 3")
    P("pq", "Crypto-agility; TLS-gebruik in de organisatie geïnventariseerd", MANUAL, None, "niet extern meetbaar",
      "Navragen bij de beheerder.", "§4.5 stap 4-5")
    return cl


# --------------------------------------------------------------------------------------
# Rapportage
# --------------------------------------------------------------------------------------
def render_markdown(cl, meta):
    out = []
    out.append(f"# TLS-checklist {meta['target']}")
    out.append("")
    out.append(f"Getoetst aan: {GUIDELINE}  ")
    out.append(f"Scan: {meta['date']} · script v{__version__} · {meta.get('testssl_version', '')}  ")
    if meta.get("ip"):
        out.append(f"IP: {meta['ip']}  ")
    counts = {}
    for it in cl.items:
        counts[it["status"]] = counts.get(it["status"], 0) + 1
    out.append("")
    out.append("**Samenvatting:** " + ", ".join(f"{STATUS_LABEL[s]}: {counts.get(s, 0)}"
                                               for s in (PASS, FAIL, ADVICE, MANUAL, UNKNOWN, INFO) if counts.get(s)))
    out.append("")
    out.append("Legenda: `[x]` = goed/voldoende of n.v.t. · `[ ]` = bevinding, advies, navraag of niet gemeten.")
    out.append("")
    for key, title in SECTIONS:
        rows = [it for it in cl.items if it["section"] == key]
        if not rows:
            continue
        out.append(f"## {title}")
        out.append("")
        for it in rows:
            box = "[x]" if it["status"] in (PASS,) else "[ ]"
            lvl = f" — **{it['level']}**" if it.get("level") and it["level"] != "-" else ""
            tag = f" `{STATUS_LABEL[it['status']]}`"
            out.append(f"- {box} {it['title']}{lvl}{tag}")
            if it.get("evidence"):
                out.append(f"    - Gemeten: {it['evidence']}")
            if it.get("advice"):
                out.append(f"    - Advies: {it['advice']}")
            if it.get("ref"):
                out.append(f"    - Richtlijn: {it['ref']}")
        out.append("")
    # bevindingen voor rapportage
    fails = [it for it in cl.items if it["status"] == FAIL]
    fails.sort(key=lambda x: (x.get("level_num") or 0))
    out.append("## Bevindingen voor rapportage")
    out.append("")
    if fails:
        out.append("| # | Bevinding | NCSC-niveau | Gemeten | Richtlijn |")
        out.append("| --- | --- | --- | --- | --- |")
        for i, it in enumerate(fails, 1):
            ev = it["evidence"].replace("|", "/")
            if len(ev) > 300:
                ev = ev[:297] + "..."
            out.append(f"| {i} | {it['title']} | {it.get('level') or '-'} | {ev} | {it.get('ref', '')} |")
    else:
        out.append("Geen bevindingen op extern meetbare punten.")
    man = [it for it in cl.items if it["status"] == MANUAL]
    if man:
        out.append("")
        out.append("**Navragen bij beheerder:**")
        out.append("")
        for it in man:
            out.append(f"- [ ] {it['title']}")
    unk = [it for it in cl.items if it["status"] == UNKNOWN]
    if unk:
        out.append("")
        out.append("**Niet gemeten (handmatig aanvullen):**")
        out.append("")
        for it in unk:
            out.append(f"- [ ] {it['title']} — {it['evidence']}")
    out.append("")
    return "\n".join(out)


COLORS = {PASS: "\033[32m", FAIL: "\033[31m", ADVICE: "\033[33m", MANUAL: "\033[36m", UNKNOWN: "\033[35m", INFO: "\033[37m"}


def print_console(cl, meta, color=True):
    print(f"\n=== {meta['target']}  ({GUIDELINE}) ===")
    for key, title in SECTIONS:
        rows = [it for it in cl.items if it["section"] == key]
        if not rows:
            continue
        print(f"\n{title}")
        for it in rows:
            lab = STATUS_LABEL[it["status"]]
            c, r = (COLORS[it["status"]], "\033[0m") if color else ("", "")
            lvl = f" [{it['level']}]" if it.get("level") and it["level"] != "-" else ""
            print(f"  {c}{lab:<9}{r} {it['title']}{lvl}")
            if it["status"] in (FAIL, UNKNOWN) and it.get("evidence"):
                print(f"            {it['evidence'][:220]}")


# --------------------------------------------------------------------------------------
# Hoofdprogramma
# --------------------------------------------------------------------------------------
def parse_target(t, default_port):
    t = t.strip()
    t = re.sub(r"^https?://", "", t).split("/")[0]
    if t.startswith("["):
        host, _, rest = t[1:].partition("]")
        port = rest.lstrip(":") or default_port
    elif t.count(":") == 1:
        host, port = t.split(":")
    else:
        host, port = t, default_port
    return host, int(port)


STARTTLS_DEFAULT_PORT = {"smtp": 25, "imap": 143, "pop3": 110, "ftp": 21, "xmpp": 5222, "ldap": 389,
                         "postgres": 5432, "mysql": 3306, "lmtp": 24, "nntp": 119, "sieve": 4190, "irc": 6667}

# nmap-servicenaam -> testssl STARTTLS-protocol
NMAP_STARTTLS = {"smtp": "smtp", "submission": "smtp", "lmtp": "lmtp", "imap": "imap", "pop3": "pop3",
                 "ftp": "ftp", "xmpp-client": "xmpp", "xmpp": "xmpp", "jabber": "xmpp",
                 "xmpp-server": "xmpp-server", "ldap": "ldap", "postgresql": "postgres", "mysql": "mysql",
                 "nntp": "nntp", "sieve": "sieve", "managesieve": "sieve", "irc": "irc"}
# servicenamen die zonder -sV-tunnelinformatie toch direct TLS zijn
NMAP_TLS_NAMES = {"https", "https-alt", "ssl", "imaps", "pop3s", "smtps", "submissions", "ldaps", "ftps",
                  "ftps-data", "ircs", "ircs-u", "nntps", "xmpps", "sips", "ms-wbt-server-ssl", "rdp-ssl"}


class ScanError(Exception):
    pass


def parse_nmap_xml(path):
    """Geeft per host de open TLS- en STARTTLS-diensten uit een nmap -oX bestand."""
    import xml.etree.ElementTree as ET
    root = ET.parse(path).getroot()
    hosts = []
    for h in root.findall("host"):
        addr = None
        for xp in ("address[@addrtype='ipv4']", "address[@addrtype='ipv6']", "address"):
            if h.find(xp) is not None:  # let op: lege Elements zijn falsy
                addr = h.find(xp)
                break
        names = [hn.get("name") for hn in h.findall("hostnames/hostname") if hn.get("type") in ("user", None)] or \
                [hn.get("name") for hn in h.findall("hostnames/hostname")]
        services = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            sv = p.find("service")
            name = (sv.get("name") if sv is not None else "") or ""
            tunnel = (sv.get("tunnel") if sv is not None else "") or ""
            product = " ".join(x for x in ((sv.get("product") if sv is not None else ""),
                                           (sv.get("version") if sv is not None else "")) if x)
            port = int(p.get("portid"))
            proto = p.get("protocol")
            if proto != "tcp":
                continue
            if tunnel == "ssl" or name in NMAP_TLS_NAMES or name.startswith("ssl"):
                services.append({"port": port, "name": (f"ssl/{name}" if tunnel == "ssl" else name),
                                 "starttls": None, "product": product})
            elif name in NMAP_STARTTLS:
                services.append({"port": port, "name": name, "starttls": NMAP_STARTTLS[name], "product": product})
        hosts.append({"ip": addr.get("addr") if addr is not None else None,
                      "hostname": names[0] if names else None, "services": services})
    return hosts


def nmap_discover(host, args, outdir):
    xml_path = os.path.join(outdir, f"{re.sub(r'[^A-Za-z0-9._-]', '_', host)}_nmap.xml")
    nmap = shutil.which("nmap")
    if not nmap:
        raise ScanError("nmap niet gevonden (sudo apt install nmap)")
    cmd = [nmap, "-Pn", "-sV", "--open", "-p", args.ports, "-oX", xml_path]
    if args.nmap_args:
        cmd += args.nmap_args.split()
    cmd.append(args.ip or host)
    print(f"[*] nmap zoekt TLS-diensten op {host} (-p {args.ports}) ...", file=sys.stderr)
    rc, out = run(cmd, timeout=args.nmap_timeout)
    if not os.path.exists(xml_path):
        raise ScanError(f"nmap leverde geen XML op: {out.strip()[-300:]}")
    return xml_path


def scan_target(target, args, outdir, starttls=None, discovery=None):
    starttls = starttls if starttls is not None else args.starttls
    default_port = STARTTLS_DEFAULT_PORT.get(starttls, 443) if starttls else 443
    host, port = parse_target(target, default_port)
    is_ip = bool(re.match(r"^[\d.]+$|^[0-9a-f:]+$", host, re.I))
    sni = None if is_ip else host
    base = os.path.join(outdir, f"{re.sub(r'[^A-Za-z0-9._-]', '_', host)}_{port}")
    meta = {"target": f"{host}:{port}" + (f" (STARTTLS {starttls})" if starttls else ""),
            "date": dt.datetime.now().strftime("%Y-%m-%d %H:%M"), "starttls": starttls, "ip": args.ip,
            "md": base + "_ncsc.md"}
    ctx = {"discovery": discovery}

    # ---- OpenSSL
    ver, vtxt = openssl_version(args.openssl)
    ctx["openssl_version"] = vtxt or "openssl niet gevonden"
    ctx["openssl_pq"] = bool(ver and ver >= (3, 5, 0))

    # ---- testssl
    if args.json:
        json_path = args.json
        meta["testssl_version"] = "bestaande testssl-JSON: " + os.path.basename(json_path)
    else:
        testssl = find_testssl(args.testssl)
        if not testssl:
            raise ScanError("testssl.sh niet gevonden; installeer het (sudo apt install testssl.sh) "
                            "of geef het pad op met --testssl")
        json_path = base + "_testssl.json"
        log_path = base + "_testssl.log"
        if os.path.exists(json_path):
            os.remove(json_path)
        cmd = [testssl, "--quiet", "--warnings", "off", "--color", "0", "--jsonfile", json_path,
               "-p", "-s", "-f", "-P", "-S", "-h", "-U"]
        if starttls:
            cmd += ["-t", starttls]
        if args.ip:
            cmd += ["--ip", args.ip]
        if args.testssl_args:
            cmd += args.testssl_args.split()
        cmd.append(f"{host}:{port}")
        print(f"[*] testssl.sh draait tegen {meta['target']} (kan enkele minuten duren) ...", file=sys.stderr)
        rc, out = run(cmd, timeout=args.timeout)
        with open(log_path, "w") as fh:
            fh.write(out)
        rc2, vout = run([testssl, "--version"], timeout=30)
        vout = re.sub(r"\x1b\[[0-9;]*m", "", vout)
        m = re.search(r"testssl\.sh(?: version)?\s+([\w.\-]+)", vout)
        meta["testssl_version"] = f"testssl.sh {m.group(1)}" if m else "testssl.sh"
        if not os.path.exists(json_path):
            raise ScanError(f"testssl.sh leverde geen JSON op; zie {log_path}")
    ctx["testssl_version"] = meta["testssl_version"]
    f = Findings(load_testssl_json(json_path))
    fatal = [it for it in f.items if it.get("severity") == "FATAL"]
    if fatal and not any(f.has(p) for p in ("TLS1_2", "TLS1_3", "TLS1")):
        raise ScanError("testssl.sh: " + "; ".join(it.get("finding", "") for it in fatal)[:300])
    if not meta.get("ip"):
        for it in f.items:
            if it.get("ip"):
                meta["ip"] = it["ip"].split("/")[-1]
                break

    # ---- aanvullende probes
    if not args.no_probes and ver:
        prober = Prober(args.openssl, host, port, sni, starttls, args.ip)
        print("[*] aanvullende OpenSSL-probes ...", file=sys.stderr)
        if ctx["openssl_pq"]:
            ctx["pq_probe"] = prober.pq_groups()
            ctx["large_ch"] = prober.large_clienthello()
        ed = f.get("early_data")
        if (not ed or ed.get("severity") in ("WARN", "INFO")) and not starttls:
            http = (f.finding("service", "") or "").upper().startswith("HTTP") or port in (443, 8443)
            try:
                ctx["early_data_probe"] = prober.early_data(http)
            except Exception as e:  # noqa: BLE001
                ctx["early_data_probe"] = (None, f"probe mislukt: {e}")
    if sni and not args.no_dns:
        ctx["tlsa"] = dns_tlsa(host, port)
    elif is_ip:
        ctx["tlsa"] = (None, "n.v.t. (IP-adres als doel)")

    cl = assess(f, ctx)
    md = render_markdown(cl, meta)
    with open(base + "_ncsc.md", "w", encoding="utf-8") as fh:
        fh.write(md)
    with open(base + "_ncsc.json", "w", encoding="utf-8") as fh:
        json.dump({"meta": meta, "guideline": GUIDELINE, "items": cl.items,
                   "cipher_suites": [{"protocol": s[0], "suite": s[1], "level": LEVEL_NAME[s[2]["level"]],
                                      "components": {k: LEVEL_NAME[v] for k, v in s[2]["levels"].items()}}
                                     for s in ctx.get("suites", [])]},
                  fh, indent=2, ensure_ascii=False)
    print_console(cl, meta, color=sys.stdout.isatty() and not args.no_color)
    print(f"\n[+] Checklist: {base}_ncsc.md\n[+] JSON:      {base}_ncsc.json", file=sys.stderr)
    cl.md_path = base + "_ncsc.md"
    return cl


def main():
    ap = argparse.ArgumentParser(description="Toets een TLS-dienst aan de NCSC TLS-richtlijnen 2025-05.")
    ap.add_argument("targets", nargs="*", help="host[:poort] (standaard poort 443)")
    ap.add_argument("-f", "--file", help="bestand met één target per regel")
    ap.add_argument("-o", "--outdir", default=".", help="map voor resultaten (standaard: huidige map)")
    ap.add_argument("-t", "--starttls", help="STARTTLS-protocol: smtp, imap, pop3, ftp, xmpp, ldap, ...")
    ap.add_argument("--ip", help="test dit IP-adres (bv. bij meerdere A-records of /etc/hosts)")
    ap.add_argument("--json", help="bestaande testssl.sh JSON (--jsonfile) gebruiken in plaats van scannen")
    ap.add_argument("--testssl", help="pad naar testssl.sh")
    ap.add_argument("--testssl-args", help="extra argumenten voor testssl.sh, tussen aanhalingstekens")
    ap.add_argument("--openssl", default=os.environ.get("NCSC_OPENSSL", "openssl"),
                    help="pad naar openssl (3.5+ aanbevolen voor PQ-probes)")
    ap.add_argument("--no-probes", action="store_true", help="geen aanvullende OpenSSL-probes")
    ap.add_argument("--no-dns", action="store_true", help="geen TLSA/DANE-lookup")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--timeout", type=int, default=1800, help="max. seconden voor testssl.sh (standaard 1800)")
    d = ap.add_argument_group("poortontdekking met nmap")
    d.add_argument("-d", "--discover", action="store_true",
                   help="zoek met nmap alle TLS- en STARTTLS-diensten op de host en toets ze allemaal")
    d.add_argument("--ports", default="1-65535", help="poorten voor nmap (standaard alle: 1-65535)")
    d.add_argument("--nmap-args", default="-T4", help="extra nmap-argumenten (standaard: -T4)")
    d.add_argument("--nmap-xml", help="bestaande nmap -oX uitvoer gebruiken in plaats van opnieuw scannen")
    d.add_argument("--nmap-timeout", type=int, default=7200, help="max. seconden voor nmap (standaard 7200)")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args()

    targets = list(args.targets)
    if args.file:
        with open(args.file) as fh:
            targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not targets and not args.nmap_xml:
        ap.error("geef minstens één target op")
    if args.json and (len(targets) > 1 or args.discover or args.nmap_xml):
        ap.error("--json werkt met precies één target, zonder --discover/--nmap-xml")
    os.makedirs(args.outdir, exist_ok=True)

    # ---- bepaal de lijst (target, starttls, discovery-info)
    jobs = []
    if args.discover or args.nmap_xml:
        xml_hosts = []
        if args.nmap_xml:
            xml_hosts = parse_nmap_xml(args.nmap_xml)
            if not targets:  # alle hosts uit de XML
                targets = [h["hostname"] or h["ip"] for h in xml_hosts]
        for t in targets:
            host, _ = parse_target(t, 443)
            try:
                if args.nmap_xml:
                    match = [h for h in xml_hosts if host in (h["hostname"], h["ip"])]
                    if not match:
                        print(f"[!] {host} niet gevonden in {args.nmap_xml}", file=sys.stderr)
                        continue
                    hinfo, ports_arg = match[0], f"uit {os.path.basename(args.nmap_xml)}"
                else:
                    hinfo = parse_nmap_xml(nmap_discover(host, args, args.outdir))
                    if not hinfo:
                        print(f"[!] nmap: {host} niet bereikbaar", file=sys.stderr)
                        continue
                    hinfo, ports_arg = hinfo[0], f"-p {args.ports}"
            except ScanError as e:
                sys.exit(f"[!] {e}")
            svcs = hinfo["services"]
            print(f"[+] {host}: {len(svcs)} TLS-dienst(en): " +
                  (", ".join(f"{s['port']}/{s['name']}" + (f"+STARTTLS" if s["starttls"] else "") for s in svcs) or "geen"),
                  file=sys.stderr)
            disc = {"ports_arg": ports_arg, "services": svcs}
            for s in svcs:
                jobs.append((f"{host}:{s['port']}", s["starttls"], disc, s))
    else:
        jobs = [(t, None, None, None) for t in targets]

    # ---- toetsen
    summary = []
    for t, stls, disc, svc in jobs:
        try:
            cl = scan_target(t, args, args.outdir, starttls=stls, discovery=disc)
        except ScanError as e:
            print(f"[!] {t}: {e}", file=sys.stderr)
            summary.append({"target": t, "starttls": stls, "error": str(e), "svc": svc})
            continue
        cnt = {s: sum(1 for it in cl.items if it["status"] == s) for s in (FAIL, ADVICE, MANUAL, UNKNOWN)}
        worst_lv = worst([it.get("level_num") for it in cl.items if it["status"] == FAIL])
        worst_txt = LEVEL_NAME[worst_lv] if worst_lv else ("geen NCSC-niveau (bv. certificaat)" if cnt[FAIL] else "-")
        summary.append({"target": t, "starttls": stls, "counts": cnt, "worst": worst_txt,
                        "md": os.path.basename(cl.md_path), "svc": svc})

    if len(summary) > 1 or (summary and summary[0].get("error")) or args.discover or args.nmap_xml:
        write_overview(summary, args.outdir)
    sys.exit(1 if any(s.get("error") or s["counts"][FAIL] for s in summary) else 0)


def write_overview(summary, outdir):
    lines = ["# Overzicht TLS-toetsing (NCSC 2025-05)", "",
             f"Datum: {dt.datetime.now().strftime('%Y-%m-%d %H:%M')}", "",
             "| Dienst | STARTTLS | Bevindingen | Zwakste niveau | Advies | Navraag | Onbekend | Checklist |",
             "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    print("\nOverzicht:", file=sys.stderr)
    for s in summary:
        name = s["target"] + (f" ({s['svc']['name']})" if s.get("svc") else "")
        if s.get("error"):
            lines.append(f"| {name} | {s['starttls'] or '-'} | scan mislukt | - | - | - | - | {s['error'][:120]} |")
            print(f"  {name:<40} MISLUKT: {s['error'][:100]}", file=sys.stderr)
            if s["starttls"]:
                print(f"  {'':<40} (geen STARTTLS? dan gaat deze dienst onversleuteld - controleer handmatig)",
                      file=sys.stderr)
            continue
        c = s["counts"]
        lines.append(f"| {name} | {s['starttls'] or '-'} | {c[FAIL]} | {s['worst']} | {c[ADVICE]} | {c[MANUAL]} | "
                     f"{c[UNKNOWN]} | [{s['md']}]({s['md']}) |")
        print(f"  {name:<40} {c[FAIL]} bevinding(en), zwakste: {s['worst']}", file=sys.stderr)
    fails = [s for s in summary if s.get("error") and s.get("starttls")]
    if fails:
        lines += ["", "Een STARTTLS-dienst waarvan de scan mislukt, biedt mogelijk geen STARTTLS aan en "
                      "communiceert dan onversleuteld. Controleer dit handmatig."]
    path = os.path.join(outdir, "overzicht.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"[+] Overzicht: {path}", file=sys.stderr)


if __name__ == "__main__":
    main()
