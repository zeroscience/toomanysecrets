"""FTP / HTTP(AD) / SNMP engines - pure parsers + findings, no tool/host needed.

FTP parses captured nxc ftp output; HTTP and SNMP inject their fetch/runner. Run:
    python tests/test_protocol_engines.py   (or)   python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.engines import ftp, http_ad, snmp  # noqa: E402
from redness.engines.base import Target  # noqa: E402
from redness.findings import Category, Severity  # noqa: E402

# --------------------------------------------------------------------------- #
# FTP                                                                          #
# --------------------------------------------------------------------------- #
FTP_ANON = (
    "FTP         10.10.0.10      21     HOST             [*] Banner: Microsoft FTP Service\n"
    "FTP         10.10.0.10      21     HOST             [+] anonymous: - Anonymous Login!\n"
)
FTP_CREDS = (
    "FTP         10.10.0.10      21     HOST             [*] Banner: vsFTPd 3.0.3\n"
    "FTP         10.10.0.10      21     HOST             [+] jdoe:Passw0rd!\n"
)


def test_ftp_anonymous():
    by = {f.id: f for f in ftp.parse_ftp(FTP_ANON)}
    assert by["ftp-anonymous"].severity is Severity.MEDIUM
    assert by["ftp-anonymous"].category is Category.CONFIG
    assert by["ftp-exposed"].severity is Severity.INFO
    assert "Microsoft FTP Service" in by["ftp-exposed"].evidence[0].detail
    assert "ftp-access" not in by                          # anonymous is not a cred hit


def test_ftp_credentialed_access():
    by = {f.id: f for f in ftp.parse_ftp(FTP_CREDS, credentialed=True)}
    assert "ftp-anonymous" not in by
    assert by["ftp-access"].severity is Severity.LOW and "jdoe" in by["ftp-access"].title
    assert "vsFTPd 3.0.3" in by["ftp-exposed"].evidence[0].detail


def test_ftp_no_output_no_findings():
    assert ftp.parse_ftp("") == []


# --------------------------------------------------------------------------- #
# HTTP (AD-scoped)                                                             #
# --------------------------------------------------------------------------- #
def _P(label, scheme, status, server=""):
    return http_ad.Probe(label=label, scheme=scheme, status=status, server=server)


def test_http_certsrv_is_esc8_high_adcs():
    fs = http_ad.build_findings("10.10.0.5", [
        _P("certsrv", "https", 401), _P("root", "https", 200, "Microsoft-IIS/10.0")])
    by = {f.id: f for f in fs}
    assert by["adcs-web-enrollment"].severity is Severity.HIGH
    assert by["adcs-web-enrollment"].category is Category.ADCS
    assert "T1649" in by["adcs-web-enrollment"].references[0]
    assert by["http-exposed"].severity is Severity.INFO


def test_http_certsrv_absent_no_adcs():
    fs = http_ad.build_findings("10.10.0.5", [_P("certsrv", "https", 404),
                                              _P("root", "https", 200)])
    assert not any(f.id == "adcs-web-enrollment" for f in fs)


def test_http_owa_exposed_low():
    fs = http_ad.build_findings("10.10.0.5", [_P("owa", "https", 302), _P("root", "https", 200)])
    by = {f.id: f for f in fs}
    assert by["exchange-owa-exposed"].severity is Severity.LOW


def test_http_engine_run_with_injected_fetch():
    def fake(url, timeout):
        if url.endswith("/certsrv/"):
            return 401, ""
        if url.endswith("/certsrv/certfnsh.asp"):
            return 200, ""
        if url.rstrip("/").endswith("10.10.0.5"):          # root
            return 200, "Microsoft-IIS/10.0"
        if "https://" in url:
            return 404, ""
        return 0, ""                                       # http scheme not listening

    eng = http_ad.HttpEngine(fetch=fake)
    ids = {f.id for f in eng.run(Target(host="10.10.0.5"))}
    assert "adcs-web-enrollment" in ids and "http-exposed" in ids


# --------------------------------------------------------------------------- #
# SNMP                                                                         #
# --------------------------------------------------------------------------- #
SNMP_OK = ".1.3.6.1.2.1.1.1.0 = STRING: Hardware: Intel64 Family - Windows Server 2019\n"
SNMP_TIMEOUT = "Timeout: No Response from 10.10.0.9\n"


def test_parse_snmp_reads_sysdescr():
    assert "Windows Server 2019" in snmp.parse_snmp(SNMP_OK)
    assert snmp.parse_snmp(SNMP_TIMEOUT) is None


def test_snmp_public_high_private_critical():
    fs = snmp.build_findings("10.10.0.9", [("public", "Cisco IOS"), ("private", "Cisco IOS")])
    sev = {f.title.split("'")[1]: f.severity for f in fs}
    assert sev["public"] is Severity.HIGH
    assert sev["private"] is Severity.CRITICAL


def test_snmp_engine_run_with_injected_runner():
    def runner(host, community):
        return SNMP_OK if community == "public" else SNMP_TIMEOUT

    eng = snmp.SnmpEngine(runner=runner)
    fs = eng.run(Target(host="10.10.0.9"))
    assert [f.id for f in fs] == ["snmp-default-community"]
    assert fs[0].severity is Severity.HIGH                 # only 'public' answered


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
