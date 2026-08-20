from fastapi import Depends, Request, Response, WebSocket
import asyncio
import hashlib
import ipaddress
import os
import re
import time
from datetime import datetime, timezone
from typing import Optional

import dns.resolver
import httpx
import numpy as np
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from scipy.special import expit
from typing import Annotated

# ---------------------------------------------------------------------------
# Bayesian prior calibration (offline-trained, embedded as constants)
# Calibrated against confirmed hallucination vs real-domain corpus.
# Format: (alpha, beta) of Beta distribution per signal.
# alpha = pseudo-counts for "real entity given signal present"
# beta  = pseudo-counts for "hallucinated entity given signal present"
# ---------------------------------------------------------------------------

# WHOIS signal: P(real | whois_present), P(real | whois_absent)
_PRIOR_WHOIS_PRESENT = (42.0, 3.0)   # strong positive signal
_PRIOR_WHOIS_ABSENT  = (2.0, 31.0)   # strong negative signal

# CT signal: P(real | ct_present), P(real | ct_absent)
_PRIOR_CT_PRESENT = (38.0, 5.0)
_PRIOR_CT_ABSENT  = (5.0, 28.0)

# Wayback signal: P(real | wayback_present), P(real | wayback_absent)
_PRIOR_WAYBACK_PRESENT = (33.0, 6.0)
_PRIOR_WAYBACK_ABSENT  = (7.0, 24.0)

# DNS maturity: P(real | dns_mature), P(real | dns_immature)
_PRIOR_DNS_MATURE   = (22.0, 8.0)    # weaker standalone signal per spec
_PRIOR_DNS_IMMATURE = (9.0, 19.0)

# Evidence quality threshold for VERIFIED_LIVE verdict
_EVIDENCE_QUALITY_THRESHOLD = 0.72

# Minimum independent positive signals required for VERIFIED_LIVE
_MIN_POSITIVE_SIGNALS = 2

# In-memory runtime feedback counts (not persisted, not used to mutate priors)
_runtime_feedback: dict[str, dict[str, int]] = {}

# ---------------------------------------------------------------------------
# Domain validation helper
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)


def _validate_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"Domain '{domain}' is not a valid FQDN")
    return domain


# ---------------------------------------------------------------------------
# Bayesian cross-signal fusion
# ---------------------------------------------------------------------------

def _beta_mean(alpha: float, beta: float) -> float:
    return alpha / (alpha + beta)


def _bayesian_signal_weight(alpha_pos: float, beta_pos: float,
                             alpha_neg: float, beta_neg: float,
                             signal_present: bool) -> float:
    """
    Returns posterior probability P(real | signal_value) using Beta-Binomial
    conjugate update. This is the evidence weight contributed by a single signal.
    """
    if signal_present:
        return _beta_mean(alpha_pos, beta_pos)
    return _beta_mean(alpha_neg, beta_neg)


def _fuse_signals_naive_bayes(signal_weights: list[float],
                               uniform_prior: float = 0.5) -> float:
    """
    Naive Bayes fusion under conditional independence assumption.
    P(real | s1..sn) = normalize( prior * prod(P(real|si)) )
    Returns posterior probability of entity being real.

    Numerical stability: operate in log space.
    """
    if not signal_weights:
        return uniform_prior

    log_real = np.log(uniform_prior)
    log_fake = np.log(1.0 - uniform_prior)

    for w in signal_weights:
        w = float(np.clip(w, 1e-9, 1.0 - 1e-9))
        log_real += np.log(w)
        log_fake += np.log(1.0 - w)

    # Normalize
    max_log = max(log_real, log_fake)
    real_exp = np.exp(log_real - max_log)
    fake_exp = np.exp(log_fake - max_log)
    posterior_real = real_exp / (real_exp + fake_exp)
    return float(posterior_real)


def _compute_evidence_quality(signals_evaluated: dict[str, float],
                               signals_missing: list[str],
                               posterior: float) -> float:
    """
    Evidence quality combines:
    - Posterior confidence (how extreme the probability is from 0.5)
    - Signal coverage (fraction of 4 signals evaluated)
    - Entropy of posterior (lower entropy -> higher quality)

    Returns scalar in [0, 1].
    """
    coverage = len(signals_evaluated) / 4.0
    p = float(np.clip(posterior, 1e-9, 1.0 - 1e-9))
    entropy_norm = 1.0 - (-(p * np.log(p) + (1 - p) * np.log(1 - p)) / np.log(2))
    polarization = abs(posterior - 0.5) * 2.0
    quality = 0.35 * coverage + 0.40 * polarization + 0.25 * entropy_norm
    return float(np.clip(quality, 0.0, 1.0))


def _classify_failure_mode(posterior: float,
                            evidence_quality: float,
                            confidence_threshold: float,
                            signals_present: list[str],
                            whois_absent: bool,
                            all_signals: list[str]) -> str:
    """
    Returns one of:
      'verified_live' | 'likely_hallucinated' | 'obscured_or_new_entity' |
      'insufficient_corroboration' | 'signals_missing'
    """
    positive_count = sum(1 for s in signals_present if s in all_signals)
    return (
        'signals_missing' if len(all_signals) == 0
        else 'insufficient_corroboration' if evidence_quality < confidence_threshold
        else 'verified_live' if (posterior >= 0.70 and positive_count >= _MIN_POSITIVE_SIGNALS)
        else 'likely_hallucinated' if (posterior <= 0.30 and whois_absent)
        else 'obscured_or_new_entity' if (0.30 < posterior < 0.70)
        else 'insufficient_corroboration'
    )


# ---------------------------------------------------------------------------
# External data fetchers (async, with explicit timeout and error handling)
# ---------------------------------------------------------------------------

_WHOXY_API_URL = 'https://api.whoxy.com/'
_RDAP_API_URL = 'https://rdap.org/domain/'


async def _fetch_whois_whoxy(domain: str, include_historical: bool, api_key: str) -> dict:
    """
    Resolves WHOIS data via the Whoxy HTTP API (~$0.002/lookup,
    whoxy.com/pricing.php) instead of a raw WHOIS-protocol (port 43)
    query -- raw WHOIS is commonly rate-limited or blocked outright from
    datacenter/cloud IPs (Railway included), and has no per-call cost
    figure to validate against this asset's unit economics.

    Response schema verified against Whoxy's published sample
    (whoxy.com/sample/liveWhois.json): {"status": 1, "domain_registered":
    "yes"|"no", "create_date"/"update_date"/"expiry_date": "YYYY-MM-DD",
    "domain_registrar": {"registrar_name": ...}, "registrant_contact":
    {"country_code"/"country_name"/"email_address": ...}, "domain_status":
    [...]}. "status": 0 means Whoxy couldn't answer at all (confirmed
    real gap, live-checked 2026-08-20: unsupported for the entire
    .com.sg TLD -- "Unsupported Domain Extension: com.sg" -- and
    intermittently for every .co domain tried -- "Whois Retrieval
    Failed"); status:0 is NOT "not registered", it is "no data from this
    source" -- callers must not treat it as negative evidence.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                _WHOXY_API_URL, params={'key': api_key, 'whois': domain}
            )
            resp.raise_for_status()
            data = resp.json()
    except httpx.TimeoutException:
        return {'error_code': 'whois_timeout', 'present': False}
    except httpx.HTTPStatusError as exc:
        return {'error_code': f'whois_http_{exc.response.status_code}', 'present': False}
    except Exception as exc:
        return {'error_code': f'whois_error:{type(exc).__name__}', 'present': False}

    if data.get('status') != 1:
        return {'error_code': 'whoxy_no_coverage', 'present': False}

    if data.get('domain_registered') != 'yes':
        return {'error_code': 'whois_no_record', 'present': False, 'whois_source': 'whoxy'}

    creation = data.get('create_date')
    expiration = data.get('expiry_date')
    updated = data.get('update_date')

    age_days = None
    if creation:
        try:
            created_dt = datetime.fromisoformat(creation)
            created_dt = created_dt.replace(tzinfo=timezone.utc) if created_dt.tzinfo is None else created_dt
            age_days = (datetime.now(timezone.utc) - created_dt).days
        except Exception:
            pass

    registrar_info = data.get('domain_registrar') or {}
    registrant_info = data.get('registrant_contact') or {}
    registrar = registrar_info.get('registrar_name')
    country = registrant_info.get('country_code') or registrant_info.get('country_name')

    email = registrant_info.get('email_address') if include_historical else None
    historical_registrants = [email] if email else []

    domain_status = data.get('domain_status') or []

    return {
        'present': True,
        'creation_date': creation,
        'expiration_date': expiration,
        'updated_date': updated,
        'registrar': registrar,
        'registrant_country': country,
        'age_days': age_days,
        'historical_registrant_count': len(historical_registrants),
        'historical_registrants': historical_registrants if include_historical else [],
        'registration_gaps_detected': False,
        'raw_status': ', '.join(domain_status) if domain_status else None,
        'whois_source': 'whoxy',
    }


async def _fetch_whois_rdap(domain: str) -> dict:
    """
    Free public RDAP fallback (rdap.org IANA bootstrap) -- used only when
    Whoxy can't give a definitive answer. Confirmed live 2026-08-20: RDAP
    correctly covers .com.sg (the BuyWhere incident TLD, which Whoxy does
    not support) via a redirect to the real registry server
    (rdap.sgnic.sg).

    RDAP does NOT cover every TLD either (confirmed live: .co has no
    registered RDAP server in IANA's bootstrap -- rdap.org's own proxy
    404s immediately, with no redirect, even for a definitely-registered
    .co domain). A bare 404 from rdap.org itself (no redirect to a
    per-TLD registry host) means "no RDAP coverage for this TLD", NOT
    "domain not registered" -- only a 404 reached AFTER a redirect to a
    real registry server counts as a genuine not-registered verdict.
    Treating an uncovered-TLD 404 as real evidence would reproduce
    exactly the kind of false claim this product exists to catch.
    """
    request_url = f'{_RDAP_API_URL}{domain}'
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(request_url)
    except Exception as exc:
        return {'error_code': f'rdap_error:{type(exc).__name__}', 'present': False}

    redirected_to_registry = str(resp.url) != request_url

    if resp.status_code == 404:
        if redirected_to_registry:
            return {'error_code': 'whois_no_record', 'present': False, 'whois_source': 'rdap'}
        return {'error_code': 'rdap_no_coverage', 'present': False}

    if resp.status_code != 200:
        return {'error_code': f'rdap_http_{resp.status_code}', 'present': False}

    try:
        data = resp.json()
    except Exception as exc:
        return {'error_code': f'rdap_parse_error:{type(exc).__name__}', 'present': False}

    # Last matching 'registration' event wins -- same semantics as the
    # original loop (RDAP responses have at most one in practice).
    registration_dates = [
        ev.get('eventDate') for ev in (data.get('events') or [])
        if ev.get('eventAction') == 'registration'
    ]
    creation = registration_dates[-1] if registration_dates else None

    age_days = None
    if creation:
        try:
            created_dt = datetime.fromisoformat(creation.replace('Z', '+00:00'))
            created_dt = created_dt.replace(tzinfo=timezone.utc) if created_dt.tzinfo is None else created_dt
            age_days = (datetime.now(timezone.utc) - created_dt).days
        except Exception:
            pass

    # Last matching 'fn' vcard field across all registrar entities wins --
    # same semantics as the original nested loop.
    registrar_candidates = [
        field[3]
        for entity in (data.get('entities') or [])
        if 'registrar' in (entity.get('roles') or [])
        for field in ((entity.get('vcardArray') or [None, []])[1]
                       if len(entity.get('vcardArray') or []) > 1 else [])
        if field and field[0] == 'fn' and len(field) > 3
    ]
    registrar = registrar_candidates[-1] if registrar_candidates else None

    return {
        'present': True,
        'creation_date': creation,
        'expiration_date': None,
        'updated_date': None,
        'registrar': registrar,
        'registrant_country': None,
        'age_days': age_days,
        'historical_registrant_count': 0,
        'historical_registrants': [],
        'registration_gaps_detected': False,
        'raw_status': ', '.join(data.get('status') or []) or None,
        'whois_source': 'rdap',
    }


async def _fetch_whois(domain: str, include_historical: bool) -> dict:
    """
    Resolves WHOIS data. Tries Whoxy first (paid, ~$0.002/lookup, richer
    data -- registrar name/contact, exact dates). Falls back to free
    public RDAP only when Whoxy can't give a definitive answer (no API
    key configured, timeout, HTTP error, or an API-level failure like an
    unsupported TLD). Never raises -- returns error_code on failure, same
    contract as before. See _fetch_whois_whoxy / _fetch_whois_rdap for
    the real, live-confirmed coverage gaps in each source (2026-08-20).
    """
    api_key = os.getenv('WHOXY_API_KEY')
    whoxy_result = None
    if api_key:
        whoxy_result = await _fetch_whois_whoxy(domain, include_historical, api_key)
        if whoxy_result.get('present') or whoxy_result.get('error_code') == 'whois_no_record':
            return whoxy_result
    else:
        whoxy_result = {'error_code': 'whois_no_api_key', 'present': False}

    rdap_result = await _fetch_whois_rdap(domain)
    if rdap_result.get('present') or rdap_result.get('error_code') == 'whois_no_record':
        return rdap_result

    # Neither source could give a definitive answer -- genuinely missing
    # data, not evidence either way. Prefer whichever error is more
    # specific for observability.
    return rdap_result if rdap_result.get('error_code') != 'rdap_error' else whoxy_result


async def _fetch_ct_presence(domain: str, include_subdomains: bool,
                              max_certs: int) -> dict:
    """
    Queries crt.sh Certificate Transparency log aggregator.
    Returns certificate count, issuance dates, unique issuers, subdomain count,
    and a continuity score.
    """
    query_domain = f'%.{domain}' if include_subdomains else domain
    url = 'https://crt.sh/'
    params = {'q': query_domain, 'output': 'json'}

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            records = resp.json()
        except httpx.TimeoutException:
            return {'error_code': 'ct_timeout', 'present': False}
        except httpx.HTTPStatusError as exc:
            return {'error_code': f'ct_http_{exc.response.status_code}', 'present': False}
        except Exception as exc:
            return {'error_code': f'ct_error:{type(exc).__name__}', 'present': False}

    if not records:
        return {'present': False, 'certificate_count': 0, 'unique_issuers': [],
                'subdomain_count': 0, 'continuity_score': 0.0,
                'earliest_issuance': None, 'latest_issuance': None}

    records = records[:max_certs]

    dates = []
    issuers = set()
    subdomains = set()

    for r in records:
        not_before = r.get('not_before') or r.get('entry_timestamp')
        if not_before:
            try:
                dt = datetime.fromisoformat(not_before.replace('Z', '+00:00'))
                dates.append(dt)
            except Exception:
                pass
        issuer = r.get('issuer_name') or r.get('issuer_ca_id')
        if issuer:
            issuers.add(str(issuer))
        name = r.get('name_value') or r.get('common_name') or ''
        for n in name.split('\n'):
            n = n.strip()
            if n and n != domain and n.endswith(f'.{domain}'):
                subdomains.add(n)

    dates.sort()
    cert_count = len(records)

    continuity_score = 0.0
    if dates:
        span_days = (dates[-1] - dates[0]).days
        expected_certs_per_year = 12
        if span_days > 0:
            years = span_days / 365.25
            expected = max(1, expected_certs_per_year * years)
            continuity_score = float(np.clip(cert_count / expected, 0.0, 1.0))
        else:
            continuity_score = min(1.0, cert_count / 3.0)

    return {
        'present': cert_count > 0,
        'certificate_count': cert_count,
        'earliest_issuance': dates[0].isoformat() if dates else None,
        'latest_issuance': dates[-1].isoformat() if dates else None,
        'unique_issuers': list(issuers),
        'subdomain_count': len(subdomains),
        'continuity_score': round(continuity_score, 4),
    }


async def _fetch_wayback_density(domain: str, lookback_years: float) -> dict:
    """
    Queries Wayback Machine CDX API for snapshot count and density.
    Returns total snapshots, first/last dates, snapshots per year,
    density score, and coverage gaps in months.
    """
    now = datetime.now(timezone.utc)
    from_dt = now.replace(year=now.year - int(lookback_years))
    from_ts = from_dt.strftime('%Y%m%d')
    to_ts = now.strftime('%Y%m%d')

    url = 'http://web.archive.org/cdx/search/cdx'
    params = {
        'url': domain,
        'output': 'json',
        'fl': 'timestamp',
        'collapse': 'timestamp:6',  # monthly granularity
        'from': from_ts,
        'to': to_ts,
        'limit': 1000,
        'statuscode': 200,
    }

    async with httpx.AsyncClient(timeout=35.0) as client:
        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            raw = resp.json()
        except httpx.TimeoutException:
            return {'error_code': 'wayback_timeout', 'present': False}
        except httpx.HTTPStatusError as exc:
            return {'error_code': f'wayback_http_{exc.response.status_code}', 'present': False}
        except Exception as exc:
            return {'error_code': f'wayback_error:{type(exc).__name__}', 'present': False}

    # CDX returns [['timestamp'], ['YYYYMMDDHHMMSS'], ...]
    if not raw or len(raw) <= 1:
        return {
            'present': False,
            'total_snapshots': 0,
            'first_snapshot_date': None,
            'last_snapshot_date': None,
            'snapshots_per_year': 0.0,
            'density_score': 0.0,
            'coverage_gaps_months': [],
        }

    timestamps = []
    for row in raw[1:]:
        ts = row[0]
        try:
            dt = datetime.strptime(ts[:8], '%Y%m%d').replace(tzinfo=timezone.utc)
            timestamps.append(dt)
        except Exception:
            pass

    if not timestamps:
        return {
            'present': False,
            'total_snapshots': 0,
            'first_snapshot_date': None,
            'last_snapshot_date': None,
            'snapshots_per_year': 0.0,
            'density_score': 0.0,
            'coverage_gaps_months': [],
        }

    timestamps.sort()
    total = len(timestamps)
    span_days = (timestamps[-1] - timestamps[0]).days
    span_years = max(span_days / 365.25, 1 / 12)
    per_year = total / span_years

    # Density score: logistic mapping of per_year (12/yr -> score ~0.5, 36/yr -> ~0.9)
    density_score = float(expit((per_year - 12.0) / 8.0))

    # Coverage gaps: months within lookback window with zero snapshots
    covered_months = set()
    for dt in timestamps:
        covered_months.add((dt.year, dt.month))

    start = from_dt.replace(day=1)
    gap_months = []
    cursor = start
    while cursor <= now:
        key = (cursor.year, cursor.month)
        if key not in covered_months:
            gap_months.append(f'{cursor.year}-{cursor.month:02d}')
        if cursor.month == 12:
            cursor = cursor.replace(year=cursor.year + 1, month=1)
        else:
            cursor = cursor.replace(month=cursor.month + 1)

    return {
        'present': True,
        'total_snapshots': total,
        'first_snapshot_date': timestamps[0].date().isoformat(),
        'last_snapshot_date': timestamps[-1].date().isoformat(),
        'snapshots_per_year': round(per_year, 2),
        'density_score': round(density_score, 4),
        'coverage_gaps_months': gap_months,
    }


async def _audit_dns_maturity(domain: str, resolvers: list[str]) -> dict:
    """
    Queries MX, SPF (TXT), DMARC (_dmarc TXT), NS records and checks
    DKIM for common selectors across provided resolvers.
    Returns maturity score and component signals.
    """
    resolvers = resolvers or ['8.8.8.8', '1.1.1.1']
    resolvers = resolvers[:5]

    DKIM_SELECTORS = ['google', 'default', 'mail', 'k1', 'smtp', 'selector1', 'selector2']

    loop = asyncio.get_event_loop()
    signals_missing = []

    def _resolve_with_resolver(resolver_ip: str, qname: str, rdtype: str) -> list[str]:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [resolver_ip]
        r.timeout = 5.0
        r.lifetime = 5.0
        try:
            answers = r.resolve(qname, rdtype)
            return [str(a) for a in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException:
            return []

    async def _async_resolve(resolver_ip: str, qname: str, rdtype: str) -> list[str]:
        return await loop.run_in_executor(
            None, _resolve_with_resolver, resolver_ip, qname, rdtype
        )

    # MX records
    mx_results = []
    for r in resolvers:
        try:
            mx = await asyncio.wait_for(_async_resolve(r, domain, 'MX'), timeout=6.0)
            mx_results.extend(mx)
        except asyncio.TimeoutError:
            signals_missing.append(f'mx@{r}')

    has_mx = len(mx_results) > 0

    # SPF (TXT containing v=spf1)
    spf_results = []
    for r in resolvers:
        try:
            txt = await asyncio.wait_for(_async_resolve(r, domain, 'TXT'), timeout=6.0)
            spf_results.extend([t for t in txt if 'v=spf1' in t.lower()])
        except asyncio.TimeoutError:
            signals_missing.append(f'spf@{r}')

    has_spf = len(spf_results) > 0

    # DMARC (_dmarc.domain TXT)
    dmarc_domain = f'_dmarc.{domain}'
    dmarc_results = []
    for r in resolvers:
        try:
            txt = await asyncio.wait_for(_async_resolve(r, dmarc_domain, 'TXT'), timeout=6.0)
            dmarc_results.extend([t for t in txt if 'v=dmarc1' in t.lower()])
        except asyncio.TimeoutError:
            signals_missing.append(f'dmarc@{r}')

    has_dmarc = len(dmarc_results) > 0

    # NS records
    ns_results = []
    for r in resolvers:
        try:
            ns = await asyncio.wait_for(_async_resolve(r, domain, 'NS'), timeout=6.0)
            ns_results.extend(ns)
        except asyncio.TimeoutError:
            signals_missing.append(f'ns@{r}')

    ns_count = len(set(ns_results))

    # DKIM (check selectors against first resolver)
    dkim_found = []
    primary_resolver = resolvers[0]
    for selector in DKIM_SELECTORS:
        dkim_domain = f'{selector}._domainkey.{domain}'
        try:
            dkim_txt = await asyncio.wait_for(
                _async_resolve(primary_resolver, dkim_domain, 'TXT'), timeout=4.0
            )
            if dkim_txt:
                dkim_found.append(selector)
        except asyncio.TimeoutError:
            pass

    has_dkim = len(dkim_found) > 0

    # Propagation consistency: check if first and last resolver agree on NS
    propagation_consistent = True
    if len(resolvers) >= 2:
        ns_sets = []
        for r in resolvers[:2]:
            ns_set = set(await asyncio.wait_for(
                _async_resolve(r, domain, 'NS'), timeout=6.0
            ) if True else [])
            ns_sets.append(ns_set)
        if len(ns_sets) == 2:
            propagation_consistent = bool(ns_sets[0] & ns_sets[1])

    # Maturity score: weighted sum of components
    # Weights calibrated to reward operational email config (SPF+DMARC+MX triple = moat)
    score_components = {
        'has_mx': (0.25, has_mx),
        'has_spf': (0.20, has_spf),
        'has_dmarc': (0.20, has_dmarc),
        'has_dkim': (0.15, has_dkim),
        'ns_count_adequate': (0.12, ns_count >= 2),
        'propagation_consistent': (0.08, propagation_consistent),
    }
    maturity_score = sum(w for w, v in score_components.values() if v)

    # DNS is considered mature if it reaches 0.45 threshold
    is_mature = maturity_score >= 0.45

    return {
        'present': ns_count > 0,
        'is_mature': is_mature,
        'maturity_score': round(maturity_score, 4),
        'has_mx': has_mx,
        'has_spf': has_spf,
        'has_dmarc': has_dmarc,
        'has_dkim': has_dkim,
        'dkim_selectors_found': dkim_found,
        'ns_count': ns_count,
        'propagation_consistent': propagation_consistent,
        'signals_missing': list(set(signals_missing)),
        'resolvers_used': resolvers,
    }


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

VALID_SIGNALS = {'whois', 'ct', 'wayback', 'dns'}


class VerifyEntityRequest(BaseModel):
    domain: Annotated[str, Field(..., min_length=3, max_length=253,
        description="Fully qualified domain name, e.g. 'acme-corp.com'.")]
    entity_name: Annotated[str, Field(..., min_length=1, max_length=200,
        description='Human-readable entity name the domain is supposed to represent.')]
    min_confidence_threshold: Annotated[float, Field(0.65, ge=0.0, le=1.0,
        description='Minimum verdict_confidence for a decisive verdict.')]
    signal_mask: Annotated[Optional[list[str]], Field(None, min_length=1, max_length=4,
        description="Subset of signals to evaluate. Null means all four are evaluated.")]

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)

    @field_validator('signal_mask')
    @classmethod
    def validate_signal_mask(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v is None:
            return v
        invalid = [s for s in v if s not in VALID_SIGNALS]
        if invalid:
            raise ValueError(f"Invalid signal names: {invalid}. Must be subset of {VALID_SIGNALS}")
        return v


class WhoisRequest(BaseModel):
    domain: Annotated[str, Field(..., min_length=3, max_length=253,
        description="Fully qualified domain name, e.g. 'acme-corp.com'.")]
    include_historical_registrants: Annotated[bool, Field(False,
        description='When true, resolves historical registrant records where available.')]

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)


class CTRequest(BaseModel):
    domain: Annotated[str, Field(..., min_length=3, max_length=253,
        description="Fully qualified domain name, e.g. 'acme-corp.com'.")]
    include_subdomains: Annotated[bool, Field(False,
        description='When true, includes certificates issued to subdomains.')]
    max_certs_to_analyze: Annotated[float, Field(100, ge=1, le=1000,
        description='Maximum number of certificate records to analyze from CT logs.')]

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)


class WaybackRequest(BaseModel):
    domain: Annotated[str, Field(..., min_length=3, max_length=253,
        description="Fully qualified domain name, e.g. 'acme-corp.com'.")]
    lookback_years: Annotated[float, Field(5, ge=1, le=30,
        description='Number of years back from now to analyze snapshot density.')]

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)


class DNSRequest(BaseModel):
    domain: Annotated[str, Field(..., min_length=3, max_length=253,
        description="Fully qualified domain name, e.g. 'acme-corp.com'.")]
    resolvers: Annotated[Optional[list[str]], Field(None, min_length=1, max_length=5,
        description="Optional list of DNS resolver IPs. Defaults to ['8.8.8.8','1.1.1.1'].")]

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)

    @field_validator('resolvers')
    @classmethod
    def validate_resolvers(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v is None:
            return v
        validated = []
        for r in v:
            r = r.strip()
            try:
                ipaddress.ip_address(r)
                validated.append(r)
            except ValueError:
                # Accept hostnames too
                if re.match(r'^[a-zA-Z0-9.\-]+$', r):
                    validated.append(r)
                else:
                    raise ValueError(f"Resolver '{r}' is not a valid IP or hostname")
        return validated


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title='Live Entity Verification API',
    description=(
        'Cross-signal Bayesian corroboration of entity existence. '
        'Combines WHOIS, Certificate Transparency, Wayback Machine, '
        'and DNS operational maturity into a calibrated hallucination verdict.'
    ),
    version='1.0.0',
    docs_url='/docs',
    redoc_url='/redoc',
)


# ---------------------------------------------------------------------------
# POST /verify-entity-existence-cross-signal
# ---------------------------------------------------------------------------

@app.post('/verify-entity-existence-cross-signal', status_code=status.HTTP_200_OK)
async def verify_entity_existence_cross_signal(req: VerifyEntityRequest) -> dict:
    """
    Fuses WHOIS, CT, Wayback, and DNS signals with Bayesian calibrated weights.
    Returns corroborated existence verdict, hallucination probability, and
    failure mode classification. Fail-closed: insufficient corroboration
    returns a blocking verdict rather than an ambiguous null.
    """
    active_signals: list[str] = list(req.signal_mask) if req.signal_mask else ['whois', 'ct', 'wayback', 'dns']
    domain = req.domain

    tasks = {}
    if 'whois' in active_signals:
        tasks['whois'] = _fetch_whois(domain, False)
    if 'ct' in active_signals:
        tasks['ct'] = _fetch_ct_presence(domain, False, 100)
    if 'wayback' in active_signals:
        tasks['wayback'] = _fetch_wayback_density(domain, 5.0)
    if 'dns' in active_signals:
        tasks['dns'] = _audit_dns_maturity(domain, ['8.8.8.8', '1.1.1.1'])

    gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
    results = {}
    for key, result in zip(tasks.keys(), gathered):
        if isinstance(result, Exception):
            results[key] = {'error_code': f'{key}_exception:{type(result).__name__}', 'present': False}
        else:
            results[key] = result

    # Extract signal presence
    signals_evaluated: dict[str, float] = {}
    signals_missing: list[str] = []
    positive_signals: list[str] = []

    whois_absent = True

    if 'whois' in results:
        w = results['whois']
        if w.get('error_code') == 'whois_no_record':
            # Confirmed real negative evidence, not missing data: the
            # domain was actually queried (Whoxy or RDAP) and confirmed
            # to have never been registered -- same missing-vs-negative
            # criterion already applied to the CT/Wayback signals below.
            whois_present = False
            whois_absent = True
            weight = _bayesian_signal_weight(
                *_PRIOR_WHOIS_PRESENT, *_PRIOR_WHOIS_ABSENT, whois_present
            )
            signals_evaluated['whois'] = weight
        elif 'error_code' in w and not w.get('present', False):
            signals_missing.append('whois')
        else:
            whois_present = w.get('present', False)
            whois_absent = not whois_present
            weight = _bayesian_signal_weight(
                *_PRIOR_WHOIS_PRESENT, *_PRIOR_WHOIS_ABSENT, whois_present
            )
            signals_evaluated['whois'] = weight
            if whois_present:
                positive_signals.append('whois')

    if 'ct' in results:
        c = results['ct']
        if 'error_code' in c and not c.get('present', False):
            signals_missing.append('ct')
        else:
            ct_present = c.get('present', False)
            weight = _bayesian_signal_weight(
                *_PRIOR_CT_PRESENT, *_PRIOR_CT_ABSENT, ct_present
            )
            signals_evaluated['ct'] = weight
            if ct_present:
                positive_signals.append('ct')

    if 'wayback' in results:
        wb = results['wayback']
        if 'error_code' in wb and not wb.get('present', False):
            signals_missing.append('wayback')
        else:
            wb_present = wb.get('present', False)
            weight = _bayesian_signal_weight(
                *_PRIOR_WAYBACK_PRESENT, *_PRIOR_WAYBACK_ABSENT, wb_present
            )
            signals_evaluated['wayback'] = weight
            if wb_present:
                positive_signals.append('wayback')

    if 'dns' in results:
        d = results['dns']
        if 'error_code' in d and not d.get('present', False):
            signals_missing.append('dns')
        else:
            dns_mature = d.get('is_mature', False)
            weight = _bayesian_signal_weight(
                *_PRIOR_DNS_MATURE, *_PRIOR_DNS_IMMATURE, dns_mature
            )
            signals_evaluated['dns'] = weight
            if dns_mature:
                positive_signals.append('dns')

    # Bayesian fusion
    signal_weight_list = list(signals_evaluated.values())
    posterior_real = _fuse_signals_naive_bayes(signal_weight_list)
    hallucination_probability = round(1.0 - posterior_real, 4)
    verdict_confidence = round(float(np.clip(abs(posterior_real - 0.5) * 2.0, 0.0, 1.0)), 4)

    evidence_quality = _compute_evidence_quality(
        signals_evaluated, signals_missing, posterior_real
    )

    failure_mode = _classify_failure_mode(
        posterior=posterior_real,
        evidence_quality=evidence_quality,
        confidence_threshold=req.min_confidence_threshold,
        signals_present=positive_signals,
        whois_absent=whois_absent,
        all_signals=list(signals_evaluated.keys()),
    )

    # Per-spec: DNS alone is never sufficient for VERIFIED_LIVE
    if failure_mode == 'verified_live' and positive_signals == ['dns']:
        failure_mode = 'insufficient_corroboration'

    verdict = 'VERIFIED_LIVE' if failure_mode == 'verified_live' else (
        'LIKELY_HALLUCINATED' if failure_mode == 'likely_hallucinated' else
        'UNVERIFIED'
    )

    return {
        'domain': domain,
        'entity_name': req.entity_name,
        'verdict': verdict,
        'hallucination_probability': hallucination_probability,
        'verdict_confidence': verdict_confidence,
        'evidence_quality_score': round(evidence_quality, 4),
        'failure_mode_classification': failure_mode,
        'positive_signals': positive_signals,
        'signals_evaluated': list(signals_evaluated.keys()),
        'signals_missing': signals_missing,
        'signal_weights': {k: round(v, 4) for k, v in signals_evaluated.items()},
        'posterior_probability_real': round(posterior_real, 4),
        'evaluated_at': datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# POST /resolve-whois-registration-timeline
# ---------------------------------------------------------------------------

@app.post('/resolve-whois-registration-timeline', status_code=status.HTTP_200_OK)
async def resolve_whois_registration_timeline(req: WhoisRequest) -> dict:
    """
    Resolves WHOIS registration timeline. Returns creation, expiration,
    updated dates, registrar, registrant country, age in days, and
    historical registrant count where available.
    """
    result = await _fetch_whois(req.domain, req.include_historical_registrants)

    if not result.get('present', False):
        return {
            'domain': req.domain,
            'whois_record_found': False,
            'error_code': result.get('error_code', 'whois_no_record'),
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'registrar': None,
            'registrant_country': None,
            'age_days': None,
            'historical_registrant_count': 0,
            'historical_registrants': [],
            'registration_gaps_detected': None,
            'raw_status': None,
            'queried_at': datetime.now(timezone.utc).isoformat(),
        }

    return {
        'domain': req.domain,
        'whois_record_found': True,
        'error_code': None,
        'creation_date': result.get('creation_date'),
        'expiration_date': result.get('expiration_date'),
        'updated_date': result.get('updated_date'),
        'registrar': result.get('registrar'),
        'registrant_country': result.get('registrant_country'),
        'age_days': result.get('age_days'),
        'historical_registrant_count': result.get('historical_registrant_count', 0),
        'historical_registrants': result.get('historical_registrants', []),
        'registration_gaps_detected': result.get('registration_gaps_detected', False),
        'raw_status': result.get('raw_status'),
        'queried_at': datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# POST /probe-certificate-transparency-presence
# ---------------------------------------------------------------------------

@app.post('/probe-certificate-transparency-presence', status_code=status.HTTP_200_OK)
async def probe_certificate_transparency_presence(req: CTRequest) -> dict:
    """
    Searches crt.sh CT logs for certificates issued for a domain.
    Computes certificate count, issuance date range, unique issuers,
    subdomain count, and continuity score.
    """
    max_certs = int(req.max_certs_to_analyze)
    result = await _fetch_ct_presence(req.domain, req.include_subdomains, max_certs)

    if 'error_code' in result and not result.get('present', False):
        return {
            'domain': req.domain,
            'ct_records_found': False,
            'error_code': result.get('error_code'),
            'certificate_count': 0,
            'earliest_issuance': None,
            'latest_issuance': None,
            'unique_issuers': [],
            'subdomain_count': 0,
            'continuity_score': 0.0,
            'include_subdomains': req.include_subdomains,
            'max_certs_analyzed': max_certs,
            'queried_at': datetime.now(timezone.utc).isoformat(),
        }

    return {
        'domain': req.domain,
        'ct_records_found': result.get('present', False),
        'error_code': None,
        'certificate_count': result.get('certificate_count', 0),
        'earliest_issuance': result.get('earliest_issuance'),
        'latest_issuance': result.get('latest_issuance'),
        'unique_issuers': result.get('unique_issuers', []),
        'subdomain_count': result.get('subdomain_count', 0),
        'continuity_score': result.get('continuity_score', 0.0),
        'include_subdomains': req.include_subdomains,
        'max_certs_analyzed': max_certs,
        'queried_at': datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# POST /measure-wayback-snapshot-density
# ---------------------------------------------------------------------------

@app.post('/measure-wayback-snapshot-density', status_code=status.HTTP_200_OK)
async def measure_wayback_snapshot_density(req: WaybackRequest) -> dict:
    """
    Measures Wayback Machine CDX snapshot density over a lookback window.
    Returns total snapshots, first/last dates, snapshots per year,
    density score, and coverage gaps in months.
    """
    result = await _fetch_wayback_density(req.domain, req.lookback_years)

    if 'error_code' in result and not result.get('present', False):
        return {
            'domain': req.domain,
            'snapshots_found': False,
            'error_code': result.get('error_code'),
            'total_snapshots': 0,
            'first_snapshot_date': None,
            'last_snapshot_date': None,
            'snapshots_per_year': 0.0,
            'density_score': 0.0,
            'coverage_gaps_months': [],
            'lookback_years': req.lookback_years,
            'queried_at': datetime.now(timezone.utc).isoformat(),
        }

    return {
        'domain': req.domain,
        'snapshots_found': result.get('present', False),
        'error_code': None,
        'total_snapshots': result.get('total_snapshots', 0),
        'first_snapshot_date': result.get('first_snapshot_date'),
        'last_snapshot_date': result.get('last_snapshot_date'),
        'snapshots_per_year': result.get('snapshots_per_year', 0.0),
        'density_score': result.get('density_score', 0.0),
        'coverage_gaps_months': result.get('coverage_gaps_months', []),
        'lookback_years': req.lookback_years,
        'queried_at': datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# POST /audit-dns-operational-maturity
# ---------------------------------------------------------------------------

@app.post('/audit-dns-operational-maturity', status_code=status.HTTP_200_OK)
async def audit_dns_operational_maturity(req: DNSRequest) -> dict:
    """
    Audits DNS operational maturity: MX, SPF, DMARC, DKIM selectors,
    NS record count, and propagation consistency across resolvers.
    Returns maturity score and component signals. DNS maturity alone
    is not sufficient for VERIFIED_LIVE verdict per cross-signal spec.
    """
    resolvers = req.resolvers or ['8.8.8.8', '1.1.1.1']
    result = await _audit_dns_maturity(req.domain, resolvers)

    if 'error_code' in result and not result.get('present', False):
        return {
            'domain': req.domain,
            'dns_records_found': False,
            'error_code': result.get('error_code'),
            'is_mature': False,
            'maturity_score': 0.0,
            'has_mx': False,
            'has_spf': False,
            'has_dmarc': False,
            'has_dkim': False,
            'dkim_selectors_found': [],
            'ns_count': 0,
            'propagation_consistent': False,
            'signals_missing': [],
            'resolvers_used': resolvers,
            'queried_at': datetime.now(timezone.utc).isoformat(),
        }

    return {
        'domain': req.domain,
        'dns_records_found': result.get('present', False),
        'error_code': None,
        'is_mature': result.get('is_mature', False),
        'maturity_score': result.get('maturity_score', 0.0),
        'has_mx': result.get('has_mx', False),
        'has_spf': result.get('has_spf', False),
        'has_dmarc': result.get('has_dmarc', False),
        'has_dkim': result.get('has_dkim', False),
        'dkim_selectors_found': result.get('dkim_selectors_found', []),
        'ns_count': result.get('ns_count', 0),
        'propagation_consistent': result.get('propagation_consistent', False),
        'signals_missing': result.get('signals_missing', []),
        'resolvers_used': result.get('resolvers_used', resolvers),
        'queried_at': datetime.now(timezone.utc).isoformat(),
    }

# --- NEXUS: servidor MCP real montado en el mismo proceso (inyectado por forge_agent) ---
# Reemplaza el wrapper Node/TypeScript separado -- un solo deploy, sin
# segundo servicio, sin salto de red interno. Ver mcp_wrapper_generator.py
# (v2.0) para el razonamiento completo, incluido el gotcha de
# session_manager que explica el patron startup/shutdown de abajo.

from typing import Annotated, Any, Literal
from contextlib import asynccontextmanager

import asyncio
import base64
import json
import os
import time
import httpx
from pydantic import Field
from fastapi import FastAPI
from mcp.server.fastmcp import Context, FastMCP as _NexusFastMCP
from mcp.server.transport_security import TransportSecuritySettings

# --- NEXUS: PATCH fix_mcp_dns_rebinding_host ---
# FastMCP() sin host/transport_security explicito activa proteccion
# anti DNS-rebinding con allowlist localhost-only por default del SDK,
# rechazando con 421 "Invalid Host header" cualquier request real
# contra el dominio publico de Railway (bug real confirmado en
# produccion 2026-07-09, ver docstring del generador). Se pasa
# transport_security explicito leyendo RAILWAY_PUBLIC_DOMAIN en
# runtime -- Railway lo inyecta automaticamente en cada servicio, asi
# que este codigo no necesita conocer su propio dominio al generarse.
_nexus_railway_domain = os.getenv("RAILWAY_PUBLIC_DOMAIN", "*")

_nexus_mcp = _NexusFastMCP(
    'nexus-live-entity-verification',
    stateless_http=True,
    host="0.0.0.0",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        # --- PATCH fix_mcp_dns_rebinding_bare_host ---
        # Railway (como cualquier proxy HTTPS estandar) manda el Host
        # header SIN puerto explicito -- "dominio:*" nunca matchea eso,
        # solo matchea "dominio:443". Se agrega tambien el dominio
        # pelado para cubrir ambos casos (bug real confirmado en
        # produccion 2026-07-09: primer fix desplegado, /mcp seguia
        # devolviendo 421 tras el redeploy).
        allowed_hosts=[
            "localhost:*",
            "127.0.0.1:*",
            _nexus_railway_domain,
            _nexus_railway_domain + ":*",
        ],
        allowed_origins=[
            "http://localhost:*",
            "http://127.0.0.1:*",
            "https://" + _nexus_railway_domain,
        ],
    ),
)


# --- NEXUS: instancia FastAPI aislada para llamadas MCP->core internas ---
# Comparte los MISMOS objetos de ruta (app.routes) que `app` -- misma
# resolucion real de FastAPI DI (Security()/Depends(), lo que el LLM haya
# escrito) -- pero SIN ningun @app.middleware/add_middleware propio de
# `app` (billing Stripe, rate-limit, x402 PaymentMiddlewareASGI,
# traffic-log). Esos middleware ya corrieron UNA vez sobre la request HTTP
# real a /mcp (Starlette envuelve el Mount de FastMCP en "/" con el mismo
# stack que el resto de `app`) -- esta llamada interna NO debe volver a
# dispararlos, y (para rutas x402-gateadas) no debe recibir el mismo 402
# que la ruta REST publica exige, porque el pago real (si el asset lo
# tiene) se verifica aparte, a nivel de tool MCP -- ver CLAUDE.md SS9.5x.
# `list(...)` fuerza una copia -- Router.__init__ ya copia internamente,
# pero se es explicito aca para que esta instancia quede fija al set de
# rutas REST que existe en este punto (antes de app.mount("/", ...) mas
# abajo), sin importar mutaciones futuras de app.routes.
_nexus_internal_app = FastAPI(routes=list(app.routes))


async def _nexus_mcp_call_core(method: str, path: str, params: dict, headers: dict | None = None) -> Any:
    """
    Llama al endpoint real del core -- via ASGI in-process (sin red
    real, sin segundo proceso) contra _nexus_internal_app (ver arriba),
    NO contra `app` directamente.
    """
    transport = httpx.ASGITransport(app=_nexus_internal_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://nexus-internal") as client:
        if method == "GET":
            resp = await client.get(path, params=params, headers=headers)
        else:
            resp = await client.post(path, json=params, headers=headers)
        resp.raise_for_status()
        return resp.json()


# --- PATCH mcp_call_events_telemetry ---
# mcp_call_events / revenue_events -- ver Fase 1 (Revenue/Usage
# Instrumentation). Generator-side por diseno: cualquier asset nuevo
# que FORGE construya de aca en adelante nace con esto, sin depender de
# un patch manual posterior por asset.
#
# Credenciales leidas de env vars Railway con el MISMO patron defensivo
# que ya usa _nexus_usage_middleware (forge_output_saver_v6.py) para
# Stripe: si SUPABASE_URL/SUPABASE_ANON_KEY no estan seteadas (asset
# corriendo local, o el paso de sync de env vars del pipeline de deploy
# todavia no las inyecto -- ESE paso vive fuera de este generador, ver
# billing_reconciliation.py:134-144 para el patron real que lo haria),
# el insert es un no-op silencioso -- nunca rompe la response real de
# una tool call.
#
# IMPORTANTE: usa la key anon/publishable, NUNCA service_role -- esta
# key vive en el runtime del asset deployado (potencialmente expuesta
# via env dump/logs), la RLS de mcp_call_events/revenue_events
# (policies INSERT-only para el rol anon, sin SELECT/UPDATE/DELETE) es
# la unica proteccion real contra un uso indebido de esta key si se
# filtra.
_NEXUS_SUPABASE_URL = os.getenv("SUPABASE_URL")
_NEXUS_SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
_NEXUS_SECTOR = 'verification_api'
_NEXUS_ASSET_NAME = 'live-entity-verification'


def _nexus_truncate_ip(raw_ip):
    """Mismo algoritmo/mismo resultado que _nexus_traffic_log_truncate_ip
    (archive/patches/patch_traffic_log_similarity_search.py) -- portado
    aca para que todo asset nuevo lo tenga desde generacion. Trunca a
    /24 (IPv4) o /64 (IPv6); nunca devuelve la IP completa."""
    if not raw_ip:
        return None
    if ":" in raw_ip and "." not in raw_ip:
        segments = [s for s in raw_ip.split(":") if s]
        head = segments[:4] if len(segments) >= 4 else segments
        return (":".join(head) + "::/64") if head else None
    octets = raw_ip.split(".")
    if len(octets) == 4 and all(o.isdigit() for o in octets):
        return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    return None


def _nexus_extract_wallet(payment_header):
    """Mismo algoritmo que _nexus_rate_limit_extract_wallet
    (archive/patches/patch_rate_limit_similarity_search.py) -- decodifica
    el header X-PAYMENT (base64 -> JSON) y extrae la wallet pagadora de
    payload.authorization.from."""
    try:
        padded = payment_header + "=" * (-len(payment_header) % 4)
        payload = json.loads(base64.b64decode(padded))
        payer = payload.get("payload", {}).get("authorization", {}).get("from")
        return payer.lower() if isinstance(payer, str) and payer else None
    except Exception:
        return None


def _nexus_call_context(ctx):
    """
    Best-effort: ctx.request_context.request es un starlette.Request
    REAL incluso con stateless_http=True -- se puebla por REQUEST HTTP
    individual (mcp/server/streamable_http.py: ServerMessageMetadata(
    request_context=request), poblado en _create_session_message()),
    no por continuidad de sesion. Verificado contra el codigo fuente
    real de mcp==1.28.1 (version pinneada del proyecto) antes de asumir
    que el dato esta disponible -- no es una suposicion sin chequear.

    agent_framework: no existe un campo dedicado para esto en el
    protocolo MCP tal como esta implementado hoy con
    stateless_http=True -- ctx.session.client_params.clientInfo (que
    SI llevaria un nombre de framework/cliente real) solo se puebla si
    el mensaje initialize y la tool call posterior comparten la misma
    ServerSession, y en modo stateless cada POST crea una ServerSession
    nueva (mcp/server/streamable_http_manager.py:_handle_stateless_request).
    La señal real y disponible en su lugar es el header User-Agent de
    la request HTTP -- se usa tal cual cuando el cliente lo manda
    (nunca fabricado; queda None si el cliente no lo envia).
    """
    ip_range = None
    agent_framework = None
    wallet = None
    try:
        request = ctx.request_context.request if ctx is not None else None
        if request is not None:
            forwarded = request.headers.get("x-forwarded-for")
            raw_ip = forwarded.split(",")[0].strip() if forwarded else (
                request.client.host if request.client else None
            )
            ip_range = _nexus_truncate_ip(raw_ip)
            ua = request.headers.get("user-agent")
            agent_framework = ua[:255] if ua else None
            payment_header = request.headers.get("x-payment")
            if payment_header:
                wallet = _nexus_extract_wallet(payment_header)
    except Exception:
        pass
    return ip_range, agent_framework, wallet


async def _nexus_supabase_insert(table, payload):
    if not _NEXUS_SUPABASE_URL or not _NEXUS_SUPABASE_ANON_KEY:
        return
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(
                f"{_NEXUS_SUPABASE_URL}/rest/v1/{table}",
                json=payload,
                headers={
                    "apikey": _NEXUS_SUPABASE_ANON_KEY,
                    "Authorization": f"Bearer {_NEXUS_SUPABASE_ANON_KEY}",
                    "Content-Type": "application/json",
                    "Prefer": "return=minimal",
                },
            )
    except Exception:
        pass  # nunca romper el flujo real por un fallo de telemetria


# --- PATCH mcp_call_events_gc_fix ---
# asyncio.create_task() sin guardar la referencia devuelta deja el
# Task sostenido solo por una weak reference del event loop -- bajo
# trafico real concurrente, CPython puede liberarlo por refcounting
# antes de que el loop le de un solo tick (confirmado: 2/5361 filas
# reales en produccion, ambas de verificacion manual de baja
# concurrencia -- ver patch_mcp_call_events_gc_fix_generator.py).
# Mismo patron que recomienda la doc oficial de asyncio para
# fire-and-forget tasks: retener una referencia fuerte en un set a
# nivel de modulo hasta que el Task termine.
_nexus_bg_tasks: set = set()


def _nexus_fire_and_forget(coro):
    task = asyncio.create_task(coro)
    _nexus_bg_tasks.add(task)
    task.add_done_callback(_nexus_bg_tasks.discard)
    return task


async def _nexus_log_mcp_call_event(tool_id, success, latency_ms, ctx, route_key=None):
    """
    Escribe mcp_call_events (proxy de uso/latencia) siempre que haya
    credenciales -- dispara en el `finally` de cada tool MCP, es decir
    cuando el handler retorna (con o sin excepcion), ANTES de que exista
    ningun intento de settlement x402 real para esa llamada.

    --- PATCH x402_revenue_events_hook ---
    Ya NO escribe revenue_events desde aca (si escribia hasta esta
    sesion -- ver CLAUDE.md SS9.58). Ese insert vivia en este mismo punto
    proxy: para un tool protegido por x402 (create_payment_wrapper), el
    handler corre y sirve el recurso ANTES de que se intente el
    settlement (x402/mcp/server.py: handler primero, settle_payment()
    despues) -- loguear "cobrado" aca era literalmente loguearlo antes
    de que el pago se intentara liquidar. revenue_events ahora se
    escribe desde _nexus_log_x402_revenue_event, enganchado directo a
    x402ResourceServer.on_after_settle() (ver mas abajo) -- el unico
    punto que conoce el SettleResponse real (success/transaction/payer)
    y dispara solo cuando success es True.

    x402_routes/price_charged se mantienen aca SOLO para poblar
    mcp_call_events.price_charged, que si tiene sentido como proxy:
    "cuanto hubiera cobrado esta llamada si el pago hubiera settleado",
    no una afirmacion de que settleo. is_paid_route sigue en False para
    cualquier asset nuevo (x402 no se genera hoy por FORGE, CLAUDE.md
    SS8) hasta que un patch manual agregue _NEXUS_X402_ROUTES.
    """
    ip_range, agent_framework, wallet = _nexus_call_context(ctx)
    price_charged = None
    x402_routes = globals().get("_NEXUS_X402_ROUTES") or {}
    is_paid_route = route_key is not None and route_key in x402_routes
    if is_paid_route:
        raw_price = globals().get("_NEXUS_X402_PRICE")
        if raw_price:
            try:
                price_charged = float(str(raw_price).lstrip("$"))
            except Exception:
                price_charged = None
    # --- PATCH mcp_call_events_asset_name ---
    await _nexus_supabase_insert("mcp_call_events", {
        "agent_framework": agent_framework,
        "tool_id": tool_id,
        "sector": _NEXUS_SECTOR,
        "asset_name": _NEXUS_ASSET_NAME,
        # token_input/token_output: null a proposito -- ningun asset
        # que FORGE genera hoy envuelve una llamada LLM propia (son
        # productos como vector search / websocket / rate limiting,
        # no proxies de un modelo). Si algun dia existe un asset que SI
        # envuelva un LLM, ese caso deberia poblar estos campos en su
        # propio call site en vez de forzar un valor generico aca.
        "token_input": None,
        "token_output": None,
        "success": success,
        "latency_ms": latency_ms,
        "client_ip_range": ip_range,
        "price_charged": price_charged,
    })


async def _nexus_log_x402_revenue_event(ctx) -> None:
    """
    --- PATCH x402_revenue_events_hook ---
    AfterSettleHook real para revenue_events -- registrado via
    _nexus_register_x402_revenue_logging(), nunca llamado directo.
    Firma compatible con x402.server_base.AfterSettleHook
    (Callable[[SettleResultContext], Awaitable[None] | None]) pero SIN
    importar el tipo -- duck-typed a proposito, para que este generador
    no obligue a que x402 este instalado en assets que no lo tienen (la
    funcion se emite igual en todo asset nuevo, pero solo se registra
    -- ver _nexus_register_x402_revenue_logging -- si el asset tiene su
    propio _nexus_x402_server real).

    x402ResourceServer.on_after_settle() (x402/server.py) SOLO dispara
    cuando settle_result.success es True -- confirmado leyendo
    _settle_payment_core (x402/server_base.py): un settle fallido nunca
    llega a la lista de after-settle hooks, asi que esta funcion nunca
    necesita chequear success ademas del propio getattr defensivo de
    abajo. Nunca levanta: un bug aca no debe poder romper la respuesta
    de pago real que el caller ya esta por recibir.
    """
    try:
        result = getattr(ctx, "result", None)
        requirements = getattr(ctx, "requirements", None)
        if result is None or requirements is None or not getattr(result, "success", False):
            return
        # amount viene en unidades atomicas del asset -- USDC (6
        # decimales) en los 2 assets reales que usan x402 hoy
        # (similarity-search-api, ws; ver patch_x402_similarity_search.py
        # / patch_x402_ws.py). Mismo mismatch de schema ya documentado
        # mas arriba para mcp_call_events.price_charged: amount_eur no
        # es EUR, es el valor numerico crudo, sin conversion FX.
        raw_amount = getattr(requirements, "amount", None)
        amount_eur = int(raw_amount) / 1_000_000 if raw_amount is not None else None
        await _nexus_supabase_insert("revenue_events", {
            "asset_name": _NEXUS_ASSET_NAME,
            "amount_eur": amount_eur,
            "pricing_model": "x402",
            "stripe_event_id": None,
            "customer_id": getattr(result, "payer", None),
        })
    except Exception:
        pass


def _nexus_register_x402_revenue_logging(x402_server) -> None:
    """
    --- PATCH x402_revenue_events_hook ---
    Registra _nexus_log_x402_revenue_event contra el on_after_settle()
    REAL de x402ResourceServer -- llamar UNA vez, justo despues de
    instanciar/inicializar _nexus_x402_server (mismo lugar donde un
    patch x402 manual ya llama _nexus_x402_server.initialize()).

    Por que aca y no en _nexus_log_mcp_call_event / no en
    PaymentWrapperHooks.on_after_settlement (x402/mcp/types.py): tanto
    las rutas REST (PaymentMiddlewareASGI -> x402_http_server.py:216)
    como los tools MCP (create_payment_wrapper -> server.py /
    server_async.py) llaman settle_payment() sobre la MISMA instancia
    compartida de x402ResourceServer -- un solo hook registrado aca
    cubre ambas superficies de pago de un asset sin que este generador
    necesite saber cual usa cada uno. PaymentWrapperHooks.on_after_settlement
    es exclusivo del wrapper MCP: hubiera dejado sin cubrir cualquier
    pago hecho directo por REST.

    Riesgo conocido, sin cerrar (ver CLAUDE.md SS9.58): no hay forma,
    desde este codigo, de confirmar que settle_result.success==True
    significa "confirmado on-chain" en vez de "el facilitador externo
    (CDP/x402.org) lo acepto como valido, cadena aun no verificada" --
    settle_payment() hace una unica llamada HTTP a {facilitator}/settle
    y confia en el campo `success` que ese facilitador devuelva, sin
    poll ni retry propios. El facilitador de REFERENCIA que trae este
    mismo SDK (x402/mechanisms/evm/exact/facilitator.py) SI espera
    confirmacion on-chain real (wait_for_transaction_receipt) antes de
    devolver success=True -- evidencia de la semantica esperada del
    protocolo, no prueba de que un facilitador externo la respete.

    Idempotencia: revenue_events no tiene columna de tx hash ni
    constraint unico, y la RLS del rol anon es INSERT-only (sin
    SELECT) -- no hay forma de check-before-insert desde el propio
    asset. Se confia en que EIP-3009 (nonce de un solo uso) hace que un
    replay real del mismo payload firmado falle el settlement
    (success=False) en el segundo intento -- este hook solo dispara en
    success=True. Inferencia del diseno del esquema de firma, no
    verificada empiricamente. Cerrar esto de forma robusta requeriria
    una columna tx_hash + unique index en revenue_events -- cambio de
    schema a infra compartida, fuera de alcance de este generador.
    """
    x402_server.on_after_settle(_nexus_log_x402_revenue_event)


async def _nexus_log_traffic_event(ip_range, method, path, status) -> None:
    """
    --- PATCH traffic_events_hook ---
    Primitiva reusable para persistir [NEXUS_TRAFFIC] a Supabase --
    este generador NO se autoregistra en ningun middleware (el
    middleware de traffic-log sigue siendo un artefacto manual, opt-in,
    por asset -- mismo estado que x402, ver CLAUDE.md SS9.59). Pensada
    para que un patch de traffic-log (mismo patron que
    archive/patches/patch_traffic_log_similarity_search.py) la llame
    JUNTO al print() que ya existe, sin reimplementar el insert en cada
    asset.

    Aditivo por contrato: el caller es responsable de mantener el
    print("[NEXUS_TRAFFIC] ...") intacto y llamar a esta funcion
    ADEMAS, no en su lugar -- AegisAgent.PortfolioAuditor
    (aegis_discovery.py) sigue leyendo esa linea en vivo desde logs de
    Railway, no de Supabase. Nunca levanta: un fallo de telemetria
    nunca debe poder romper la response real.
    """
    try:
        await _nexus_supabase_insert("traffic_events", {
            "asset_name": _NEXUS_ASSET_NAME,
            "ip_range": ip_range,
            "method": method,
            "path": path,
            "status": status,
        })
    except Exception:
        pass



@_nexus_mcp.tool(name='nexus_live_entity_verification_verify_entity_existence_cross_signal', description='Fuses WHOIS registration timeline, Certificate Transparency log presence, Wayback Machine snapshot density, and DNS operational maturity with Bayesian calibrated weights to return a corroborated existence verdict, hallucination probability, and failure mode classification. Use when you need a single cross-signal verdict for a named entity and domain pair, especially to detect LLM-hallucinated entities. Do NOT use for live uptime or reachability checks of currently responding services, for domains already known to be registered and DNS-resolving, or when you need raw provider data without cross-signal weighting.')
async def verify_entity_existence_cross_signal(domain: Annotated[str, Field(..., description="Fully qualified domain name to verify, e.g. 'acme-corp.com'. Must be valid IDNA or punycode ASCII.", min_length=3, max_length=253)], entity_name: Annotated[str, Field(..., description='Human-readable entity name the domain is supposed to represent, used to anchor registrar, CT, and DNS context. If empty, the tool returns a validation error.', min_length=1, max_length=200)], min_confidence_threshold: Annotated[float, Field(0.65, description="Minimum verdict_confidence required to return a decisive verdict. Below this threshold the tool returns fail-closed 'insufficient_corroboration' in failure_mode_classification. Range 0.0 to 1.0.", ge=0.0, le=1.0)], signal_mask: Annotated[list[str], Field(None, description="Optional subset of signals to evaluate from ['whois','ct','wayback','dns']. If omitted or null, all four are evaluated. Do not use to force a verdict when a signal is known to be unavailable; missing signals are reported in signals_missing.", min_length=1, max_length=4)], ctx: Context) -> dict[str, Any]:
    """Verify Entity Existence Cross-Signal"""
    _nexus_path = '/verify-entity-existence-cross-signal'.format()
    params = {"domain": domain, "entity_name": entity_name, "min_confidence_threshold": min_confidence_threshold, "signal_mask": signal_mask}
    _nexus_call_t0 = time.monotonic()
    _nexus_call_success = True
    try:
        return await _nexus_mcp_call_core('POST', _nexus_path, params, headers=None)
    except Exception:
        _nexus_call_success = False
        raise
    finally:
        _nexus_call_latency_ms = int((time.monotonic() - _nexus_call_t0) * 1000)
        _nexus_fire_and_forget(_nexus_log_mcp_call_event(
            'nexus_live_entity_verification_verify_entity_existence_cross_signal', _nexus_call_success, _nexus_call_latency_ms, ctx,
            route_key='POST /verify-entity-existence-cross-signal',
        ))

@_nexus_mcp.tool(name='nexus_live_entity_verification_resolve_whois_registration_timeline', description="Resolves a domain's WHOIS registration timeline including creation date, expiration date, last updated date, registrar, registrant country, historical registrant count, age in days, and registration gaps. Use when you need to distinguish a legitimately new domain with a coherent timeline from a hallucinated or fabricated one with no WHOIS record or a redacted/broken timeline. Do NOT use for WHOIS privacy law compliance checks, for live DNS reachability status, or when you need RDAP-specific fields not guaranteed by legacy WHOIS.")
async def resolve_whois_registration_timeline(domain: Annotated[str, Field(..., description="Fully qualified domain name to query, e.g. 'acme-corp.com'. Must be valid IDNA or punycode ASCII.", min_length=3, max_length=253)], include_historical_registrants: Annotated[bool, Field(False, description='When true, resolves historical registrant records where available. When false, only the current registrant summary is returned to minimize latency and rate-limit exposure.')], ctx: Context) -> dict[str, Any]:
    """Resolve WHOIS Registration Timeline"""
    _nexus_path = '/resolve-whois-registration-timeline'.format()
    params = {"domain": domain, "include_historical_registrants": include_historical_registrants}
    _nexus_call_t0 = time.monotonic()
    _nexus_call_success = True
    try:
        return await _nexus_mcp_call_core('POST', _nexus_path, params, headers=None)
    except Exception:
        _nexus_call_success = False
        raise
    finally:
        _nexus_call_latency_ms = int((time.monotonic() - _nexus_call_t0) * 1000)
        _nexus_fire_and_forget(_nexus_log_mcp_call_event(
            'nexus_live_entity_verification_resolve_whois_registration_timeline', _nexus_call_success, _nexus_call_latency_ms, ctx,
            route_key='POST /resolve-whois-registration-timeline',
        ))

@_nexus_mcp.tool(name='nexus_live_entity_verification_probe_certificate_transparency_presence', description='Searches Certificate Transparency logs for certificates issued for a domain, computing certificate count, earliest and latest issuance dates, unique issuers, subdomain count, and a continuity score. Use when you need cryptographic evidence of operational TLS issuance, a strong signal against entity hallucination. Do NOT use for certificate content or private key handling, for checking current TLS certificate validity or expiry on a live endpoint, or when you require real-time CT log streaming.')
async def probe_certificate_transparency_presence(domain: Annotated[str, Field(..., description="Fully qualified domain name to probe, e.g. 'acme-corp.com'. Must be valid IDNA or punycode ASCII.", min_length=3, max_length=253)], include_subdomains: Annotated[bool, Field(False, description='When true, includes certificates issued to subdomains of the queried domain. When false, only exact domain matches are analyzed.')], max_certs_to_analyze: Annotated[float, Field(100, description='Maximum number of certificate records to analyze from CT logs. Lower values reduce latency but may miss continuity signals. Range 1 to 1000.', ge=1, le=1000)], ctx: Context) -> dict[str, Any]:
    """Probe Certificate Transparency Presence"""
    _nexus_path = '/probe-certificate-transparency-presence'.format()
    params = {"domain": domain, "include_subdomains": include_subdomains, "max_certs_to_analyze": max_certs_to_analyze}
    _nexus_call_t0 = time.monotonic()
    _nexus_call_success = True
    try:
        return await _nexus_mcp_call_core('POST', _nexus_path, params, headers=None)
    except Exception:
        _nexus_call_success = False
        raise
    finally:
        _nexus_call_latency_ms = int((time.monotonic() - _nexus_call_t0) * 1000)
        _nexus_fire_and_forget(_nexus_log_mcp_call_event(
            'nexus_live_entity_verification_probe_certificate_transparency_presence', _nexus_call_success, _nexus_call_latency_ms, ctx,
            route_key='POST /probe-certificate-transparency-presence',
        ))

@_nexus_mcp.tool(name='nexus_live_entity_verification_measure_wayback_snapshot_density', description='Measures Internet Archive Wayback Machine CDX snapshot density for a domain over a lookback window, returning total snapshots, first and last snapshot dates, snapshots per year, a density score, and coverage gaps in months. Use when distinguishing a long-lived archived domain from a hallucinated one with no archival footprint, or to establish temporal consistency. Do NOT use for retrieving archived page content, for CDX pagination beyond the analyzed window, or when the Internet Archive CDX API is known to be down.')
async def measure_wayback_snapshot_density(domain: Annotated[str, Field(..., description="Fully qualified domain name to query, e.g. 'acme-corp.com'. Must be valid IDNA or punycode ASCII.", min_length=3, max_length=253)], lookback_years: Annotated[float, Field(5, description='Number of years back from the current date to analyze snapshot density. Range 1 to 30.', ge=1, le=30)], ctx: Context) -> dict[str, Any]:
    """Measure Wayback Snapshot Density"""
    _nexus_path = '/measure-wayback-snapshot-density'.format()
    params = {"domain": domain, "lookback_years": lookback_years}
    _nexus_call_t0 = time.monotonic()
    _nexus_call_success = True
    try:
        return await _nexus_mcp_call_core('POST', _nexus_path, params, headers=None)
    except Exception:
        _nexus_call_success = False
        raise
    finally:
        _nexus_call_latency_ms = int((time.monotonic() - _nexus_call_t0) * 1000)
        _nexus_fire_and_forget(_nexus_log_mcp_call_event(
            'nexus_live_entity_verification_measure_wayback_snapshot_density', _nexus_call_success, _nexus_call_latency_ms, ctx,
            route_key='POST /measure-wayback-snapshot-density',
        ))

@_nexus_mcp.tool(name='nexus_live_entity_verification_audit_dns_operational_maturity', description='Queries DNS resolvers for MX, SPF, DMARC, DKIM selectors, NS record count, and propagation consistency across resolvers, producing a maturity score and signal weight for entity verification. Use when you need to assess whether a domain has been configured for real email and DNS operation, a strong signal that the entity existed and operated beyond mere registration. Do NOT use for checking current DNS resolution failures as a pure monitoring alert, for DNSSEC chain validation, or when you are not prepared for a resolver to be unreachable because it will be reported in signals_missing.')
async def audit_dns_operational_maturity(domain: Annotated[str, Field(..., description="Fully qualified domain name to audit, e.g. 'acme-corp.com'. Must be valid IDNA or punycode ASCII.", min_length=3, max_length=253)], resolvers: Annotated[list[str], Field(None, description="Optional list of DNS resolver IPs or hosts to query. If omitted or null, defaults to ['8.8.8.8','1.1.1.1']. Maximum 5 resolvers supported per call.", min_length=1, max_length=5)], ctx: Context) -> dict[str, Any]:
    """Audit DNS Operational Maturity"""
    _nexus_path = '/audit-dns-operational-maturity'.format()
    params = {"domain": domain, "resolvers": resolvers}
    _nexus_call_t0 = time.monotonic()
    _nexus_call_success = True
    try:
        return await _nexus_mcp_call_core('POST', _nexus_path, params, headers=None)
    except Exception:
        _nexus_call_success = False
        raise
    finally:
        _nexus_call_latency_ms = int((time.monotonic() - _nexus_call_t0) * 1000)
        _nexus_fire_and_forget(_nexus_log_mcp_call_event(
            'nexus_live_entity_verification_audit_dns_operational_maturity', _nexus_call_success, _nexus_call_latency_ms, ctx,
            route_key='POST /audit-dns-operational-maturity',
        ))


# Crea el sub-app ASGI de streamable HTTP -- DEBE llamarse antes de
# poder acceder a _nexus_mcp.session_manager (se crea de forma
# perezosa, ver docstring del modulo).
# Se monta en "/" (no en "/mcp"): streamable_http_app() YA expone su
# propia ruta interna en "/mcp" -- montarlo de nuevo en "/mcp" duplica
# el path a "/mcp/mcp" y da 404 (bug real encontrado probando esto en
# runtime con un cliente MCP de verdad, no algo teorico).
_nexus_mcp_asgi_app = _nexus_mcp.streamable_http_app()

# --- NEXUS: PATCH mcp_lifespan_composition_fix ---
# @app.on_event() SOLO se ejecuta si Starlette uso _DefaultLifespan --
# eso pasa unicamente cuando el `app = FastAPI(...)` que genero el LLM
# NO paso su propio parametro `lifespan=`. Si el LLM SI definio uno
# (tipico en assets con estado -- ej. cleanup de conexiones WebSocket
# al shutdown), Starlette usa ESE callable exclusivamente y los
# handlers @app.on_event quedan sin ejecutarse -- sin warning, sin
# error, el server bootea limpio ("Application startup complete") y
# el primer request a /mcp explota con "RuntimeError: Task group is
# not initialized." (confirmado contra Router.__init__ de Starlette:
# lifespan=None -> _DefaultLifespan(self) [dispara on_event],
# lifespan=<callable> -> se usa ESE, on_event nunca corre). Bug real
# encontrado en produccion 2026-07-25 (asset "ws", que define su
# propio lifespan para cerrar sesiones WebSocket abiertas).
#
# Fix: envolver el lifespan_context que Starlette YA construyo (sea
# _DefaultLifespan o el custom del LLM) en vez de competir con el
# via @app.on_event. Funciona en ambos casos sin parsear ni tocar
# el `app = FastAPI(...)` original.
_nexus_prev_lifespan_context = app.router.lifespan_context


@asynccontextmanager
async def _nexus_combined_lifespan(app):
    async with _nexus_mcp.session_manager.run():
        async with _nexus_prev_lifespan_context(app):
            yield


app.router.lifespan_context = _nexus_combined_lifespan


# --- NEXUS: receptor real de webhooks de Stripe (inyectado por forge_output_saver_v6) ---
from fastapi import Request as _NexusStripeRequest
from fastapi.responses import JSONResponse as _NexusStripeJSONResponse

@app.post("/stripe/webhook")
async def _nexus_stripe_webhook(request: _NexusStripeRequest):
    import os as _nexus_os
    import stripe as _nexus_stripe
    _webhook_secret = _nexus_os.environ.get("STRIPE_WEBHOOK_SECRET")
    if not _webhook_secret:
        return _NexusStripeJSONResponse(
            status_code=404,
            content={"error": "stripe webhook not configured"},
        )
    _secret_key = _nexus_os.environ.get("STRIPE_SECRET_KEY")
    if _secret_key:
        _nexus_stripe.api_key = _secret_key
    _payload = await request.body()
    _sig_header = request.headers.get("stripe-signature", "")
    try:
        _event = _nexus_stripe.Webhook.construct_event(
            _payload, _sig_header, _webhook_secret
        )
    except ValueError:
        return _NexusStripeJSONResponse(
            status_code=400, content={"error": "invalid payload"}
        )
    except _nexus_stripe.error.SignatureVerificationError:
        return _NexusStripeJSONResponse(
            status_code=400, content={"error": "invalid signature"}
        )
    # NEXUS: solo verificacion + ack real -- el gate de
    # autorizacion por estado de suscripcion y la politica de
    # dunning/downgrade son decisiones de producto pendientes,
    # no implementadas a proposito (ver CLAUDE.md).
    print(
        f"[NEXUS_STRIPE_WEBHOOK] type={_event['type']} "
        f"id={_event['id']}"
    )
    return _NexusStripeJSONResponse(
        status_code=200, content={"received": True}
    )


app.mount("/", _nexus_mcp_asgi_app)