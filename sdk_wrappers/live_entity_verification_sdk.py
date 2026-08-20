from fastapi import status
"""
Cliente HTTP para LiveEntityVerification -- generado deterministicamente desde
el contrato OpenAPI real (src/agents/openapi_sdk_generator.py). No
edites rutas/params a mano aca -- se regenera en cada build desde
tool_spec; sdk.js sale del mismo spec, por diseno no puede divergir.
"""
from __future__ import annotations

import requests
from typing import Any, Optional


class LiveEntityVerificationError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class LiveEntityVerification:
    """HTTP client. Base URL real del deploy: https://live-entity-verification.railway.app"""

    def __init__(self, api_key: Optional[str] = None, base_url: str = 'https://live-entity-verification.railway.app', timeout: float = 30.0):
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({'X-API-Key': api_key})

    def verify_entity_existence_cross_signal(self, domain: str, entity_name: str, min_confidence_threshold: Optional[float] = 0.65, signal_mask: Optional[list[str]] = None) -> dict:
        """Fuses WHOIS registration timeline, Certificate Transparency log presence, Wayback Machine snapshot density, and DNS operational maturity with Bayesian calibrated weights to return a corroborated existence verdict, hallucination probability, and failure mode classification. Use when you need a single cross-signal verdict for a named entity and domain pair, especially to detect LLM-hallucinated entities. Do NOT use for live uptime or reachability checks of currently responding services, for domains already known to be registered and DNS-resolving, or when you need raw provider data without cross-signal weighting.

        Calls POST /verify-entity-existence-cross-signal
        """
        payload = {}
        payload['domain'] = domain
        payload['entity_name'] = entity_name
        if min_confidence_threshold is not None:
            payload['min_confidence_threshold'] = min_confidence_threshold
        if signal_mask is not None:
            payload['signal_mask'] = signal_mask
        url = self.base_url + '/verify-entity-existence-cross-signal'
        response = self.session.post(url, json=payload, timeout=self.timeout)
        if not response.ok:
            raise LiveEntityVerificationError(f'HTTP {response.status_code}: {response.text[:500]}', status_code=response.status_code)
        return response.json()

    def resolve_whois_registration_timeline(self, domain: str, include_historical_registrants: Optional[bool] = False) -> dict:
        """Resolves a domain's WHOIS registration timeline including creation date, expiration date, last updated date, registrar, registrant country, historical registrant count, age in days, and registration gaps. Use when you need to distinguish a legitimately new domain with a coherent timeline from a hallucinated or fabricated one with no WHOIS record or a redacted/broken timeline. Do NOT use for WHOIS privacy law compliance checks, for live DNS reachability status, or when you need RDAP-specific fields not guaranteed by legacy WHOIS.

        Calls POST /resolve-whois-registration-timeline
        """
        payload = {}
        payload['domain'] = domain
        if include_historical_registrants is not None:
            payload['include_historical_registrants'] = include_historical_registrants
        url = self.base_url + '/resolve-whois-registration-timeline'
        response = self.session.post(url, json=payload, timeout=self.timeout)
        if not response.ok:
            raise LiveEntityVerificationError(f'HTTP {response.status_code}: {response.text[:500]}', status_code=response.status_code)
        return response.json()

    def probe_certificate_transparency_presence(self, domain: str, include_subdomains: Optional[bool] = False, max_certs_to_analyze: Optional[float] = 100) -> dict:
        """Searches Certificate Transparency logs for certificates issued for a domain, computing certificate count, earliest and latest issuance dates, unique issuers, subdomain count, and a continuity score. Use when you need cryptographic evidence of operational TLS issuance, a strong signal against entity hallucination. Do NOT use for certificate content or private key handling, for checking current TLS certificate validity or expiry on a live endpoint, or when you require real-time CT log streaming.

        Calls POST /probe-certificate-transparency-presence
        """
        payload = {}
        payload['domain'] = domain
        if include_subdomains is not None:
            payload['include_subdomains'] = include_subdomains
        if max_certs_to_analyze is not None:
            payload['max_certs_to_analyze'] = max_certs_to_analyze
        url = self.base_url + '/probe-certificate-transparency-presence'
        response = self.session.post(url, json=payload, timeout=self.timeout)
        if not response.ok:
            raise LiveEntityVerificationError(f'HTTP {response.status_code}: {response.text[:500]}', status_code=response.status_code)
        return response.json()

    def measure_wayback_snapshot_density(self, domain: str, lookback_years: Optional[float] = 5) -> dict:
        """Measures Internet Archive Wayback Machine CDX snapshot density for a domain over a lookback window, returning total snapshots, first and last snapshot dates, snapshots per year, a density score, and coverage gaps in months. Use when distinguishing a long-lived archived domain from a hallucinated one with no archival footprint, or to establish temporal consistency. Do NOT use for retrieving archived page content, for CDX pagination beyond the analyzed window, or when the Internet Archive CDX API is known to be down.

        Calls POST /measure-wayback-snapshot-density
        """
        payload = {}
        payload['domain'] = domain
        if lookback_years is not None:
            payload['lookback_years'] = lookback_years
        url = self.base_url + '/measure-wayback-snapshot-density'
        response = self.session.post(url, json=payload, timeout=self.timeout)
        if not response.ok:
            raise LiveEntityVerificationError(f'HTTP {response.status_code}: {response.text[:500]}', status_code=response.status_code)
        return response.json()

    def audit_dns_operational_maturity(self, domain: str, resolvers: Optional[list[str]] = None) -> dict:
        """Queries DNS resolvers for MX, SPF, DMARC, DKIM selectors, NS record count, and propagation consistency across resolvers, producing a maturity score and signal weight for entity verification. Use when you need to assess whether a domain has been configured for real email and DNS operation, a strong signal that the entity existed and operated beyond mere registration. Do NOT use for checking current DNS resolution failures as a pure monitoring alert, for DNSSEC chain validation, or when you are not prepared for a resolver to be unreachable because it will be reported in signals_missing.

        Calls POST /audit-dns-operational-maturity
        """
        payload = {}
        payload['domain'] = domain
        if resolvers is not None:
            payload['resolvers'] = resolvers
        url = self.base_url + '/audit-dns-operational-maturity'
        response = self.session.post(url, json=payload, timeout=self.timeout)
        if not response.ok:
            raise LiveEntityVerificationError(f'HTTP {response.status_code}: {response.text[:500]}', status_code=response.status_code)
        return response.json()