/**
 * Cliente HTTP para LiveEntityVerification -- generado deterministicamente
 * desde el contrato OpenAPI real (src/agents/openapi_sdk_generator.py).
 * No edites rutas/params a mano aca -- sdk.py sale del mismo spec,
 * por diseno no puede divergir.
 */

class LiveEntityVerificationError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.name = 'LiveEntityVerificationError';
    this.statusCode = statusCode;
  }
}

class LiveEntityVerification {
  constructor(apiKey, baseUrl = "https://live-entity-verification.railway.app", timeoutMs = 30000) {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.timeoutMs = timeoutMs;
  }

  _headers() {
    const h = { 'Content-Type': 'application/json' };
    if (this.apiKey) h['X-API-Key'] = this.apiKey;
    return h;
  }

  async verifyEntityExistenceCrossSignal({ domain, entity_name, min_confidence_threshold = 0.65, signal_mask = undefined }) {
    // Fuses WHOIS registration timeline, Certificate Transparency log presence, Wayback Machine snapshot density, and DNS operational maturity with Bayesian calibrated weights to return a corroborated exist
    // Calls POST /verify-entity-existence-cross-signal
    const payload = { domain, entity_name, min_confidence_threshold, signal_mask };
    const url = `${this.baseUrl}/verify-entity-existence-cross-signal`;
    const response = await fetch(url, { method: 'POST', headers: this._headers(), body: JSON.stringify(payload) });
    if (!response.ok) {
      const text = await response.text();
      throw new LiveEntityVerificationError(`HTTP ${response.status}: ${text.slice(0, 500)}`, response.status);
    }
    return response.json();
  }

  async resolveWhoisRegistrationTimeline({ domain, include_historical_registrants = false }) {
    // Resolves a domain's WHOIS registration timeline including creation date, expiration date, last updated date, registrar, registrant country, historical registrant count, age in days, and registration g
    // Calls POST /resolve-whois-registration-timeline
    const payload = { domain, include_historical_registrants };
    const url = `${this.baseUrl}/resolve-whois-registration-timeline`;
    const response = await fetch(url, { method: 'POST', headers: this._headers(), body: JSON.stringify(payload) });
    if (!response.ok) {
      const text = await response.text();
      throw new LiveEntityVerificationError(`HTTP ${response.status}: ${text.slice(0, 500)}`, response.status);
    }
    return response.json();
  }

  async probeCertificateTransparencyPresence({ domain, include_subdomains = false, max_certs_to_analyze = 100 }) {
    // Searches Certificate Transparency logs for certificates issued for a domain, computing certificate count, earliest and latest issuance dates, unique issuers, subdomain count, and a continuity score. U
    // Calls POST /probe-certificate-transparency-presence
    const payload = { domain, include_subdomains, max_certs_to_analyze };
    const url = `${this.baseUrl}/probe-certificate-transparency-presence`;
    const response = await fetch(url, { method: 'POST', headers: this._headers(), body: JSON.stringify(payload) });
    if (!response.ok) {
      const text = await response.text();
      throw new LiveEntityVerificationError(`HTTP ${response.status}: ${text.slice(0, 500)}`, response.status);
    }
    return response.json();
  }

  async measureWaybackSnapshotDensity({ domain, lookback_years = 5 }) {
    // Measures Internet Archive Wayback Machine CDX snapshot density for a domain over a lookback window, returning total snapshots, first and last snapshot dates, snapshots per year, a density score, and c
    // Calls POST /measure-wayback-snapshot-density
    const payload = { domain, lookback_years };
    const url = `${this.baseUrl}/measure-wayback-snapshot-density`;
    const response = await fetch(url, { method: 'POST', headers: this._headers(), body: JSON.stringify(payload) });
    if (!response.ok) {
      const text = await response.text();
      throw new LiveEntityVerificationError(`HTTP ${response.status}: ${text.slice(0, 500)}`, response.status);
    }
    return response.json();
  }

  async auditDnsOperationalMaturity({ domain, resolvers = undefined }) {
    // Queries DNS resolvers for MX, SPF, DMARC, DKIM selectors, NS record count, and propagation consistency across resolvers, producing a maturity score and signal weight for entity verification. Use when 
    // Calls POST /audit-dns-operational-maturity
    const payload = { domain, resolvers };
    const url = `${this.baseUrl}/audit-dns-operational-maturity`;
    const response = await fetch(url, { method: 'POST', headers: this._headers(), body: JSON.stringify(payload) });
    if (!response.ok) {
      const text = await response.text();
      throw new LiveEntityVerificationError(`HTTP ${response.status}: ${text.slice(0, 500)}`, response.status);
    }
    return response.json();
  }

}

module.exports = { LiveEntityVerification, LiveEntityVerificationError };