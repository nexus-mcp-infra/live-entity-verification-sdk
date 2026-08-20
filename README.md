# Live Entity Verification API

## Overview

The Live Entity Verification API provides a robust solution for determining the existence of a domain or entity across multiple signals including WHOIS registration history, Certificate Transparency (CT) log presence, Wayback Machine snapshot density, and DNS operational maturity. This API helps prevent LLM pipelines from acting on hallucinated company/domain names, reducing wasted API calls and reputational risk.

## Installation

The Live Entity Verification API is not available via pip or npm. You can use the API by calling the endpoint directly using HTTP requests or by cloning this repository and running the server locally.

## Base URL

The base URL for the Live Entity Verification API is:
```
https://api.liveentityverification.com
```

## Authentication

The API is accessed directly via HTTP requests. No API key or registration is required.

## Endpoints

### 1. Verify Entity Existence Cross-Signal

**Endpoint:**  
```
POST /verify-entity-existence-cross-signal
```

**Description:**  
Verifies the existence of an entity across multiple signals.

**Request Body:**

```json
{
  "domain": "acme-corp.com",
  "entity_name": "Acme Corporation",
  "min_confidence_threshold": 0.65,
  "signal_mask": ["whois", "ct", "wayback", "dns"]
}
```

**Response:**

```json
{
  "verdict": "VERIFIED_LIVE",
  "verdict_confidence": 0.95,
  "signals": {
    "whois": {
      "exists": true,
      "confidence": 0.8
    },
    "ct": {
      "exists": true,
      "confidence": 0.9
    },
    "wayback": {
      "exists": true,
      "confidence": 0.85
    },
    "dns": {
      "exists": true,
      "confidence": 0.95
    }
  }
}
```

### 2. Resolve WHOIS Registration Timeline

**Endpoint:**  
```
POST /resolve-whois-registration-timeline
```

**Description:**  
Resolves the WHOIS registration timeline for a domain.

**Request Body:**

```json
{
  "domain": "acme-corp.com",
  "include_historical_registrants": false
}
```

**Response:**

```json
{
  "domain": "acme-corp.com",
  "creation_date": "2019-01-01T00:00:00Z",
  "expiration_date": "2024-01-01T00:00:00Z",
  "last_updated_date": "2022-01-01T00:00:00Z",
  "registrar": "GoDaddy",
  "registrant_country": "US",
  "historical_registrants": 0,
  "age_in_days": 1577,
  "registration_gaps": false
}
```

## Examples

### Example 1: Verify Entity Existence

```python
import requests

url = "https://api.liveentityverification.com/verify-entity-existence-cross-signal"
payload = {
    "domain": "acme-corp.com",
    "entity_name": "Acme Corporation",
    "min_confidence_threshold": 0.65,
    "signal_mask": ["whois", "ct", "wayback", "dns"]
}

response = requests.post(url, json=payload)

if response.ok:
    print(response.json())
else:
    print(f"Error: {response.status_code} - {response.text}")
```

### Example 2: Resolve WHOIS Registration Timeline

```python
import requests

url = "https://api.liveentityverification.com/resolve-whois-registration-timeline"
payload = {
    "domain": "acme-corp.com",
    "include_historical_registrants": false
}

response = requests.post(url, json=payload)

if response.ok:
    print(response.json())
else:
    print(f"Error: {response.status_code} - {response.text}")
```

## Models

The API uses the following Pydantic models for request validation:

### VerifyEntityRequest

```python
from pydantic import BaseModel, Field, Annotated, validator
import ipaddress
import re

class VerifyEntityRequest(BaseModel):
    domain: Annotated[str, Field(..., min_length=3, max_length=253,
        description="Fully qualified domain name, e.g. 'acme-corp.com'.")]
    entity_name: Annotated[str, Field(..., min_length=1, max_length=200,
        description='Human-readable entity name the domain is supposed to represent.')]
    min_confidence_threshold: Annotated[float, Field(0.65, ge=0.0, le=1.0,
        description='Minimum verdict_confidence for a decisive verdict.')]
    signal_mask: Annotated[Optional[list[str]], Field(None, min_length=1, max_length=4,
        description="Subset of signals to evaluate. Null means all four are evaluated.")]

    @validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)

    @validator('signal_mask')
    @classmethod
    def validate_signal_mask(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v is None:
            return v
        invalid = [s for s in v if s not in VALID_SIGNALS]
        if invalid:
            raise ValueError(f"Invalid signal names: {invalid}. Must be subset of {VALID_SIGNALS}")
        return v
```

### WhoisRequest

```python
class WhoisRequest(BaseModel):
    domain: Annotated[str, Field(..., min_length=3, max_length=253,
        description="Fully qualified domain name, e.g. 'acme-corp.com'.")]
    include_historical_registrants: Annotated[bool, Field(False,
        description='When true, resolves historical registrant records where available.')]

    @validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)
```

### CTRequest

```python
class CTRequest(BaseModel):
    domain: Annotated[str, Field(..., min_length=3, max_length=253,
        description="Fully qualified domain name, e.g. 'acme-corp.com'.")]
    include_subdomains: Annotated[bool, Field(False,
        description='When true, includes certificates issued to subdomains.')]
    max_certs_to_analyze: Annotated[float, Field(100, ge=1, le=1000,
        description='Maximum number of certificate records to analyze from CT logs.')]

    @validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)
```

### WaybackRequest

```python
class WaybackRequest(BaseModel):
    domain: Annotated[str, Field(..., min_length=3, max_length=253,
        description="Fully qualified domain name, e.g. 'acme-corp.com'.")]
    lookback_years: Annotated[float, Field(5, ge=1, le=30,
        description='Number of years back from now to analyze snapshot density.')]

    @validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)
```

### DNSRequest

```python
class DNSRequest(BaseModel):
    domain: Annotated[str, Field(..., min_length=3, max_length=253,
        description="Fully qualified domain name, e.g. 'acme-corp.com'.")]
    resolvers: Annotated[Optional[list[str]], Field(None, min_length=1, max_length=5,
        description="Optional list of DNS resolver IPs. Defaults to ['8.8.8.8','1.1.1.1'].")]

    @validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)

    @validator('resolvers')
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
```

## Support

For any questions or support, please contact us at [support@liveentityverification.com](mailto:support@liveentityverification.com).

---

---

## Pricing

| Calls / month | Price per call |
|---|---|
| 0 - 100 | Free |
| 101 - 10,000 | $0.0025 |
| 10,001 - 100,000 | $0.0018 |
| 100,001 - 1,000,000 | $0.0012 |
| 1,000,001 - 10,000,000 | $0.0008 |
| 10,000,001+ | $0.0005 |

No base fee. No storage fee. No minimum commitment. You pay for computation, not for parking vectors you queried once.