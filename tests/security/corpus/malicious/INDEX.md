# Malicious Corpus — True-Positive Suite

Attack samples grouped by the detector they target. Each sample
MUST be blocked by its named detector specifically — not by a
generic catch-all rule — so that regressions in a single detector
are visible.

## Layout

```
malicious/
├── sqli/              # M2 T2.4 sqli detector
├── xss/               # M2 T2.4 xss detector
├── traversal/         # M2 T2.4 path traversal
├── ssrf/              # M2 T2.4 ssrf
├── header-injection/  # M2 T2.4 header injection
├── recon/             # M2 T3.x recon detector
└── body-abuse/        # M2 T2.4 body abuse
```

## Format

Same raw HTTP/1.1 format as the benign corpus. Each file begins
with a comment block identifying the attack class and source:

```
# class: sqli
# technique: union-based
# source: OWASP CRS v4.0 rule 942100
# expected: block status=403 reason=sqli

GET /search?q=' UNION SELECT 1,2,3-- HTTP/1.1
Host: example.com

```

The `expected:` line is parsed by `run-corpus.sh` and compared
against the actual decision.

## Sourcing

- OWASP Core Rule Set (CRS) test vectors
- PayloadsAllTheThings (github.com/swisskyrepo)
- CVE proof-of-concepts from NVD
- Red-team engagement captures (sanitized)

## Target Detection Rates

| Class             | Minimum true-positive rate | Plan reference |
|-------------------|----------------------------|----------------|
| sqli              | ≥ 99%                      | M2 T2.4 DoD    |
| xss               | ≥ 98%                      | M2 T2.4 DoD    |
| traversal         | ≥ 99%                      | M2 T2.4 DoD    |
| ssrf              | ≥ 95%                      | M2 T2.4 DoD    |
| header-injection  | ≥ 99%                      | M2 T2.4 DoD    |
| recon             | ≥ 90%                      | M2 T3.x        |
| body-abuse        | ≥ 95%                      | M2 T2.4 DoD    |

## Running

```sh
./tests/security/run-corpus.sh malicious
./tests/security/run-corpus.sh malicious --class sqli  # single class
```
