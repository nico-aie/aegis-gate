# Path Traversal Detection

## Purpose

Block attempts to access files outside the web root using `../` and related sequences. Path traversal attacks target file-serving endpoints, template loaders, include directives, and any code that builds a filesystem path from user input.

## Patterns

### Classic sequences

- `../`
- `..\`
- `..%2F`, `..%2f`
- `..%5C`, `..%5c`

### Double encoding

- `%252e%252e%252f` (double-URL-encoded `../`)
- `..%c0%af` (overlong UTF-8 for `/`)
- `..%c1%9c`

### Null byte injection

- `../../../etc/passwd%00.jpg`
- `\x00` in paths

### Unicode tricks

- `..\u002f`
- `..%u2215`
- `\ufeff` (BOM) in paths

### Absolute path references

- `/etc/passwd`
- `C:\Windows\`, `C:/Windows/`
- `\\?\C:\` (Windows namespace paths)
- `file:///`

### Known sensitive files

When absolute or traversal sequences target known files, the detection is high-confidence:

- `/etc/passwd`, `/etc/shadow`, `/etc/hosts`
- `/proc/self/environ`, `/proc/self/cmdline`
- `.env`, `.git/config`, `.ssh/id_rsa`
- `wp-config.php`, `web.config`, `application.yml`
- `%WINDIR%\system.ini`

## Depth check

Even if no traversal sequences are found, a path with excessive depth (many `/` segments) is suspicious, especially if the frontend routing doesn't use deep paths. Configurable via `max_depth`.

## Normalization

Before matching, the path is normalized:

1. URL-decode (up to 2 rounds for double encoding)
2. Resolve `%00` null bytes
3. Normalize `\` to `/`
4. Collapse redundant slashes
5. Case-fold for comparison against known-sensitive file list

After normalization, any `../` sequence that escapes the current directory (i.e., the resolved path is above the request's root) is flagged.

## Surfaces

- URL path (primary)
- Query parameters (file-download endpoints often take filenames)
- Request body (upload endpoints)
- Specific headers configured as file references

## Configuration

```yaml
detection:
  path_traversal:
    enabled: true
    max_depth: 10
    risk_increment: 50
    block_on_detect: true         # CATCH-ALL tier always blocks regardless
```

## Actions

- Add 50 to risk score (traversal is high-confidence)
- Audit log
- Block immediately on CATCH-ALL tier (path traversal almost never has legitimate uses in user input)
- Other tiers defer to the final risk decision

## Implementation

- `src/detection/path_traversal.rs`

## Design notes

- Normalization is done once and cached on the `RequestContext` — later stages (rule engine) can reuse the normalized path
- The detector trusts the reverse proxy layer's URL parsing; it does not try to re-parse the raw request line
- Sensitive-file list is hot-reloadable — operators can add files specific to their stack
