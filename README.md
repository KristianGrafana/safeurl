# @safelib/safeurl

Client-side URL validation to prevent path traversal, CRLF injection, and dangerous protocols.

## Installation

```bash
npm install @safelib/safeurl
```

## Usage

```typescript
import { isSafeUrl, safeFetch } from '@safelib/safeurl';
```

### isSafeUrl

Validate a URL string:

```typescript

isSafeUrl('https://example.com/api/users');  // true
isSafeUrl('https://example.com/../secret');  // false (path traversal)
isSafeUrl('javascript:alert(1)');            // false (dangerous protocol)
isSafeUrl('/api/data');                      // true (relative URL)
```

### safeFetch

Drop-in replacement for `fetch` with URL validation:

```typescript
// Safe - works normally
const response = await safeFetch('https://api.example.com/users');

// Unsafe - throws error
await safeFetch('https://api.example.com/../admin'); // Error: Security Violation
```

Supports all standard fetch options:

```typescript
await safeFetch('https://api.example.com/data', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ name: 'test' }),
  redirect: 'error'  // or 'follow', 'manual'
});
```

## What it checks

- **Path traversal**: `..` sequences (plain and URL-encoded, including double/triple encoding)
- **Control characters**: `\r`, `\n`, `\t` (CRLF injection)
- **Protocols**: Only `http://` and `https://` allowed by default

## Options

```typescript
interface SafeUrlOptions {
  allowRelative?: boolean;      // Allow relative URLs (default: true)
  allowedProtocols?: string[];  // Allowed protocols (default: ['http', 'https'])
}
```

### Examples

```typescript
// Require absolute URLs
isSafeUrl('/api/data', { allowRelative: false });  // false

// HTTPS only
isSafeUrl('http://example.com', { allowedProtocols: ['https'] });  // false

// Allow FTP
isSafeUrl('ftp://files.example.com/data.zip', { 
  allowedProtocols: ['http', 'https', 'ftp'] 
});  // true
```

## Encoding attacks

Handles multi-level URL encoding:

```typescript
isSafeUrl('https://example.com/%2e%2e/secret');       // false (single encoded)
isSafeUrl('https://example.com/%252e%252e/secret');   // false (double encoded)
isSafeUrl('https://example.com/%25252e%25252e/secret'); // false (triple encoded)
```

## License

MIT

