import { isSafeUrl, safeFetch } from '../src/index';

console.log("Running SafeURL Tests...\n");

const tests = [
  // --- Valid URLs ---
  { url: "https://example.com/api/v1/users", expected: true, desc: "Standard Absolute URL" },
  { url: "/api/users/123", expected: true, desc: "Standard Relative URL" },
  { url: "http://localhost:3000/data", expected: true, desc: "Localhost URL" },
  { url: "image.png", expected: true, desc: "Simple filename" },

  // --- Path Traversal Attempts (Should Fail) ---
  { url: "https://example.com/api/../secret", expected: false, desc: "Traversal in absolute URL" },
  { url: "../etc/passwd", expected: false, desc: "Traversal at start" },
  { url: "/api/v1/../../admin", expected: false, desc: "Deep traversal" },
  { url: "data/..", expected: false, desc: "Traversal at end" },
  
  // --- Edge Cases for ".." (Should Pass if not a segment) ---
  { url: "https://example.com/upload/image..jpg", expected: true, desc: "Double dot in filename (valid)" },
  { url: "/api/v1/data...json", expected: true, desc: "Triple dot (valid)" },

  // --- Control Characters (Should Fail) ---
  { url: "https://example.com/api\r", expected: false, desc: "Contains Carriage Return" },
  { url: "https://example.com/api\n", expected: false, desc: "Contains Newline" },
  { url: "https://example.com/api\t/param", expected: false, desc: "Contains Tab" },

  // --- Control Characters and Path Traversal in Request Object ---
  { url: { url: "https://example.com/api\r../secret" }, expected: false, desc: "Contains Carriage Return in Request Object" },
  { url: { url: "https://example.com/api\n../secret" }, expected: false, desc: "Contains Newline in Request Object" },
  { url: { url: "https://example.com/api\t/param" }, expected: false, desc: "Contains Tab in Request Object" },

  // --- Encoded path traversal attempts (Should Fail) ---
  // Single encoding: %2e = ".", %2f = "/"
  { url: "https://example.com/api/%2e%2e/secret", expected: false, desc: "Single encoded traversal (%2e%2e)" },
  { url: "https://example.com/api/%2e%2e%2fsecret", expected: false, desc: "Single encoded traversal with slash (%2e%2e%2f)" },
  
  // Double encoding: %25 = "%", so %252e -> %2e -> "."
  { url: "https://example.com/api/%252e%252e/secret", expected: false, desc: "Double encoded traversal (%252e%252e)" },
  { url: "https://example.com/api/%252e%252e%252fsecret", expected: false, desc: "Double encoded traversal with slash" },
  
  // Triple encoding: %2525 -> %25 -> "%", so %25252e -> %252e -> %2e -> "."
  { url: "https://example.com/api/%25252e%25252e/secret", expected: false, desc: "Triple encoded traversal (%25252e%25252e)" },
  { url: "https://example.com/api/%25252e%25252e%25252fsecret", expected: false, desc: "Triple encoded traversal with slash" },
  
  // Mixed encoding variations
  { url: "https://example.com/api/..%2fsecret", expected: false, desc: "Mixed: plain dots with encoded slash" },
  { url: "https://example.com/api/%2e./secret", expected: false, desc: "Mixed: one encoded dot, one plain" },
  { url: "/%252e%252e/etc/passwd", expected: false, desc: "Double encoded relative path traversal" },

  // --- Backslash Traversal (Windows-style) ---
  { url: "https://example.com/api/..\\secret", expected: false, desc: "Backslash traversal" },
  { url: "https://example.com/api/..%5csecret", expected: false, desc: "Encoded backslash traversal" },
  { url: "..\\Windows\\System32", expected: false, desc: "Relative backslash traversal" },

  // --- Protocol Validation (Dangerous Protocols - Should Fail) ---
  { url: "javascript:alert('XSS')", expected: false, desc: "javascript: protocol (XSS)" },
  { url: "JAVASCRIPT:alert('XSS')", expected: false, desc: "JAVASCRIPT: protocol (case insensitive)" },
  { url: "data:text/html,<script>alert('XSS')</script>", expected: false, desc: "data: protocol" },
  { url: "vbscript:msgbox('XSS')", expected: false, desc: "vbscript: protocol" },
  { url: "file:///etc/passwd", expected: false, desc: "file: protocol" },
  { url: "ftp://example.com/file.txt", expected: false, desc: "ftp: protocol (not in default allowlist)" },

  // --- Protocol Validation (Safe Protocols - Should Pass) ---
  { url: "http://example.com/page", expected: true, desc: "http: protocol (allowed)" },
  { url: "https://example.com/page", expected: true, desc: "https: protocol (allowed)" },
  { url: "HTTP://example.com/page", expected: true, desc: "HTTP: protocol (case insensitive)" },
  { url: "HTTPS://example.com/page", expected: true, desc: "HTTPS: protocol (case insensitive)" },

  // --- Edge Cases for Protocol Detection ---
  { url: "mailto:test@example.com", expected: false, desc: "mailto: not in default allowlist" },
  { url: "tel:+1234567890", expected: false, desc: "tel: not in default allowlist" },
  { url: "//example.com/page", expected: true, desc: "Protocol-relative URL (treated as relative)" },
  { url: "example.com/page", expected: true, desc: "No protocol (relative URL)" },
  { url: "/path/to/resource", expected: true, desc: "Absolute path (relative URL)" },

];

let passed = 0;
let failed = 0;

tests.forEach(t => {
  // If t.url is an object, extract its 'url' property
  const url = typeof t.url === 'string' ? t.url : t.url.url;
  const result = isSafeUrl(url);
  if (result === t.expected) {
    console.log(`[PASS] ${t.desc}`);
    passed++;
  } else {
    console.error(`[FAIL] ${t.desc} | Input: "${t.url}" | Expected: ${t.expected} | Got: ${result}`);
    failed++;
  }
});

// --- Custom Protocol Tests ---
console.log("\n--- Custom Protocol Tests ---");

const customProtocolTests = [
  // Note: Only protocols using "://" format are supported (http://, https://, ftp://, etc.)
  // Protocols like mailto: and tel: cannot be allowlisted with this simple approach
  
  // Restricting to https only
  { 
    url: "http://example.com", 
    options: { allowedProtocols: ['https'] }, 
    expected: false, 
    desc: "http: blocked when only https allowed" 
  },
  { 
    url: "https://example.com", 
    options: { allowedProtocols: ['https'] }, 
    expected: true, 
    desc: "https: allowed when only https allowed" 
  },
  // Empty allowlist blocks all absolute URLs with protocols
  { 
    url: "https://example.com", 
    options: { allowedProtocols: [] }, 
    expected: false, 
    desc: "https: blocked with empty allowlist" 
  },
  // Relative URLs still work with restricted protocols
  { 
    url: "/api/data", 
    options: { allowedProtocols: ['https'] }, 
    expected: true, 
    desc: "Relative URL allowed even with restricted protocols" 
  },
  // FTP allowed with custom list
  { 
    url: "ftp://files.example.com/data.zip", 
    options: { allowedProtocols: ['http', 'https', 'ftp'] }, 
    expected: true, 
    desc: "ftp: with custom allowlist" 
  },
];

customProtocolTests.forEach(t => {
  const result = isSafeUrl(t.url, t.options);
  if (result === t.expected) {
    console.log(`[PASS] ${t.desc}`);
    passed++;
  } else {
    console.error(`[FAIL] ${t.desc} | Input: "${t.url}" | Expected: ${t.expected} | Got: ${result}`);
    failed++;
  }
});

console.log(`\nTests Completed. Passed: ${passed}, Failed: ${failed}`);

if (failed > 0) process.exit(1);

// Mocking fetch for safeFetch demonstration
global.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    return new Response("Mock Response");
}

// Demo safeFetch
console.log("\nTesting safeFetch wrapper:");

(async () => {
    try {
        await safeFetch("https://example.com/good");
        console.log("[PASS] safeFetch allowed good URL");
    } catch (e) {
        console.error("[FAIL] safeFetch blocked good URL");
    }

    try {
        await safeFetch("https://example.com/../bad");
        console.error("[FAIL] safeFetch allowed bad URL");
    } catch (e) {
        console.log("[PASS] safeFetch blocked bad URL");
    }
})();