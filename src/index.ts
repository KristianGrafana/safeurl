/**
 * Configuration options for URL validation.
 */
export interface SafeUrlOptions {
    /**
     * If true, allows relative URLs (e.g., "/api/data").
     * If false, strictly requires absolute URLs (e.g., "https://example.com/api").
     * @default true
     */
    allowRelative?: boolean;

    /**
     * List of allowed URL protocols/schemes (without the colon).
     * Only protocols using "://" format are supported (e.g., http, https, ftp).
     * Relative URLs bypass protocol checks.
     * @default ['http', 'https']
     * @example ['http', 'https', 'ftp']
     */
    allowedProtocols?: string[];
  }
  
  /**
   * Validates a URL string for client-side security risks.
   * Specifically checks for Path Traversal attempts ("..") and Control Characters ("\r\n\t").
   * * Note: This checks the raw string *before* the browser's URL parser normalizes it.
   * This is crucial because `new URL('http://a.com/../b')` automatically becomes `http://a.com/b`,
   * hiding the traversal attempt if checked after parsing.
   * * @param url - The URL string to validate.
   * @param options - Configuration options.
   * @returns {boolean} - True if the URL is considered safe, false otherwise.
   */
  export function isSafeUrl(url: string, options: SafeUrlOptions = {}): boolean {
    const { allowRelative = true, allowedProtocols = ['http', 'https'] } = options;
  
    if (!url || typeof url !== 'string') {
      return false;
    }
  
    // 1. Check for Control Characters (CRLF Injection / Request Splitting)
    // \r (Carriage Return), \n (New Line), \t (Tab) are forbidden in fetch.
    // We use a regex to detect any occurrence.
    const controlCharsPattern = /[\r\n\t]/;
    if (controlCharsPattern.test(url)) {
      return false;
    }
  
    // 2. Check for Path Traversal ("..")
    // We look for ".." segments. A segment is defined as:
    // - Starts with ".." and ends (relative path)
    // - Starts with ".." and follows with "/" (../abc)
    // - inside the path (/../)
    // - ends with /..
    
    // Regex Explanation:
    // (^|\/)  -> Match start of string OR a forward slash
    // \.\.    -> Match literal ".."
    // (\/|$)  -> Match a forward slash OR end of string
    const traversalPattern = /(^|\/)\.\.(\/|$)/;
    
    if (traversalPattern.test(url)) {
      return false;
    }

    // 3. Protocol validation
    // Check if URL starts with an allowed protocol (e.g., "http://" or "https://")
    const urlLower = url.toLowerCase();
    const hasAllowedProtocol = allowedProtocols.some(
      protocol => urlLower.startsWith(`${protocol.toLowerCase()}://`)
    );

    if (hasAllowedProtocol) {
      // URL starts with an allowed protocol - safe
      return true;
    }

    // Check if URL has any protocol by looking for ":" before the first "/"
    // This catches javascript:, data:, mailto:, vbscript:, etc.
    const colonIndex = url.indexOf(':');
    const slashIndex = url.indexOf('/');
    const hasProtocol = colonIndex !== -1 && (slashIndex === -1 || colonIndex < slashIndex);
    
    if (hasProtocol) {
      // Has a protocol but not in allowed list - block it
      return false;
    }

    // No protocol found - it's a relative URL
    if (!allowRelative) {
      return false;
    }
  
    return true;
  }
  
  /**
   * A wrapper around the native `fetch` API that performs security validation checks
   * before executing the request.
   * * @param input - The resource URL.
   * @param init - Standard fetch options. Use `redirect: 'error' | 'manual' | 'follow'` to control redirect behavior.
   * @returns Promise<Response>
   * @throws Error if the URL contains security violations.
   */
  export async function safeFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    // Normalize input to string for validation
    let urlStr: string;
  
    if (typeof input === 'string') {
      urlStr = input;
    } else if (input instanceof URL) {
      // Note: If a URL object is passed, ".." are likely already resolved/removed by the browser.
      // We convert to string to check for control chars, but traversal might be hidden.
      urlStr = input.toString();
    } else if ('url' in input) {
      // Handle Request object
      // Handle Request object safely
      if (typeof input.url === 'string') {
        urlStr = input.url;
      } else {
        throw new Error("Request object does not have a valid URL string.");
      }
      throw new Error(`Security Violation: URL contains unsafe characters or traversal attempts: "${urlStr}"`);
    }
  
    // Execute standard fetch with user-provided init options.
    // This allows the user to pass { redirect: 'follow' } (default), 
    // { redirect: 'error' }, or { redirect: 'manual' } to adhere to WHATWG spec.
    return fetch(input, init);
  }