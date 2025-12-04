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
export declare function isSafeUrl(url: string, options?: SafeUrlOptions): boolean;
/**
 * A wrapper around the native `fetch` API that performs security validation checks
 * before executing the request.
 * * @param input - The resource URL.
 * @param init - Standard fetch options. Use `redirect: 'error' | 'manual' | 'follow'` to control redirect behavior.
 * @returns Promise<Response>
 * @throws Error if the URL contains security violations.
 */
export declare function safeFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
