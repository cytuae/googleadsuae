/**
 * Security HTTP responses
 * -----------------------
 * Shared response builders for block / challenge outcomes.
 */

import { NextResponse } from "next/server";

/**
 * Simple Access Denied page for blocked visitors.
 * @returns {string}
 */
export function forbiddenPageHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>Access Denied</title>
  <style>
    :root { color-scheme: dark; }
    body {
      margin: 0;
      min-height: 100dvh;
      display: grid;
      place-items: center;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif;
      background: #0c090b;
      color: #f5f5f5;
    }
    main {
      text-align: center;
      padding: 2rem;
    }
    h1 {
      margin: 0 0 0.5rem;
      font-size: 1.5rem;
      font-weight: 600;
    }
    p {
      margin: 0;
      color: #c4b0b8;
      font-size: 1rem;
    }
  </style>
</head>
<body>
  <main>
    <h1>Access Denied</h1>
    <p>You do not have permission to access this resource.</p>
  </main>
</body>
</html>`;
}

/**
 * Build a 403 Access Denied response for a security block.
 *
 * @param {{
 *   requestId: string,
 *   engineVersion: string,
 *   blockType?: string,
 *   country?: string|null,
 *   reason?: string|null
 * }} options
 * @returns {import('next/server').NextResponse}
 */
export function createForbiddenResponse(options) {
  const headers = {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "x-security-engine": options.engineVersion,
    "x-security-decision": "block",
    "x-request-id": options.requestId,
    "x-security-block": options.blockType || "denied"
  };

  if (options.country) {
    headers["x-security-country"] = String(options.country);
  }
  if (options.reason) {
    headers["x-security-reason"] = String(options.reason);
  }

  return new NextResponse(forbiddenPageHtml(), {
    status: 403,
    headers
  });
}
