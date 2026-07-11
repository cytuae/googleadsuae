/**
 * Minimal Edge middleware — site availability only.
 * Security engine is temporarily disabled (see middleware.disabled.js).
 * No Node APIs. No external calls. No blocking.
 */

import { NextResponse } from "next/server";

export function middleware(request) {
  try {
    const { pathname } = request.nextUrl;

    if (pathname === "/" || pathname === "") {
      return NextResponse.rewrite(new URL("/index.html", request.url));
    }

    return NextResponse.next();
  } catch {
    // Never take the site down
    return NextResponse.next();
  }
}

export const config = {
  matcher: ["/"]
};
