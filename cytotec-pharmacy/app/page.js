import { permanentRedirect } from "next/navigation";

/**
 * No Edge middleware — avoid MIDDLEWARE_INVOCATION_FAILED on Vercel.
 * Send visitors to the static landing page in /public/index.html
 */
export default function Page() {
  permanentRedirect("/index.html");
}
