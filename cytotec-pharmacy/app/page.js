import { redirect } from "next/navigation";

/**
 * Fallback when middleware does not rewrite.
 * Primary path: middleware serves /public/index.html
 */
export default function Page() {
  redirect("/index.html");
}
