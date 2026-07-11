/**
 * Admin layout — noindex, isolated from public marketing layout chrome.
 */
export const metadata = {
  robots: { index: false, follow: false }
};

export default function AdminLayout({ children }) {
  return (
    <div
      dir="ltr"
      lang="en"
      style={{ margin: 0, minHeight: "100dvh", background: "#0b0d10" }}
    >
      {children}
    </div>
  );
}
