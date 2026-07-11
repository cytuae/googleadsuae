/**
 * Minimal Access Denied page — no landing content, no tracking scripts.
 */
export const metadata = {
  title: "Access Denied",
  robots: { index: false, follow: false }
};

export default function AccessDeniedPage() {
  return (
    <main
      style={{
        margin: 0,
        minHeight: "100dvh",
        display: "grid",
        placeItems: "center",
        fontFamily:
          "ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif",
        background: "#0c090b",
        color: "#f5f5f5",
        textAlign: "center",
        padding: "2rem"
      }}
    >
      <div>
        <h1 style={{ margin: "0 0 0.5rem", fontSize: "1.5rem", fontWeight: 600 }}>
          Access Denied
        </h1>
        <p style={{ margin: 0, color: "#c4b0b8", fontSize: "1rem" }}>
          You do not have permission to access this resource.
        </p>
      </div>
    </main>
  );
}
