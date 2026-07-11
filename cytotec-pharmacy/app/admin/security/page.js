import SecurityDashboardClient from "./SecurityDashboardClient";

export const metadata = {
  title: "Security Admin",
  robots: { index: false, follow: false }
};

export default function AdminSecurityPage() {
  return <SecurityDashboardClient />;
}
