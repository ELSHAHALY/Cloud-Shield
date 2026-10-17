import { useCallback, useEffect, useMemo, useState } from "react";
import { BrowserRouter, Route, Routes, useNavigate } from "react-router";
import { createApiClient, type ApiClient } from "./api/client";
import type { Me } from "./api/types";
import type { AuthBackend } from "./auth/backend";
import { makeCan, SessionContext, type Session } from "./auth/session";
import { Layout } from "./components/Layout";
import { RoleGuard } from "./components/RoleGuard";
import { ErrorBox, Loading } from "./components/ui";
import { GrcHub } from "./grc/GrcHub";
import { MatrixPage } from "./grc/MatrixPage";
import { AuditPage } from "./portal/AuditPage";
import { DocumentPage } from "./portal/DocumentPage";
import { DocumentsPage } from "./portal/DocumentsPage";
import { HomePage } from "./portal/HomePage";
import { OnboardingPage } from "./portal/OnboardingPage";
import { IncidentPage } from "./soc/IncidentPage";
import { SocDashboard } from "./soc/SocDashboard";

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<HomePage />} />
      <Route path="/documents" element={<RoleGuard need="doc:read"><DocumentsPage /></RoleGuard>} />
      <Route path="/documents/:docId" element={<RoleGuard need="doc:read"><DocumentPage /></RoleGuard>} />
      <Route path="/audit" element={<RoleGuard need="audit:read"><AuditPage /></RoleGuard>} />
      <Route path="/onboarding" element={<RoleGuard need="agreement:read"><OnboardingPage /></RoleGuard>} />
      <Route path="/grc" element={<RoleGuard need="grc:read"><GrcHub /></RoleGuard>} />
      <Route path="/grc/matrix" element={<RoleGuard need="grc:read"><MatrixPage /></RoleGuard>} />
      <Route path="/soc" element={<RoleGuard need="soc:read"><SocDashboard /></RoleGuard>} />
      <Route path="/soc/audit" element={<RoleGuard need="soc:read"><AuditPage path="/soc/audit" title="Platform audit (_platform)" /></RoleGuard>} />
      <Route path="/soc/incidents/:incidentId" element={<RoleGuard need="soc:read"><IncidentPage /></RoleGuard>} />
      <Route path="*" element={<p className="text-sm">Page not found.</p>} />
    </Routes>
  );
}

function Shell({ backend }: { backend: AuthBackend }) {
  const navigate = useNavigate();
  const [me, setMe] = useState<Me | null>(null);
  const [state, setState] = useState<"loading" | "signed-out" | "ready" | "error">("loading");
  const [error, setError] = useState<unknown>(null);

  const api: ApiClient = useMemo(
    () =>
      createApiClient({
        getToken: (force) => backend.getIdToken(force),
        onUnauthenticated: () => {
          setMe(null);
          setState("signed-out");
        },
        onAgreementRequired: () => navigate("/onboarding"),
      }),
    [backend, navigate],
  );

  const [generation, setGeneration] = useState(0);

  useEffect(() => {
    let live = true;
    backend
      .getIdToken()
      .then((token) => {
        if (!token) return null;
        return api.get<Me>("/me");
      })
      .then((m) => {
        if (!live) return;
        setMe(m);
        setState(m ? "ready" : "signed-out");
      })
      .catch((e: unknown) => {
        if (!live) return;
        setError(e);
        setState("error");
      });
    return () => {
      live = false;
    };
  }, [api, backend, generation]);

  const start = useCallback(() => {
    setState("loading");
    setGeneration((g) => g + 1);
  }, []);

  const session: Session | null = useMemo(
    () =>
      me
        ? {
            me,
            api,
            backend,
            can: makeCan(me),
            signOut: async () => {
              await backend.signOut();
              setMe(null);
              setState("signed-out");
              navigate("/");
            },
          }
        : null,
    [me, api, backend, navigate],
  );

  if (state === "loading") return <div className="p-8"><Loading /></div>;
  if (state === "error") return <div className="p-8"><ErrorBox error={error} /></div>;
  if (state === "signed-out" || !session) {
    const LoginForm = backend.LoginForm;
    return (
      <div className="mx-auto mt-16 max-w-md space-y-4 rounded-lg border border-slate-200 bg-white p-6 shadow-sm">
        <h1 className="text-lg font-semibold">Sign in to CloudShield</h1>
        <LoginForm onSignedIn={start} />
      </div>
    );
  }
  return (
    <SessionContext.Provider value={session}>
      <Layout>
        <AppRoutes />
      </Layout>
    </SessionContext.Provider>
  );
}

export function App({ backend }: { backend: AuthBackend }) {
  return (
    <BrowserRouter>
      <Shell backend={backend} />
    </BrowserRouter>
  );
}
