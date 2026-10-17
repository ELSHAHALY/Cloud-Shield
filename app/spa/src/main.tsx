import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { loadAuthBackend } from "./auth/backend";
import "./index.css";

void loadAuthBackend().then((backend) => {
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <App backend={backend} />
    </StrictMode>,
  );
});
