// Writes build-info.json from validated build args (plan D18). Values outside
// the enums become "unknown"; the image never contains its own Trivy result.
const OUTCOMES = new Set(["success", "failure", "skipped", "unknown"]);
const gate = (v) => (OUTCOMES.has(v) ? v : "unknown");
const sha = process.env.GIT_SHA ?? "";
const builtAt = process.env.BUILD_TIME ?? "";
const run = process.env.CI_RUN_ID ?? "";
const info = {
  commit: /^[0-9a-f]{40}$/.test(sha) ? sha : "local",
  builtAt: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(builtAt) ? builtAt : null,
  ciRunId: /^\d{1,20}$/.test(run) ? run : null,
  gates: {
    secrets: gate(process.env.GATE_SECRETS),
    sast: gate(process.env.GATE_SAST),
    sca: gate(process.env.GATE_SCA),
    app: gate(process.env.GATE_APP),
  },
  gatesEnforced: process.env.GATES_ENFORCED === "true",
};
process.stdout.write(JSON.stringify(info, null, 2) + "\n");
