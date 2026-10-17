// Container HEALTHCHECK (Checkov CKV_DOCKER_2; ECS uses the NLB check instead).
import http from "node:http";

const req = http.get({ host: "127.0.0.1", port: Number(process.env.PORT ?? 3000), path: "/healthz", timeout: 2000 }, (res) => {
  res.resume();
  process.exit(res.statusCode === 200 ? 0 : 1);
});
req.on("timeout", () => req.destroy());
req.on("error", () => process.exit(1));
