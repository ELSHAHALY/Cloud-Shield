import http from "node:http";
import { installShutdown } from "../src/server";

describe("graceful shutdown", () => {
  it("closes within 1.5 s even with an idle keep-alive connection", async () => {
    const server = http.createServer((_req, res) => res.end("ok"));
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const port = (server.address() as { port: number }).port;
    const agent = new http.Agent({ keepAlive: true });
    await new Promise<void>((resolve) => http.get({ port, agent }, (res) => res.resume().on("end", resolve)));
    const started = Date.now();
    const exited = new Promise<number>((resolve) => installShutdown(server, resolve, 1500)());
    expect(await exited).toBe(0);
    expect(Date.now() - started).toBeLessThan(1600);
    agent.destroy();
  });

  it("force-exits at the grace deadline when a request hangs", async () => {
    const server = http.createServer(() => undefined);
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const port = (server.address() as { port: number }).port;
    const req = http.get({ port });
    req.on("error", () => undefined);
    await new Promise((r) => setTimeout(r, 50));
    const started = Date.now();
    const code = await new Promise<number>((resolve) => installShutdown(server, resolve, 300)());
    expect(code).toBe(0);
    expect(Date.now() - started).toBeLessThan(1500);
    req.destroy();
    server.closeAllConnections();
  });
});
