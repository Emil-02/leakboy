import { describe, expect, it } from "vitest";
import { HttpClient, isPrivateAddress } from "../src/http.js";

const strict = () =>
  new HttpClient({
    allowPrivateNetworks: false,
    standardPortsOnly: true,
    timeoutMs: 2000,
    maxRequests: 5,
    maxResponseBytes: 1024,
    maxTotalBytes: 4096,
  });

describe("SSRF guard", () => {
  it.each(["127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1"])(
    "%s is private",
    (ip) => expect(isPrivateAddress(ip)).toBe(true),
  );

  it.each(["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"])("%s is public", (ip) => expect(isPrivateAddress(ip)).toBe(false));

  it("rejects private, local and odd targets before connecting", async () => {
    const http = strict();
    for (const url of [
      "http://127.0.0.1/",
      "http://[::1]/",
      "http://localhost:3000/",
      "http://169.254.169.254/latest/meta-data/",
      "http://metadata.internal/",
      "file:///etc/passwd",
      "https://user:pass@example.com/",
      "https://example.com:8443/",
    ]) {
      await expect(http.request(url)).rejects.toThrow(/private|local|only|credentials/);
    }
    expect(http.stats.requests).toBe(0);
    await http.close();
  });

  it("blocks hostnames that resolve to private addresses (DNS rebinding)", async () => {
    const http = strict();
    // localtest.me and its subdomains resolve to 127.0.0.1
    await expect(http.request("http://leakboy.localtest.me/")).rejects.toThrow(/private|ENOTFOUND|EAI_AGAIN/);
    await http.close();
  });
});

describe("redirects", () => {
  it("re-validates every redirect target", async () => {
    const { createServer } = await import("node:http");
    const server = createServer((_req, res) => {
      res.writeHead(302, { location: "http://user:pass@127.0.0.1/" });
      res.end();
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    const http = new HttpClient({
      allowPrivateNetworks: true,
      standardPortsOnly: false,
      timeoutMs: 2000,
      maxRequests: 5,
      maxResponseBytes: 1024,
      maxTotalBytes: 4096,
    });
    await expect(http.request(`http://127.0.0.1:${port}/`)).rejects.toThrow(/credentials/);
    expect(http.stats.requests).toBe(1);
    await http.close();
    server.close();
  });

  it("stops at the request budget", async () => {
    const http = new HttpClient({
      allowPrivateNetworks: true,
      standardPortsOnly: false,
      timeoutMs: 2000,
      maxRequests: 0,
      maxResponseBytes: 1024,
      maxTotalBytes: 4096,
    });
    await expect(http.request("http://127.0.0.1:9/")).rejects.toThrow(/budget/);
    await http.close();
  });
});
