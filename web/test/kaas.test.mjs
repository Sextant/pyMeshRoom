import assert from "node:assert/strict";
import { test } from "node:test";
import { kaasEndpoints, webLoginMessage } from "../src/kaas.js";

const pick = ({ ticket, ws, secure }) => ({ ticket, ws, secure });

test("the pyMeshRoom URL, however it's typed", () => {
  const want = { ticket: "https://mesh.example.com/api/v1/web/ticket", ws: "wss://mesh.example.com/api/v1/kaas", secure: true };
  for (const u of ["https://mesh.example.com", "mesh.example.com", "https://mesh.example.com/", " https://mesh.example.com/api/v1/kaas ",
    "wss://mesh.example.com/api/v1/kaas"])
    assert.deepEqual(pick(kaasEndpoints(u)), want, u);
  const proxied = kaasEndpoints("https://proxy.example.com:8443/meshroom/");
  assert.equal(proxied.login, "https://proxy.example.com:8443/meshroom/api/v1/web/login");
  assert.equal(proxied.host, "proxy.example.com:8443");
  assert.deepEqual(pick(proxied), {
    ticket: "https://proxy.example.com:8443/meshroom/api/v1/web/ticket", ws: "wss://proxy.example.com:8443/meshroom/api/v1/kaas", secure: true,
  });
  assert.equal(kaasEndpoints("http://10.0.0.5:8081").ws, "ws://10.0.0.5:8081/api/v1/kaas");
  assert.throws(() => kaasEndpoints(""));
  assert.throws(() => kaasEndpoints("ftp://x"));
});

test("what a web login signs (the server checks exactly this)", () => {
  assert.equal(new TextDecoder().decode(webLoginMessage("mesh.example.com", "wc_abc", "ab".repeat(32))),
    "meshcore-web login v1\nmesh.example.com\nwc_abc\n" + "ab".repeat(32));
});
