import { expect, test } from "bun:test";
import { namespaceStorage, type SecondaryStorageApi } from "./redis";

test("secondary storage namespaces every operation by app", async () => {
  const seen: string[] = [];
  const storage: SecondaryStorageApi = {
    get: async (key) => (seen.push(`get:${key}`), null),
    set: async (key) => void seen.push(`set:${key}`),
    delete: async (key) => void seen.push(`delete:${key}`),
    increment: async (key) => (seen.push(`increment:${key}`), 1),
    ping: async () => undefined,
  };
  const app = namespaceStorage(storage, "authport:app_web");

  await app.get("session");
  await app.set("session", "value", 60);
  await app.delete("session");
  await app.increment("rate-limit", 60);

  expect(seen).toEqual([
    "get:authport:app_web:session",
    "set:authport:app_web:session",
    "delete:authport:app_web:session",
    "increment:authport:app_web:rate-limit",
  ]);
});
