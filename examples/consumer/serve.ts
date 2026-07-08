import index from "./index.html";

// Serves the example app on the origin AuthPort trusts for `authport-web`
// (http://localhost:3001 in apps.yaml). Bun bundles app.ts + the SDK for the browser.
const server = Bun.serve({
  port: 3001,
  routes: { "/": index },
  development: { hmr: true, console: true },
});

console.log(`Consumer app running at ${server.url}`);
