const test = require("node:test");
const assert = require("node:assert");
const { resolveScopeIds, buildAppRegistrationBody } = require("../scripts/register-web-app");
const { REQUIRED_SCOPES } = require("../lib/scopes");

/** A slice of what GET /servicePrincipals?...&$select=oauth2PermissionScopes
 * actually returns — real names, made-up but GUID-shaped ids. */
const FAKE_GRAPH_SP_SCOPES = [
  { value: "Policy.Read.All", id: "11111111-1111-1111-1111-111111111111" },
  { value: "Directory.Read.All", id: "22222222-2222-2222-2222-222222222222" },
  { value: "User.Read", id: "33333333-3333-3333-3333-333333333333" },
];

test("resolveScopeIds resolves known scope names to their Graph-reported ids", () => {
  const { resourceAccess, unresolved } = resolveScopeIds(
    ["Policy.Read.All", "Directory.Read.All"],
    FAKE_GRAPH_SP_SCOPES
  );
  assert.deepStrictEqual(resourceAccess, [
    { id: "11111111-1111-1111-1111-111111111111", type: "Scope" },
    { id: "22222222-2222-2222-2222-222222222222", type: "Scope" },
  ]);
  assert.deepStrictEqual(unresolved, []);
});

test("resolveScopeIds reports unresolved names instead of guessing an id", () => {
  const { resourceAccess, unresolved } = resolveScopeIds(
    ["Policy.Read.All", "NotAReal.Scope"],
    FAKE_GRAPH_SP_SCOPES
  );
  assert.strictEqual(resourceAccess.length, 1);
  assert.deepStrictEqual(unresolved, ["NotAReal.Scope"]);
});

test("every REQUIRED_SCOPES entry lists at least one delegated Graph scope name", () => {
  // A guard against a future edit to lib/scopes.js silently adding an area
  // with no `any` list — resolveScopeIds would just skip it with no error.
  for (const req of REQUIRED_SCOPES) {
    assert.ok(Array.isArray(req.any) && req.any.length > 0, `${req.area} has no scopes`);
  }
});

test("buildAppRegistrationBody produces a public multi-tenant SPA registration", () => {
  const body = buildAppRegistrationBody({
    appName: "Entra Collect Web",
    redirectUri: "http://127.0.0.1:8080/",
    resourceAccess: [{ id: "11111111-1111-1111-1111-111111111111", type: "Scope" }],
  });
  assert.strictEqual(body.displayName, "Entra Collect Web");
  assert.strictEqual(body.signInAudience, "AzureADMultipleOrgs");
  assert.deepStrictEqual(body.spa.redirectUris, ["http://127.0.0.1:8080/"]);
  assert.strictEqual(body.requiredResourceAccess.length, 1);
  assert.strictEqual(
    body.requiredResourceAccess[0].resourceAppId,
    "00000003-0000-0000-c000-000000000000"
  );
  assert.deepStrictEqual(body.requiredResourceAccess[0].resourceAccess, [
    { id: "11111111-1111-1111-1111-111111111111", type: "Scope" },
  ]);
});
