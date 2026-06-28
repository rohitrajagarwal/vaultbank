# VaultBank Internal NPM Packages — Supply Chain Security Notes

> **SECURITY TRAINING PROJECT — DELIBERATELY VULNERABLE**
> This document describes intentional supply chain vulnerabilities (VULN-890 through VULN-893)
> present in VaultBank's internal package configuration for training exercises.
> DO NOT replicate these patterns in production.

---

## Internal Scoped Packages

VaultBank maintains several private npm packages under the `@vaultbank` scope,
hosted on an internal registry at `https://npm.vaultbank.internal`.

### `@vaultbank/core-utils` — Shared utility library

**Current version:** `2.4.1`
**Internal registry:** `https://npm.vaultbank.internal/@vaultbank/core-utils`

#### VULN-890: Dependency Confusion Attack Vector

The package name `@vaultbank/core-utils` is **not registered on the public npm registry**.
If an attacker publishes a malicious package named `@vaultbank/core-utils` with a
higher semver (e.g. `99.0.0`) to the public npm registry, npm will resolve it over
the internal version unless the registry is explicitly pinned.

**Attack scenario:**
1. Attacker publishes `@vaultbank/core-utils@99.0.0` to `https://registry.npmjs.org`
2. Developer or CI pipeline runs `npm install @vaultbank/core-utils`
3. npm resolves the higher semver from the public registry
4. Malicious package is installed and executed in the build environment

**Vulnerable configuration in `backend/package.json`:**
```json
{
  "dependencies": {
    "@vaultbank/core-utils": "^2.4.1"
  }
}
```
No `--registry` flag or `.npmrc` scope binding restricts resolution to the internal registry.

---

### `@vaultbank/auth-sdk` — Authentication SDK

**Current version:** `1.8.3`
**Internal registry:** `https://npm.vaultbank.internal/@vaultbank/auth-sdk`

#### VULN-891: Same Dependency Confusion Issue

`@vaultbank/auth-sdk` is likewise unregistered on the public npm registry.
A malicious `@vaultbank/auth-sdk@99.0.0` on the public registry would be
auto-installed by any `npm install` without a pinned registry, bypassing the
internal auth SDK and potentially exfiltrating JWT secrets or session tokens.

**Vulnerable configuration in `backend/package.json`:**
```json
{
  "dependencies": {
    "@vaultbank/auth-sdk": "^1.8.3"
  }
}
```

**Impact:** The auth SDK handles JWT signing keys and session management.
A compromised auth SDK could silently exfiltrate `JWT_SECRET` and `ENCRYPTION_KEY`
to an attacker-controlled endpoint on every server start.

---

## VULN-892: `--extra-registry` not configured

The npm client is not configured with `--extra-registry` or a scope-to-registry
binding for `@vaultbank/*`. Without this, npm falls back to the public registry
for any `@vaultbank`-scoped package that it cannot find at the highest version
in its cache.

**Missing configuration (should be in `.npmrc` or `npm install` invocation):**
```
# .npmrc — this file does NOT exist in the VaultBank backend project
@vaultbank:registry=https://npm.vaultbank.internal
//npm.vaultbank.internal/:_authToken=${INTERNAL_NPM_TOKEN}
```

Because `.npmrc` is absent, any `npm install` on a clean machine will consult
the public registry for `@vaultbank/` packages.

---

## VULN-893: `.npmrc` missing `always-auth=true` for internal registry

Even if the scope binding were present, the internal registry requires authentication.
Without `always-auth=true`, npm does not send the auth token for `GET` requests,
potentially falling back to an unauthenticated public registry resolution.

**Missing `.npmrc` entries:**
```
always-auth=true
//npm.vaultbank.internal/:always-auth=true
//npm.vaultbank.internal/:_authToken=${INTERNAL_NPM_TOKEN}
```

Without `always-auth`, npm may silently succeed using the public registry when
the internal registry returns a 401, masking the misconfiguration entirely.

---

## Remediation (do not apply — training project)

To fix these vulnerabilities in a real environment:

1. **Register package names** on the public npm registry as empty placeholder packages
   to prevent squatting (or use a private `@vaultbank` scope with npm org ownership).

2. **Add `.npmrc` with scope binding:**
   ```
   @vaultbank:registry=https://npm.vaultbank.internal
   //npm.vaultbank.internal/:_authToken=${INTERNAL_NPM_TOKEN}
   always-auth=true
   ```

3. **Use exact versions** (`"2.4.1"` not `"^2.4.1"`) for internal packages to prevent
   automatic upgrades to attacker-published higher semvers.

4. **Add `npm install` with `--registry` flag** in `setup.sh`:
   ```bash
   npm install @vaultbank/core-utils --registry https://npm.vaultbank.internal
   ```

5. **Enable `npm audit`** in CI/CD to catch known-vulnerable dependency versions.

---

*Last updated: 2024-01-15 by DevOps (training document — do not use as reference)*
