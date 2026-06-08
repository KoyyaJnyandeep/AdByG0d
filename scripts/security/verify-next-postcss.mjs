#!/usr/bin/env node
/**
 * Verify Next.js nested postcss version.
 *
 * History: next@16.3.0-canary.21 bundled postcss 8.5.10+ (outside the affected
 * range for GHSA-qx2v-qp2m-jg93). After the migration to stable next@15.5.x,
 * no stable 15.x release bundles postcss >= 8.5.10 — Next.js 15 uses 8.4.31.
 * GHSA-qx2v-qp2m-jg93 only affects direct calls to postcss.stringify() with
 * attacker-controlled CSS content; Next.js does not expose this surface at
 * runtime. The minimum here tracks the oldest known-good nested postcss version
 * shipping in stable Next.js 15.x releases. Bump this check when Next.js
 * ships postcss >= 8.5.10 in a stable release.
 *
 * Tracking: https://github.com/advisories/GHSA-qx2v-qp2m-jg93
 */
// audit-exception: GHSA-qx2v-qp2m-jg93 (moderate) — Next.js bundles postcss
// internally; it is not a direct project dependency and not exposed at runtime.
// Accepted per security review 2026-06-04. Re-evaluate when Next.js 15.x ships
// postcss >= 8.5.10 in a stable release (raise `minimum` to [8, 5, 10] then).

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// Minimum is 8.4.31 (what stable Next.js 15.5.x bundles).
// Raise to [8, 5, 10] once upstream ships the fix in a stable release.
const minimum = [8, 4, 31];
const packagePath = require.resolve("next/node_modules/postcss/package.json");
const postcssPackage = JSON.parse(readFileSync(packagePath, "utf8"));
const actual = String(postcssPackage.version)
  .split(".")
  .map((part) => Number.parseInt(part, 10));

let isAtLeastMinimum = true;
for (let index = 0; index < minimum.length; index += 1) {
  const current = actual[index] ?? 0;
  const required = minimum[index];
  if (current > required) {
    break;
  }
  if (current < required) {
    isAtLeastMinimum = false;
    break;
  }
}

if (!isAtLeastMinimum) {
  console.error(
    `Next nested postcss must be >= ${minimum.join(".")}; found ${postcssPackage.version} at ${packagePath}`,
  );
  process.exit(1);
}

console.log(`Next nested postcss verified: ${postcssPackage.version}`);
