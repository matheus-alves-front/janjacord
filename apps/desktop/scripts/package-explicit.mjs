#!/usr/bin/env node

console.error("Generic desktop packaging is disabled. Use dist:linux for guarded Linux packaging, dist:win:test for an explicitly unsigned Windows QA artifact, or dist:win:release for fail-closed signed Windows packaging.");
process.exit(2);
