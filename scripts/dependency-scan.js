
import { readFile } from "node:fs/promises";

const API_URL = "https://cve.now/api/v1/check";

function runBunAuditFallback() {
  console.warn("\n[WARNING] cve.now tidak tersedia.");
  console.warn("[FALLBACK] Beralih ke Bun Audit...\n");

  const result = Bun.spawnSync(
    ["bun", "audit", "--audit-level=high"],
    {
      stdout: "inherit",
      stderr: "inherit",
    }
  );

  if (result.exitCode !== 0) {
    console.error("[BLOCKED] Bun Audit menemukan masalah atau gagal dijalankan.");
    process.exitCode = 1;
    return;
  }

  console.log("[PASS] Bun Audit selesai.");
}

async function main() {
  let lockfileContent;

  try {
    lockfileContent = await readFile("bun.lock", "utf8");
  } catch (error) {
    console.error("[ERROR] Tidak dapat membaca bun.lock:", error.message);
    process.exitCode = 2;
    return;
  }

  let result;

  // PRIMARY SCANNER: cve.now
  try {
    console.log("[INFO] Menggunakan cve.now sebagai primary scanner...");

    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
      body: JSON.stringify({
        lockfile_name: "bun.lock",
        lockfile_content: lockfileContent,
      }),
      signal: AbortSignal.timeout(15000),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    result = await response.json();

    if (
      !Array.isArray(result.affected) ||
      typeof result.checked !== "number"
    ) {
      throw new Error("Invalid API response schema");
    }

  } catch (error) {
    console.warn(`[WARNING] cve.now gagal: ${error.message}`);

    // FALLBACK SCANNER: Bun Audit
    runBunAuditFallback();
    return;
  }

  // EVALUATE PRIMARY SCANNER RESULT
  console.log(`[INFO] Packages checked: ${result.checked}`);
  console.log(`[INFO] Vulnerabilities: ${result.affected.length}`);

  let blocked = false;

  for (const item of result.affected) {
    const severity = String(item.rating ?? "unknown").toLowerCase();

    console.log(
      `${item.id} | ${item.package?.name} | ${item.package?.version} | ${severity}`
    );

    if (["critical", "high"].includes(severity)) {
      blocked = true;
    }
  }

  if (blocked) {
    console.error("[BLOCKED] High/Critical vulnerability ditemukan.");
    process.exitCode = 1;
    return;
  }

  if (result.affected.length > 0) {
    console.warn("[WARNING] Vulnerability ditemukan, tetapi tidak mencapai batas pemblokiran.");
  } else {
    console.log("[PASS] Tidak ditemukan vulnerability.");
  }
}

main().catch((error) => {
  console.error("[ERROR]", error.message);
  process.exitCode = 2;
});
