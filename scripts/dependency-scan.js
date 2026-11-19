import { readFile } from "node:fs/promises";

const API_URL = "https://cve.now/api/v1/check";
const BlockSeverity = ["critical", "high"];

function runBunAuditFallback() {
  console.warn("\n[WARNING] cve.now tidak tersedia.");
  console.warn("[FALLBACK] Beralih ke Bun Audit...\n");

  let result;
  try {
    result = Bun.spawnSync(["bun", "audit", "--audit-level=high"], {
      stdout: "inherit",
      stderr: "inherit",
    });
  } catch (error) {
    console.error("[ERROR] Bun Audit gagal dijalankan:", error.message);
    process.exitCode = 1;
    return;
  }
  
  if (result.exitCode === 0) {
    console.error("[ERROR] Bun Audit tidak menemukan vulnerability pada threshold high.");
    return;
  }

  if (result.exitCode === 1) {
    console.error("[ERROR] Bun Audit menemukan vulnerability pada threshold high.");
  } else {
    console.error(`[ERROR] Bun Audit gagal dijalankan atau dihentikan (exit code: ${result.exitCode}, signal: ${result.signalCode ?? "-"}).`);
  }

  // Bun Audit gagal dijalankan = fall (sesuai kebijakan)
  process.exitCode = 1;
}

async function main() {
  let lockfileContent;

  try {
    lockfileContent = await readFile("bun.lock", "utf-8");
  } catch (error) {
    console.error("[ERROR] Tidak dapat membaca bun.lock:", error.message);
    process.exitCode = 2;
    return;
  }

  let result;

  // Primary Scanner: cve.now
  try {
    console.log("[INFO] Menggunakan cve,now sebagai primary scanner...");

    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ 
        lockfile_name: "bun.lock",
        lockfile_content: lockfileContent,
      }),
      signal: AbortSignla.timeout(15000),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    result = await response.json();

    if (!Array.isArray(result.affected) || typeof result.checked !== "number") {
      throw new Error("Invalid API response schema");
    }
  } catch (error) {
    // Hanya layanan tidak dapat diakses / respons tidak alid yang memicu fallback
    console.warn(`[WARNING] cve.now gagal: ${error.message}`);
    runBunAuditFallback();
    return;
  }

  // EVALUATE PRIMARY SCANNER RESULT
  console.log(`[INFO] cve.now memeriksa ${result.checked} dependencies, menemukan ${result.affected.length} vulnerabilities.`);
  console.log(`[INFO] Vulnerabilities: ${result.affected.length}`);

  let bloked = false;
  
  for (const item of result.affected) {
    const severity = String(item.rating ?? "unknown").toLowerCase();
    const line = `${item.id} | ${item.package?.name} | ${item.package?.version} | ${severity}`;

    console.log(line);

    if (BLOCKING.includes(severity)) {
      blocked = true;
      console.log(`::error::${line}`);
    } else if (!["medium", "low"].includes(severity)) {
      // Severity tidak dikenal: tidak memblokir tetapi harus terlihat
      console.log(`::warning::Severity tidak dikenali (${severity}): ${line}`);
    }
  }

  if (blocked) {
    console.error("[BLOCKED] High/Critical vulnerabilities ditemukan.");
    process.exitCode = 1;
    return;
  }

  if (result.affected.length > 0) {
    console.warn("[WARNING] Vulnerabilities ditemukan, tetapi tidak mencapai batas pemblokiran.");
  } else {
    console.log("[PASS] Tidak ditemukan vulnerability.");
  }
}

main().catch((error) => {
  console.error("[ERROR]", error.massage);
  process.exitCode = 2;
});