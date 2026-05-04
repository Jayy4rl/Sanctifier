import { NextRequest } from "next/server";
import { spawn } from "child_process";
import path from "path";
import os from "os";
import { mkdtemp, rm, writeFile } from "fs/promises";
import { normalizeReport, transformReport } from "../../lib/transform";
import { recordScanAudit } from "../../lib/audit-trail";
import type { Finding } from "../../types";

export const runtime = "nodejs";

const REPO_ROOT = path.resolve(process.cwd(), "..");
const SUPPORTED_SOURCE_EXTENSIONS = new Set([".rs"]);
const MAX_FILE_SIZE_BYTES = 250 * 1024;
const EXECUTION_TIMEOUT_MS = 30000;
const RATE_LIMIT_REQUESTS_PER_MINUTE = (process.env.CI || process.env.NODE_ENV === "test") ? 1000 : 10;
const SANCTIFIER_BIN = process.env.SANCTIFIER_BIN?.trim() || "sanctifier";

const rateLimitMap = new Map<string, { count: number; resetTime: number }>();

function getClientIP(request: NextRequest): string {
  const xForwardedFor = request.headers.get("x-forwarded-for");
  if (xForwardedFor) {
    return xForwardedFor.split(",")[0].trim();
  }
  const xRealIP = request.headers.get("x-real-ip");
  if (xRealIP) {
    return xRealIP;
  }
  return "unknown";
}

function checkRateLimit(ip: string): { allowed: boolean; retryAfter: number } {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  
  if (!entry || now > entry.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + 60000 });
    return { allowed: true, retryAfter: 0 };
  }
  
  if (entry.count >= RATE_LIMIT_REQUESTS_PER_MINUTE) {
    const retryAfter = Math.ceil((entry.resetTime - now) / 1000);
    return { allowed: false, retryAfter };
  }
  
  entry.count++;
  return { allowed: true, retryAfter: 0 };
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap.entries()) {
    if (now > entry.resetTime) {
      rateLimitMap.delete(ip);
    }
  }
}, 60000);

type ProcessResult = {
  stdout: string;
  stderr: string;
  exitCode: number | null;
};

function runAnalyzeCommand(contractPath: string, timeoutMs: number): Promise<ProcessResult> {
  return new Promise((resolve, reject) => {
    const cliProcess = spawn(
      SANCTIFIER_BIN,
      ["analyze", "--format", "json", contractPath],
      {
      cwd: REPO_ROOT,
      env: { ...process.env, FORCE_COLOR: "0" },
      }
    );
    let stdout = "";
    let stderr = "";
    let timeoutId: NodeJS.Timeout | null = null;
    let completed = false;

    const cleanup = () => {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    };

    timeoutId = setTimeout(() => {
      if (!completed) {
        completed = true;
        cleanup();
        cliProcess.kill("SIGTERM");
        reject(new Error(`Analysis timed out after ${timeoutMs / 1000} seconds`));
      }
    }, timeoutMs);

    cliProcess.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    cliProcess.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    cliProcess.on("close", (exitCode) => {
      if (!completed) {
        completed = true;
        cleanup();
        resolve({ stdout, stderr, exitCode });
      }
    });

    cliProcess.on("error", (err) => {
      if (!completed) {
        completed = true;
        cleanup();
        reject(err);
      }
    });
  });
}

function looksLikeSorobanContract(source: string): boolean {
  return source.includes("soroban_sdk") || source.includes("soroban-sdk");
}

function parseMultipartSource(formData: FormData): Promise<{ fileName: string; source: string } | null> {
  const contract = formData.get("contract");

  if (!(contract instanceof File)) {
    return Promise.resolve(null);
  }

  if (contract.size > MAX_FILE_SIZE_BYTES) {
    throw new Error(`PAYLOAD_TOO_LARGE:${MAX_FILE_SIZE_BYTES}`);
  }

  const extension = path.extname(contract.name).toLowerCase();
  if (!SUPPORTED_SOURCE_EXTENSIONS.has(extension)) {
    throw new Error("UNSUPPORTED_EXTENSION");
  }

  return contract.arrayBuffer().then((buffer) => {
    const fileBuffer = Buffer.from(buffer);
    if (!isValidUtf8(fileBuffer)) {
      throw new Error("INVALID_UTF8");
    }

    return {
      fileName: sanitizeFileName(contract.name),
      source: fileBuffer.toString("utf8"),
    };
  });
}

function parseJsonResponse(body: string): unknown | null {
  if (!body.trim()) {
    return null;
  }

  try {
    return JSON.parse(body);
  } catch {
    return null;
  }
}

function isValidUtf8(buffer: Buffer): boolean {
  try {
    buffer.toString("utf8");
    return true;
  } catch {
    return false;
  }
}

function sanitizeFileName(name: string): string {
  const sanitized = name.replace(/[^a-zA-Z0-9._-]/g, "_");
  if (sanitized === "" || sanitized === "." || sanitized === "..") {
    return "contract.rs";
  }
  if (sanitized.startsWith(".") && sanitized.length === 1) {
    return "contract.rs";
  }
  return sanitized;
}

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const projectPath = searchParams.get("path") || ".";

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      const cliProcess = spawn(
        "cargo",
        ["run", "--quiet", "--bin", "sanctifier", "--", "analyze", projectPath],
        {
          cwd: REPO_ROOT,
          env: { ...process.env, FORCE_COLOR: "0" },
        }
      );

      const sendLog = (data: string) => {
        const lines = data.split("\n");
        for (const line of lines) {
          if (line.trim()) {
            controller.enqueue(encoder.encode(`data: ${JSON.stringify(line)}\n\n`));
          }
        }
      };

      cliProcess.stdout.on("data", (data) => {
        sendLog(data.toString());
      });

      cliProcess.stderr.on("data", (data) => {
        sendLog(`[DEBUG] ${data.toString()}`);
      });

      cliProcess.on("close", (code) => {
        controller.enqueue(
          encoder.encode(
            `data: ${JSON.stringify(
              `--- Analysis complete with exit code ${code} ---`
            )}\n\n`
          )
        );
        controller.close();
      });

      cliProcess.on("error", (err) => {
        controller.enqueue(
          encoder.encode(
            `data: ${JSON.stringify(`Error spawning process: ${err.message}`)}\n\n`
          )
        );
        controller.close();
      });
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
}

export async function POST(request: NextRequest) {
  const startMs = Date.now();
  const clientIP = getClientIP(request);

  // Audit-trail mutable state — updated as we learn more about the request.
  let auditFileName = "unknown";
  let auditFileSizeBytes = 0;
  let auditOutcomeCode = 500;
  let auditTotalFindings = 0;
  let auditHasCritical = false;
  let auditHasHigh = false;

  const rateLimitResult = checkRateLimit(clientIP);

  if (!rateLimitResult.allowed) {
    auditOutcomeCode = 429;
    recordScanAudit({
      timestamp: new Date(startMs).toISOString(),
      clientIp: clientIP,
      fileName: auditFileName,
      fileSizeBytes: auditFileSizeBytes,
      latencyMs: Date.now() - startMs,
      outcomeCode: auditOutcomeCode,
      totalFindings: 0,
      hasCritical: false,
      hasHigh: false,
    });
    return Response.json(
      { error: "Rate limit exceeded. Please try again later." },
      {
        status: 429,
        headers: { "Retry-After": rateLimitResult.retryAfter.toString() },
      }
    );
  }

  // Helper: records the outcome code so the finally-block audit has it.
  const respond = (body: unknown, init?: ResponseInit): Response => {
    auditOutcomeCode = (init as { status?: number } | undefined)?.status ?? 200;
    return Response.json(body, init);
  };

  let tempDir: string | null = null;

  try {
    tempDir = await mkdtemp(path.join(os.tmpdir(), "sanctifier-contract-"));
    const contentType = request.headers.get("content-type") ?? "";

    let sourcePayload: { fileName: string; source: string } | null = null;
    if (contentType.includes("application/json")) {
      const body = await request.json().catch(() => null);
      const source =
        body && typeof body === "object" && "source" in body && typeof body.source === "string"
          ? body.source
          : null;

      if (!source || !source.trim()) {
        return respond({ error: "Provide JSON body as { source: string }." }, { status: 400 });
      }

      if (Buffer.byteLength(source, "utf8") > MAX_FILE_SIZE_BYTES) {
        return respond(
          { error: `Source exceeds limit of ${MAX_FILE_SIZE_BYTES / 1024} KB.` },
          { status: 413 }
        );
      }

      sourcePayload = { fileName: "contract.rs", source };
    } else if (contentType.includes("multipart/form-data")) {
      const formData = await request.formData();
      sourcePayload = await parseMultipartSource(formData);
      if (!sourcePayload) {
        return respond({ error: "Attach a Rust .rs file in `contract` field." }, { status: 400 });
      }
    } else {
      return respond(
        { error: "Content-Type must be multipart/form-data or application/json." },
        { status: 400 }
      );
    }

    // Capture file metadata for the audit record now that we have a parsed payload.
    auditFileName = sourcePayload.fileName;
    auditFileSizeBytes = Buffer.byteLength(sourcePayload.source, "utf8");

    if (!looksLikeSorobanContract(sourcePayload.source)) {
      return respond(
        { error: "Source is not a Soroban contract (missing soroban-sdk import)." },
        { status: 422 }
      );
    }

    const contractPath = path.join(tempDir, sourcePayload.fileName);
    await writeFile(contractPath, sourcePayload.source, "utf8");

    const { stdout, stderr, exitCode } = await runAnalyzeCommand(contractPath, EXECUTION_TIMEOUT_MS);
    const report = parseJsonResponse(stdout);

    if (report) {
      const findings: Finding[] = transformReport(normalizeReport(report));
      auditTotalFindings = findings.length;
      auditHasCritical = findings.some((f) => f.severity === "critical");
      auditHasHigh = findings.some((f) => f.severity === "high");
      return respond(findings);
    }

    return respond(
      {
        error:
          stderr.trim() ||
          stdout.trim() ||
          `Contract analysis failed with exit code ${exitCode ?? "unknown"}.`,
      },
      { status: 500 }
    );
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("PAYLOAD_TOO_LARGE:")) {
      return respond(
        { error: `File size exceeds limit of ${MAX_FILE_SIZE_BYTES / 1024} KB.` },
        { status: 413 }
      );
    }
    if (error instanceof Error && error.message === "UNSUPPORTED_EXTENSION") {
      return respond(
        { error: "Only .rs contract source files are supported right now." },
        { status: 400 }
      );
    }
    if (error instanceof Error && error.message === "INVALID_UTF8") {
      return respond({ error: "File content is not valid UTF-8." }, { status: 400 });
    }
    if (error instanceof Error && error.message.includes("timed out")) {
      return respond(
        { error: "Analysis timed out. Please try with a smaller contract." },
        { status: 504 }
      );
    }
    return respond(
      {
        error:
          error instanceof Error ? error.message : "Contract analysis failed unexpectedly.",
      },
      { status: 500 }
    );
  } finally {
    recordScanAudit({
      timestamp: new Date(startMs).toISOString(),
      clientIp: clientIP,
      fileName: auditFileName,
      fileSizeBytes: auditFileSizeBytes,
      latencyMs: Date.now() - startMs,
      outcomeCode: auditOutcomeCode,
      totalFindings: auditTotalFindings,
      hasCritical: auditHasCritical,
      hasHigh: auditHasHigh,
    });
    if (tempDir) await rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }
}
