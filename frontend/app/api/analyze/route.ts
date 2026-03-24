import { NextRequest } from "next/server";
import { spawn } from "child_process";
import path from "path";
import os from "os";
import { mkdtemp, rm, writeFile } from "fs/promises";

export const runtime = "nodejs";

const REPO_ROOT = path.resolve(process.cwd(), "..");
const SUPPORTED_SOURCE_EXTENSIONS = new Set([".rs"]);

type ProcessResult = {
  stdout: string;
  stderr: string;
  exitCode: number | null;
};

function runAnalyzeCommand(args: string[]): Promise<ProcessResult> {
  return new Promise((resolve, reject) => {
    const cliProcess = spawn("cargo", args, {
      cwd: REPO_ROOT,
      env: { ...process.env, FORCE_COLOR: "0" },
    });
    let stdout = "";
    let stderr = "";

    cliProcess.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    cliProcess.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    cliProcess.on("close", (exitCode) => {
      resolve({ stdout, stderr, exitCode });
    });

    cliProcess.on("error", reject);
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
  const formData = await request.formData();
  const contract = formData.get("contract");

  if (!(contract instanceof File)) {
    return Response.json({ error: "Attach a Rust contract source file." }, { status: 400 });
  }

  const extension = path.extname(contract.name).toLowerCase();
  if (!SUPPORTED_SOURCE_EXTENSIONS.has(extension)) {
    return Response.json(
      { error: "Only .rs contract source files are supported right now." },
      { status: 400 }
    );
  }

  const tempDir = await mkdtemp(path.join(os.tmpdir(), "sanctifier-contract-"));
  const fileName = contract.name.replace(/[^a-zA-Z0-9._-]/g, "_") || `contract${extension}`;
  const contractPath = path.join(tempDir, fileName);

  try {
    const fileBuffer = Buffer.from(await contract.arrayBuffer());
    await writeFile(contractPath, fileBuffer);

    const { stdout, stderr, exitCode } = await runAnalyzeCommand([
      "run",
      "--quiet",
      "--bin",
      "sanctifier",
      "--",
      "analyze",
      contractPath,
      "--format",
      "json",
    ]);
    const report = parseJsonResponse(stdout);

    if (report) {
      return Response.json(report);
    }

    return Response.json(
      {
        error:
          stderr.trim() ||
          stdout.trim() ||
          `Contract analysis failed with exit code ${exitCode ?? "unknown"}.`,
      },
      { status: 500 }
    );
  } catch (error) {
    return Response.json(
      {
        error:
          error instanceof Error ? error.message : "Contract analysis failed unexpectedly.",
      },
      { status: 500 }
    );
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}
