import type { ExecutionRecord, ProofBundleReceipt } from "@openrouter/spawn-shared";
import type { VerifyResult } from "./execution-witness.js";

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";
import { getErrorMessage, isExecutionRecord, isProofBundleReceipt, tryCatch } from "@openrouter/spawn-shared";
import { applyAttestationVerification, SIGNATURE_FILE_NAME, WITNESS_FILE_NAME } from "./attestation.js";
import { getExecutionRunDir, verifyExecutionDirectory } from "./execution-witness.js";
import { applyTrustVerification } from "./trust.js";

const BUNDLE_SCHEMA_VERSION = "spawn-proof-bundle/v1";
const BUNDLE_FORMAT_VERSION = "1";
const CANONICALIZATION_VERSION = "1";
const BUNDLE_ROOT_DIRECTORY = "spawn-bundle";
const BUNDLE_FILE_NAME = "spawn-proof-bundle.tar.gz";
const BUNDLE_RECEIPT_NAME = "bundle.json";
const REQUIRED_BUNDLE_FILES = [
  "envelope.json",
  "declare.json",
  "environment.json",
  "steps.jsonl",
  "artifacts.json",
  "result.json",
  "manifest.lock.json",
  "checksums.txt",
] as const;
const OPTIONAL_ATTESTATION_FILES = [
  WITNESS_FILE_NAME,
  SIGNATURE_FILE_NAME,
] as const;

interface BundleEntry {
  path: string;
  bytes: Buffer;
}

export interface BundleExportResult {
  bundlePath: string;
  bundleDigest: string;
  recordDigest: string;
  runId: string;
  fileCount: number;
}

function sha256OfBuffer(buffer: Uint8Array): string {
  return createHash("sha256").update(buffer).digest("hex");
}

function isZeroBlock(block: Buffer): boolean {
  for (const byte of block) {
    if (byte !== 0) {
      return false;
    }
  }
  return true;
}

function readNullTerminatedAscii(buffer: Buffer, start: number, length: number): string {
  const slice = buffer.subarray(start, start + length);
  const nullIndex = slice.indexOf(0);
  return slice.subarray(0, nullIndex >= 0 ? nullIndex : slice.length).toString("utf-8");
}

function parseOctal(buffer: Buffer, start: number, length: number): number {
  const raw = readNullTerminatedAscii(buffer, start, length).trim().replace(/\0+$/, "").trim();
  return raw ? Number.parseInt(raw, 8) : 0;
}

function writeStringField(target: Buffer, offset: number, length: number, value: string): void {
  const valueBuffer = Buffer.from(value, "utf-8");
  valueBuffer.copy(target, offset, 0, Math.min(valueBuffer.length, length));
}

function writeOctalField(target: Buffer, offset: number, length: number, value: number): void {
  const octal = value.toString(8).padStart(length - 1, "0");
  writeStringField(target, offset, length - 1, octal);
  target[offset + length - 1] = 0;
}

function buildTarHeader(path: string, size: number): Buffer {
  const header = Buffer.alloc(512, 0);
  writeStringField(header, 0, 100, path);
  writeOctalField(header, 100, 8, 0o644);
  writeOctalField(header, 108, 8, 0);
  writeOctalField(header, 116, 8, 0);
  writeOctalField(header, 124, 12, size);
  writeOctalField(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = "0".charCodeAt(0);
  writeStringField(header, 257, 6, "ustar");
  writeStringField(header, 263, 2, "00");

  let checksum = 0;
  for (const byte of header) {
    checksum += byte;
  }
  const checksumField = checksum.toString(8).padStart(6, "0");
  writeStringField(header, 148, 6, checksumField);
  header[154] = 0;
  header[155] = 0x20;
  return header;
}

function createDeterministicTar(entries: BundleEntry[]): Buffer {
  const parts: Buffer[] = [];
  for (const entry of entries.sort((a, b) => a.path.localeCompare(b.path))) {
    parts.push(buildTarHeader(entry.path, entry.bytes.length));
    parts.push(entry.bytes);
    const remainder = entry.bytes.length % 512;
    if (remainder > 0) {
      parts.push(Buffer.alloc(512 - remainder, 0));
    }
  }
  parts.push(Buffer.alloc(1024, 0));
  return Buffer.concat(parts);
}

function gzipDeterministic(buffer: Buffer): Buffer {
  const gzipped = gzipSync(buffer, {
    mtime: 0,
  });
  if (gzipped.length > 9) {
    gzipped[9] = 255;
  }
  return gzipped;
}

function parseTarEntries(buffer: Buffer): BundleEntry[] {
  const entries: BundleEntry[] = [];
  let offset = 0;

  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512);
    if (isZeroBlock(header)) {
      break;
    }

    const name = readNullTerminatedAscii(header, 0, 100);
    const prefix = readNullTerminatedAscii(header, 345, 155);
    const path = prefix ? `${prefix}/${name}` : name;
    const size = parseOctal(header, 124, 12);
    const typeFlag = header[156] === 0 ? "0" : String.fromCharCode(header[156]);
    offset += 512;

    if (typeFlag !== "0") {
      offset += Math.ceil(size / 512) * 512;
      continue;
    }

    const bytes = buffer.subarray(offset, offset + size);
    entries.push({
      path,
      bytes: Buffer.from(bytes),
    });
    offset += Math.ceil(size / 512) * 512;
  }

  return entries;
}

function assertSafeBundlePath(path: string): void {
  if (!path || path.startsWith("/") || path.startsWith("\\") || path.includes("..")) {
    throw new Error(`Unsafe bundle path: ${path}`);
  }
  if (!path.startsWith(`${BUNDLE_ROOT_DIRECTORY}/`)) {
    throw new Error(`Bundle entry outside root directory: ${path}`);
  }
}

function loadExecutionRecord(runDir: string): ExecutionRecord {
  const envelopePath = join(runDir, "envelope.json");
  const loadResult = tryCatch(() => JSON.parse(readFileSync(envelopePath, "utf-8")));
  if (!loadResult.ok || !isExecutionRecord(loadResult.data)) {
    throw new Error(`Invalid execution record at ${envelopePath}`);
  }
  return loadResult.data;
}

function collectBundlePaths(_runDir: string, record: ExecutionRecord): string[] {
  const included = new Set<string>(REQUIRED_BUNDLE_FILES);
  for (const artifact of record.artifacts) {
    included.add(artifact.path);
  }
  for (const attestationFile of OPTIONAL_ATTESTATION_FILES) {
    included.add(attestationFile);
  }
  return Array.from(included).sort((a, b) => a.localeCompare(b));
}

function buildBundleReceipt(record: ExecutionRecord): ProofBundleReceipt {
  if (!record.result) {
    throw new Error(`Run ${record.run_id} is not finalized and cannot be bundled`);
  }
  return {
    schema_version: BUNDLE_SCHEMA_VERSION,
    bundle_format_version: BUNDLE_FORMAT_VERSION,
    canonicalization_version: CANONICALIZATION_VERSION,
    root_directory: BUNDLE_ROOT_DIRECTORY,
    run_id: record.run_id,
    record_digest: record.result.final_digest,
    record_digest_algorithm: "sha256",
    bundle_digest_algorithm: "sha256",
    built_at: record.timestamps.ended_at ?? record.timestamps.started_at,
  };
}

function writeExtractedEntry(targetRoot: string, entry: BundleEntry): void {
  assertSafeBundlePath(entry.path);
  const filePath = resolve(join(targetRoot, entry.path));
  const normalizedTargetRoot = resolve(targetRoot).replaceAll("\\", "/");
  const normalizedFilePath = filePath.replaceAll("\\", "/");
  if (normalizedFilePath !== normalizedTargetRoot && !normalizedFilePath.startsWith(`${normalizedTargetRoot}/`)) {
    throw new Error(`Bundle entry escaped extraction root: ${entry.path}`);
  }
  mkdirSync(dirname(filePath), {
    recursive: true,
  });
  writeFileSync(filePath, entry.bytes);
}

function verifyExtractedBundle(
  rootDir: string,
  bundleDigest: string,
  bundleReceipt: ProofBundleReceipt | null,
): VerifyResult {
  const result = applyTrustVerification(
    rootDir,
    applyAttestationVerification(rootDir, verifyExecutionDirectory(rootDir, bundleReceipt?.run_id ?? "")),
  );
  const recordDigestMatches = bundleReceipt ? result.digest === bundleReceipt.record_digest : false;
  if (bundleReceipt && !recordDigestMatches) {
    result.errors.push("Bundle record digest does not match extracted proof record");
  }
  result.transport = {
    kind: "bundle",
    ok: bundleReceipt !== null && recordDigestMatches,
    bundle_digest: bundleDigest,
    record_digest: result.digest,
    record_digest_matches: recordDigestMatches,
    bundle_manifest: bundleReceipt !== null,
  };
  result.ok = result.ok && result.transport.ok;
  result.verified = result.ok;
  return result;
}

export function exportExecutionBundle(runId: string, outputPath?: string): BundleExportResult {
  const runDir = getExecutionRunDir(runId);
  if (!existsSync(runDir)) {
    throw new Error(`Run directory not found: ${runDir}`);
  }

  const record = loadExecutionRecord(runDir);
  const bundleReceipt = buildBundleReceipt(record);
  const bundlePath = outputPath ? resolve(outputPath) : join(runDir, BUNDLE_FILE_NAME);
  const entries: BundleEntry[] = [
    {
      path: `${BUNDLE_ROOT_DIRECTORY}/${BUNDLE_RECEIPT_NAME}`,
      bytes: Buffer.from(JSON.stringify(bundleReceipt, null, 2) + "\n", "utf-8"),
    },
  ];

  for (const relativePath of collectBundlePaths(runDir, record)) {
    const filePath = join(runDir, relativePath);
    const optionalAttestation = OPTIONAL_ATTESTATION_FILES.some((entry) => entry === relativePath);
    if (!existsSync(filePath)) {
      if (optionalAttestation) {
        continue;
      }
      throw new Error(`Cannot bundle missing proof file: ${relativePath}`);
    }
    if (!statSync(filePath).isFile()) {
      throw new Error(`Cannot bundle missing proof file: ${relativePath}`);
    }
    entries.push({
      path: `${BUNDLE_ROOT_DIRECTORY}/${relativePath.replaceAll("\\", "/")}`,
      bytes: readFileSync(filePath),
    });
  }

  const archiveBytes = gzipDeterministic(createDeterministicTar(entries));
  mkdirSync(dirname(bundlePath), {
    recursive: true,
  });
  writeFileSync(bundlePath, archiveBytes);

  return {
    bundlePath,
    bundleDigest: sha256OfBuffer(archiveBytes),
    recordDigest: bundleReceipt.record_digest,
    runId: record.run_id,
    fileCount: entries.length,
  };
}

export function verifyExecutionSource(source: string): VerifyResult {
  const resolvedSource = resolve(source);
  if (!existsSync(resolvedSource)) {
    return applyTrustVerification(
      getExecutionRunDir(source),
      applyAttestationVerification(
        getExecutionRunDir(source),
        verifyExecutionDirectory(getExecutionRunDir(source), source),
      ),
    );
  }

  const stats = statSync(resolvedSource);
  if (stats.isDirectory()) {
    const bundleReceiptPath = join(resolvedSource, BUNDLE_RECEIPT_NAME);
    if (!existsSync(bundleReceiptPath)) {
      return applyTrustVerification(
        resolvedSource,
        applyAttestationVerification(resolvedSource, verifyExecutionDirectory(resolvedSource)),
      );
    }

    const bundleLoadResult = tryCatch(() => JSON.parse(readFileSync(bundleReceiptPath, "utf-8")));
    const bundleReceipt =
      bundleLoadResult.ok && isProofBundleReceipt(bundleLoadResult.data) ? bundleLoadResult.data : null;
    const result = applyTrustVerification(
      resolvedSource,
      applyAttestationVerification(
        resolvedSource,
        verifyExecutionDirectory(resolvedSource, bundleReceipt?.run_id ?? ""),
      ),
    );
    const recordDigestMatches = bundleReceipt ? result.digest === bundleReceipt.record_digest : false;
    if (!bundleReceipt) {
      result.errors.push("Invalid bundle.json structure");
    } else if (!recordDigestMatches) {
      result.errors.push("Bundle record digest does not match extracted proof record");
    }
    result.transport = {
      kind: "bundle",
      ok: bundleReceipt !== null && recordDigestMatches,
      record_digest: result.digest,
      record_digest_matches: recordDigestMatches,
      bundle_manifest: bundleReceipt !== null,
    };
    result.ok = result.ok && result.transport.ok;
    result.verified = result.ok;
    return result;
  }

  const bundleDigest = sha256OfBuffer(readFileSync(resolvedSource));
  const extractionRoot = mkdtempSync(join(tmpdir(), "spawn-bundle-"));
  const verificationResult = tryCatch(() => {
    const entries = parseTarEntries(gunzipSync(readFileSync(resolvedSource)));
    for (const entry of entries) {
      writeExtractedEntry(extractionRoot, entry);
    }

    const bundleRoot = join(extractionRoot, BUNDLE_ROOT_DIRECTORY);
    const bundleReceiptPath = join(bundleRoot, BUNDLE_RECEIPT_NAME);
    const bundleLoadResult = tryCatch(() => JSON.parse(readFileSync(bundleReceiptPath, "utf-8")));
    if (!bundleLoadResult.ok || !isProofBundleReceipt(bundleLoadResult.data)) {
      const failed = verifyExecutionDirectory(bundleRoot);
      failed.errors.push(
        !bundleLoadResult.ok
          ? `Failed to read bundle.json: ${getErrorMessage(bundleLoadResult.error)}`
          : "Invalid bundle.json structure",
      );
      failed.transport = {
        kind: "bundle",
        ok: false,
        bundle_digest: bundleDigest,
        bundle_manifest: false,
      };
      failed.ok = false;
      failed.verified = false;
      return failed;
    }

    return verifyExtractedBundle(bundleRoot, bundleDigest, bundleLoadResult.data);
  });
  rmSync(extractionRoot, {
    recursive: true,
    force: true,
  });
  if (verificationResult.ok) {
    return verificationResult.data;
  }
  return {
    ok: false,
    verified: false,
    runId: "",
    runDir: resolvedSource,
    checkedFiles: [],
    errors: [
      `Failed to inspect bundle: ${getErrorMessage(verificationResult.error)}`,
    ],
    integrity: {
      ok: false,
      schemas: false,
      artifacts: false,
      checksums: false,
      record_digest: false,
    },
    capture: {
      ok: false,
      interactive_transcript: "absent",
      expected_by_policy: false,
      artifact_present: false,
      mode: "unknown",
    },
    policy: {
      ok: false,
      transcript_policy: "optional",
      attestation_policy: "optional",
      trust_policy: "any-valid",
      required_artifacts: [],
      missing_artifacts: [],
      trusted_signers: [],
    },
    attestation: {
      ok: true,
      state: "none",
      subject: "record_digest",
    },
    trust: {
      ok: true,
      state: "none",
    },
    transport: {
      kind: "bundle",
      ok: false,
      bundle_digest: bundleDigest,
      bundle_manifest: false,
    },
  };
}
