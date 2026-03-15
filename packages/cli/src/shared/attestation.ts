import type { ExecutionRecord, SignatureReceipt, WitnessReceipt } from "@openrouter/spawn-shared";
import type { VerifyResult } from "./execution-witness.js";

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  getErrorMessage,
  isExecutionRecord,
  isSignatureReceipt,
  isWitnessReceipt,
  tryCatch,
} from "@openrouter/spawn-shared";
import {
  getAttestationVerifierKeyPath,
  getDefaultAttestationPrivateKeyPath,
  getDefaultAttestationPublicKeyPath,
} from "./paths.js";

const WITNESS_FILE_NAME = "witness.json";
const SIGNATURE_FILE_NAME = "signature.json";
const WITNESS_SCHEMA_VERSION = "spawn-attestation/v1";
const SIGNATURE_SCHEMA_VERSION = "spawn-signature/v1";
const CANONICALIZATION_VERSION = "1";
const DEFAULT_VERIFIER = "local-key-registry/v1";

interface AttestationKeyMaterial {
  keyId: string;
  privateKeyPath: string;
  publicKeyPath: string;
  verifierKeyPath: string;
}

interface AttestationResult {
  witnessPath: string;
  signaturePath: string;
  keyId: string;
  recordDigest: string;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  const entries = Object.entries(value).sort(([a], [b]) => a.localeCompare(b));
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableStringify(item)}`).join(",")}}`;
}

function sha256OfString(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

function writeJson(filePath: string, data: unknown): void {
  mkdirSync(dirname(filePath), {
    recursive: true,
  });
  writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n", {
    mode: 0o600,
  });
}

function getIdentityHint(): string | undefined {
  const username = process.env.USER || process.env.USERNAME;
  const hostname = process.env.HOSTNAME || process.env.COMPUTERNAME;
  if (!username && !hostname) {
    return undefined;
  }
  if (username && hostname) {
    return `${username}@${hostname}`;
  }
  return username || hostname;
}

function ensureDefaultAttestationKey(): AttestationKeyMaterial {
  const privateKeyPath = getDefaultAttestationPrivateKeyPath();
  const publicKeyPath = getDefaultAttestationPublicKeyPath();

  mkdirSync(dirname(privateKeyPath), {
    recursive: true,
  });
  mkdirSync(dirname(getAttestationVerifierKeyPath("placeholder")), {
    recursive: true,
  });

  if (!existsSync(privateKeyPath) || !existsSync(publicKeyPath)) {
    const generated = generateKeyPairSync("ed25519");
    const privatePem = generated.privateKey.export({
      format: "pem",
      type: "pkcs8",
    });
    const publicPem = generated.publicKey.export({
      format: "pem",
      type: "spki",
    });
    writeFileSync(privateKeyPath, privatePem, {
      mode: 0o600,
    });
    writeFileSync(publicKeyPath, publicPem, {
      mode: 0o644,
    });
  }

  const publicKey = createPublicKey(readFileSync(publicKeyPath));
  const publicDer = publicKey.export({
    format: "der",
    type: "spki",
  });
  const keyId = createHash("sha256").update(publicDer).digest("hex").slice(0, 16);
  const verifierKeyPath = getAttestationVerifierKeyPath(keyId);
  if (!existsSync(verifierKeyPath)) {
    writeFileSync(verifierKeyPath, readFileSync(publicKeyPath), {
      mode: 0o644,
    });
  }

  return {
    keyId,
    privateKeyPath,
    publicKeyPath,
    verifierKeyPath,
  };
}

function loadExecutionRecord(runDir: string): ExecutionRecord {
  const loadResult = tryCatch(() => JSON.parse(readFileSync(join(runDir, "envelope.json"), "utf-8")));
  if (!loadResult.ok || !isExecutionRecord(loadResult.data)) {
    throw new Error(`Invalid execution record at ${join(runDir, "envelope.json")}`);
  }
  return loadResult.data;
}

function buildWitnessReceipt(record: ExecutionRecord, keyId: string): WitnessReceipt {
  if (!record.result) {
    throw new Error(`Run ${record.run_id} is not finalized and cannot be attested`);
  }
  return {
    schema_version: WITNESS_SCHEMA_VERSION,
    canonicalization_version: CANONICALIZATION_VERSION,
    subject: "record_digest",
    witness_type: "spawn-ed25519",
    run_id: record.run_id,
    record_digest: record.result.final_digest,
    signer: {
      key_id: keyId,
      identity_hint: getIdentityHint(),
      verifier: DEFAULT_VERIFIER,
    },
    signed_at: new Date().toISOString(),
  };
}

function buildSignatureReceipt(witness: WitnessReceipt, keyMaterial: AttestationKeyMaterial): SignatureReceipt {
  const payload = stableStringify(witness);
  const payloadDigest = sha256OfString(payload);
  const privateKey = createPrivateKey(readFileSync(keyMaterial.privateKeyPath));
  const signature = sign(null, Buffer.from(payload, "utf-8"), privateKey).toString("base64");
  return {
    schema_version: SIGNATURE_SCHEMA_VERSION,
    algorithm: "ed25519",
    key_id: keyMaterial.keyId,
    verifier: DEFAULT_VERIFIER,
    payload_type: "spawn-attestation-statement",
    payload_digest: payloadDigest,
    signature,
  };
}

export function attestExecutionRun(runDir: string): AttestationResult {
  const record = loadExecutionRecord(runDir);
  const keyMaterial = ensureDefaultAttestationKey();
  const witness = buildWitnessReceipt(record, keyMaterial.keyId);
  const signature = buildSignatureReceipt(witness, keyMaterial);
  const witnessPath = join(runDir, WITNESS_FILE_NAME);
  const signaturePath = join(runDir, SIGNATURE_FILE_NAME);
  writeJson(witnessPath, witness);
  writeJson(signaturePath, signature);
  return {
    witnessPath,
    signaturePath,
    keyId: keyMaterial.keyId,
    recordDigest: witness.record_digest,
  };
}

function loadAttestationArtifacts(rootDir: string): {
  witness: WitnessReceipt | null;
  signature: SignatureReceipt | null;
  reason?: string;
} {
  const witnessPath = join(rootDir, WITNESS_FILE_NAME);
  const signaturePath = join(rootDir, SIGNATURE_FILE_NAME);
  if (!existsSync(witnessPath) && !existsSync(signaturePath)) {
    return {
      witness: null,
      signature: null,
    };
  }
  if (!existsSync(witnessPath) || !existsSync(signaturePath)) {
    return {
      witness: null,
      signature: null,
      reason: "incomplete-attestation-files",
    };
  }

  const witnessResult = tryCatch(() => JSON.parse(readFileSync(witnessPath, "utf-8")));
  const signatureResult = tryCatch(() => JSON.parse(readFileSync(signaturePath, "utf-8")));
  if (!witnessResult.ok || !isWitnessReceipt(witnessResult.data)) {
    return {
      witness: null,
      signature: null,
      reason: !witnessResult.ok
        ? `failed-to-read-witness: ${getErrorMessage(witnessResult.error)}`
        : "invalid-witness-schema",
    };
  }
  if (!signatureResult.ok || !isSignatureReceipt(signatureResult.data)) {
    return {
      witness: witnessResult.data,
      signature: null,
      reason: !signatureResult.ok
        ? `failed-to-read-signature: ${getErrorMessage(signatureResult.error)}`
        : "invalid-signature-schema",
    };
  }
  return {
    witness: witnessResult.data,
    signature: signatureResult.data,
  };
}

function verifyAttestation(rootDir: string, result: VerifyResult): VerifyResult["attestation"] {
  const loaded = loadAttestationArtifacts(rootDir);
  if (!loaded.witness && !loaded.signature && !loaded.reason) {
    return {
      ok: true,
      state: "none",
      subject: "record_digest",
    };
  }

  if (!loaded.witness || !loaded.signature) {
    return {
      ok: false,
      state: "present-unverified",
      subject: "record_digest",
      cryptographic_valid: false,
      reason: loaded.reason ?? "incomplete-attestation-files",
      key_id: loaded.witness?.signer.key_id,
      signer_identity_hint: loaded.witness?.signer.identity_hint,
    };
  }

  const witness = loaded.witness;
  const signature = loaded.signature;
  if (witness.subject !== "record_digest") {
    return {
      ok: false,
      state: "present-unverified",
      subject: "record_digest",
      key_id: witness.signer.key_id,
      signer_identity_hint: witness.signer.identity_hint,
      cryptographic_valid: false,
      reason: "unsupported-attestation-subject",
    };
  }

  if (result.digest && witness.record_digest !== result.digest) {
    return {
      ok: false,
      state: "present-unverified",
      subject: "record_digest",
      key_id: witness.signer.key_id,
      signer_identity_hint: witness.signer.identity_hint,
      cryptographic_valid: false,
      reason: "record-digest-mismatch",
    };
  }

  if (signature.key_id !== witness.signer.key_id) {
    return {
      ok: false,
      state: "present-unverified",
      subject: "record_digest",
      key_id: witness.signer.key_id,
      signer_identity_hint: witness.signer.identity_hint,
      cryptographic_valid: false,
      reason: "signature-key-id-mismatch",
    };
  }

  const payload = stableStringify(witness);
  const payloadDigest = sha256OfString(payload);
  if (payloadDigest !== signature.payload_digest) {
    return {
      ok: false,
      state: "present-unverified",
      subject: "record_digest",
      key_id: witness.signer.key_id,
      signer_identity_hint: witness.signer.identity_hint,
      cryptographic_valid: false,
      reason: "payload-digest-mismatch",
    };
  }

  const verifierKeyPath = getAttestationVerifierKeyPath(witness.signer.key_id);
  if (!existsSync(verifierKeyPath) || !statSync(verifierKeyPath).isFile()) {
    return {
      ok: false,
      state: "present-unverified",
      subject: "record_digest",
      key_id: witness.signer.key_id,
      signer_identity_hint: witness.signer.identity_hint,
      cryptographic_valid: undefined,
      reason: "verifier-key-not-found",
    };
  }

  const publicKey = createPublicKey(readFileSync(verifierKeyPath));
  const signatureValid = verify(
    null,
    Buffer.from(payload, "utf-8"),
    publicKey,
    Buffer.from(signature.signature, "base64"),
  );
  if (!signatureValid) {
    return {
      ok: false,
      state: "present-unverified",
      subject: "record_digest",
      key_id: witness.signer.key_id,
      signer_identity_hint: witness.signer.identity_hint,
      cryptographic_valid: false,
      reason: "invalid-signature",
    };
  }

  return {
    ok: true,
    state: "verified",
    subject: "record_digest",
    key_id: witness.signer.key_id,
    signer_identity_hint: witness.signer.identity_hint,
    cryptographic_valid: true,
  };
}

export function applyAttestationVerification(rootDir: string, result: VerifyResult): VerifyResult {
  return {
    ...result,
    attestation: verifyAttestation(rootDir, result),
  };
}

export { SIGNATURE_FILE_NAME, WITNESS_FILE_NAME };
