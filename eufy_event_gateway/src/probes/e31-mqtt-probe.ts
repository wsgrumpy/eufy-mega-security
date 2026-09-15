import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { MegaClient } from "../mega/client.js";
import type { LockMqttCredentials } from "../mega/types.js";
import { EslMqttClient } from "../mqtt/esl-client.js";

const DATA_DIRECTORY =
  process.env.EUFY_GATEWAY_DATA_DIR ?? "/data/runtime";

const CREDENTIAL_CACHE =
  join(DATA_DIRECTORY, "e31-mqtt-credentials.json");

async function main(): Promise<void> {
  const email =
    requiredEnvironment("EUFY_USERNAME");

  const password =
    requiredEnvironment("EUFY_PASSWORD");

  const country =
    requiredEnvironment("EUFY_COUNTRY");

  const verificationCode =
    optionalEnvironment("EUFY_VERIFY_CODE");

  const forceReprovision =
    process.env.EUFY_E31_FORCE_REPROVISION === "1";

  await mkdir(
    DATA_DIRECTORY,
    { recursive: true },
  );

  const client = new MegaClient({
    email,
    password,
    country,
    persistentDirectory: DATA_DIRECTORY,
  });

  process.stdout.write(
    "E31_PROBE phase=mega_auth status=starting\n",
  );

  const auth = await client.connect(
    verificationCode ?? undefined,
  );

  if (auth.state === "captcha-required") {
    throw new Error(
      "Mega authentication requires a CAPTCHA",
    );
  }

  if (auth.state === "verification-required") {
    throw new Error(
      "Mega authentication requires an email verification code",
    );
  }

  process.stdout.write(
    "E31_PROBE phase=mega_auth status=authenticated\n",
  );

  let credentials =
    forceReprovision
      ? null
      : await loadCachedCredentials();

  if (credentials) {
    process.stdout.write(
      "E31_PROBE phase=certificate status=cache_hit\n",
    );
  } else {
    process.stdout.write(
      "E31_PROBE phase=certificate status=provisioning\n",
    );

    credentials =
      await client.provisionLockMqttCert();

    await saveCachedCredentials(
      credentials,
    );

    process.stdout.write(
      "E31_PROBE phase=certificate status=provisioned\n",
    );
  }

  const mqtt = new EslMqttClient({
    credentials,
    log: (message) => {
      process.stdout.write(
        `E31_PROBE phase=transport ${message}\n`,
      );
    },
  });

  try {
    process.stdout.write(
      "E31_PROBE phase=transport status=connecting\n",
    );

    await mqtt.connect();

    process.stdout.write(
      "E31_PROBE_RESULT status=success tls=true mqtt_connack=true publish=false subscribe=false lock_command=false\n",
    );
  } finally {
    mqtt.disconnect();
  }
}

async function loadCachedCredentials():
Promise<LockMqttCredentials | null> {
  try {
    const parsed: unknown =
      JSON.parse(
        await readFile(
          CREDENTIAL_CACHE,
          "utf8",
        ),
      );

    return isLockMqttCredentials(parsed)
      ? parsed
      : null;
  } catch (error) {
    if (
      isNodeError(error) &&
      error.code === "ENOENT"
    ) {
      return null;
    }

    throw error;
  }
}

async function saveCachedCredentials(
  credentials: LockMqttCredentials,
): Promise<void> {
  const temporary =
    `${CREDENTIAL_CACHE}.tmp`;

  await writeFile(
    temporary,
    `${JSON.stringify(credentials)}\n`,
    { mode: 0o600 },
  );

  await rename(
    temporary,
    CREDENTIAL_CACHE,
  );

  await chmod(
    CREDENTIAL_CACHE,
    0o600,
  );
}

function isLockMqttCredentials(
  value: unknown,
): value is LockMqttCredentials {
  if (!isRecord(value)) {
    return false;
  }

  const required = [
    "cert",
    "key",
    "endpoint",
    "thingName",
    "userId",
    "certificateId",
  ];

  for (const key of required) {
    if (
      typeof value[key] !== "string" ||
      value[key].length === 0
    ) {
      return false;
    }
  }

  return (
    typeof value.caCert === "string"
  );
}

function isRecord(
  value: unknown,
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function isNodeError(
  value: unknown,
): value is NodeJS.ErrnoException {
  return (
    value instanceof Error &&
    "code" in value
  );
}

function requiredEnvironment(
  name: string,
): string {
  const value =
    optionalEnvironment(name);

  if (!value) {
    throw new Error(
      `${name} is required`,
    );
  }

  return value;
}

function optionalEnvironment(
  name: string,
): string | null {
  const value =
    process.env[name]?.trim();

  return value
    ? value
    : null;
}

try {
  await main();
} catch (error) {
  const message =
    error instanceof Error
      ? error.message
      : "Unknown probe failure";

  process.stderr.write(
    `E31_PROBE_RESULT status=failure error=${JSON.stringify(message)}\n`,
  );

  process.exitCode = 1;
}