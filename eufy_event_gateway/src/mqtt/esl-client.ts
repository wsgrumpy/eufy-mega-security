/**
 * Minimal mutual-TLS MQTT transport probe for newer Eufy smart locks.
 *
 * Phase 1 goal:
 *
 *   Mega certificate provisioning
 *        ↓
 *   TLS connection to Eufy's lock broker
 *        ↓
 *   MQTT 3.1.1 CONNECT
 *        ↓
 *   CONNACK accepted
 *
 * This file deliberately does NOT implement:
 *
 * - MQTT SUBSCRIBE
 * - MQTT PUBLISH
 * - ESL payload encoding
 * - lock()
 * - unlock()
 *
 * It exists only to prove that the Mega-provisioned certificate can establish
 * the authenticated MQTT transport required by the E31 lock path.
 */

import { randomBytes } from "node:crypto";
import {
  connect as tlsConnect,
  type ConnectionOptions,
  type TLSSocket,
} from "node:tls";

import type { LockMqttCredentials } from "../mega/types.js";

const DEFAULT_MQTT_PORT = 8883;
const DEFAULT_CONNECT_TIMEOUT_MS = 15_000;
const DEFAULT_KEEP_ALIVE_SECONDS = 60;

/** Configuration for the first-stage E31 MQTT transport probe. */
export interface EslMqttClientOptions {
  readonly credentials: LockMqttCredentials;
  readonly connectTimeoutMs?: number;
  readonly keepAliveSeconds?: number;
  readonly log?: (message: string) => void;
}

/**
 * Minimal MQTT client used only to validate the Eufy smart-lock mTLS channel.
 *
 * The implementation uses Node's native TLS socket and constructs only the
 * MQTT CONNECT packet required to receive a broker CONNACK.
 */
export class EslMqttClient {
  readonly #credentials: LockMqttCredentials;
  readonly #connectTimeoutMs: number;
  readonly #keepAliveSeconds: number;
  readonly #log: (message: string) => void;

  #socket: TLSSocket | null = null;
  #clientId: string | null = null;
  #connected = false;

  constructor(options: EslMqttClientOptions) {
    this.#credentials = options.credentials;
    this.#connectTimeoutMs =
      options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
    this.#keepAliveSeconds =
      options.keepAliveSeconds ?? DEFAULT_KEEP_ALIVE_SECONDS;
    this.#log = options.log ?? (() => undefined);
  }

  /** True only after the MQTT broker has returned CONNACK success. */
  get connected(): boolean {
    return this.#connected;
  }

  /** MQTT client id used for the current connection. */
  get clientId(): string | null {
    return this.#clientId;
  }

  /**
   * Establish TLS and complete the MQTT 3.1.1 CONNECT handshake.
   *
   * Resolves only after the broker returns CONNACK return code 0.
   */
  async connect(): Promise<void> {
    if (
      this.#connected &&
      this.#socket &&
      !this.#socket.destroyed
    ) {
      return;
    }

    const { host, port } = parseEndpoint(
      this.#credentials.endpoint,
    );

    const clientId = buildClientId(
      this.#credentials.userId,
    );

    const connectPacket = buildMqttConnectPacket(
      clientId,
      this.#keepAliveSeconds,
    );

    this.#clientId = clientId;
    this.#connected = false;

    /*
     * Important:
     *
     * Do NOT set the "ca" option here for the first transport probe.
     *
     * Supplying ca explicitly to Node TLS replaces the normal trusted root
     * store. Eufy's MQTT broker uses a publicly trusted certificate chain, so
     * the correct first test is to keep Node's default CA roots while still
     * presenting the Mega-provisioned client certificate and private key.
     */
    const tlsOptions: ConnectionOptions = {
      host,
      port,
      servername: host,
      cert: this.#credentials.cert,
      key: this.#credentials.key,
      rejectUnauthorized: true,
      minVersion: "TLSv1.2",
    };

    await new Promise<void>((resolve, reject) => {
      let settled = false;
      let receiveBuffer = Buffer.alloc(0);

      const socket = tlsConnect(tlsOptions);
      this.#socket = socket;

      const timer = setTimeout(() => {
        fail(
          new Error(
            `Eufy lock MQTT connection timed out after ${this.#connectTimeoutMs} ms`,
          ),
        );
      }, this.#connectTimeoutMs);

      const cleanupTimer = (): void => {
        clearTimeout(timer);
      };

      const fail = (error: Error): void => {
        if (settled) {
          this.#log(
            `E31 MQTT socket error after connection: ${error.message}`,
          );
          return;
        }

        settled = true;
        cleanupTimer();
        this.#connected = false;

        if (!socket.destroyed) {
          socket.destroy();
        }

        this.#socket = null;

        reject(error);
      };

      socket.once("secureConnect", () => {
        if (!socket.authorized) {
          fail(
            new Error(
              `Eufy MQTT TLS certificate was not authorized: ${
                socket.authorizationError ?? "unknown TLS error"
              }`,
            ),
          );
          return;
        }

        this.#log(
          `E31 TLS connected to ${host}:${port}`,
        );

        socket.write(connectPacket);
      });

      socket.on("data", (chunk: Buffer) => {
        if (settled) {
          return;
        }

        receiveBuffer = Buffer.concat([
          receiveBuffer,
          chunk,
        ]);

        let packet: DecodedMqttPacket | null;

        try {
          packet = readMqttPacket(
            receiveBuffer,
          );
        } catch (error) {
          fail(
            error instanceof Error
              ? error
              : new Error("Invalid MQTT packet"),
          );
          return;
        }

        if (!packet) {
          return;
        }

        if (packet.type !== 2) {
          fail(
            new Error(
              `Expected MQTT CONNACK but received packet type ${packet.type}`,
            ),
          );
          return;
        }

        if (packet.payload.length !== 2) {
          fail(
            new Error(
              `Invalid MQTT CONNACK length ${packet.payload.length}`,
            ),
          );
          return;
        }

        const sessionPresent =
          (packet.payload.readUInt8(0) & 0x01) !== 0;

        const returnCode =
          packet.payload.readUInt8(1);

        if (returnCode !== 0) {
          fail(
            new Error(
              `Eufy MQTT broker rejected CONNECT: ${mqttConnackReason(returnCode)}`,
            ),
          );
          return;
        }

        settled = true;
        cleanupTimer();

        this.#connected = true;

        this.#log(
          `E31 MQTT connected: sessionPresent=${sessionPresent}`,
        );

        resolve();
      });

      socket.on("error", (error: Error) => {
        fail(error);
      });

      socket.once("close", () => {
        this.#connected = false;

        if (this.#socket === socket) {
          this.#socket = null;
        }

        if (!settled) {
          fail(
            new Error(
              "Eufy lock MQTT connection closed before CONNACK",
            ),
          );
          return;
        }

        this.#log(
          "E31 MQTT connection closed",
        );
      });
    });
  }

  /**
   * Close the MQTT transport cleanly.
   *
   * MQTT DISCONNECT contains no lock command and cannot change lock state.
   */
  disconnect(): void {
    const socket = this.#socket;

    this.#connected = false;
    this.#socket = null;

    if (!socket || socket.destroyed) {
      return;
    }

    try {
      socket.write(
        Buffer.from([
          0xe0,
          0x00,
        ]),
      );
    } finally {
      socket.end();
    }
  }
}

/**
 * Build the MQTT client id used by the Eufy Security Android-style client.
 *
 * The identifier itself is never written to logs.
 */
function buildClientId(
  userId: string,
): string {
  const random =
    randomBytes(4).toString("hex");

  const timestamp =
    Math.floor(Date.now() / 1_000);

  return [
    "android-eufy_security",
    userId,
    random,
    timestamp,
  ].join("-");
}

/**
 * Build an MQTT 3.1.1 CONNECT packet.
 *
 * Flags:
 *
 *   Clean Session = true
 *   Username      = false
 *   Password      = false
 *   Will          = false
 */
function buildMqttConnectPacket(
  clientId: string,
  keepAliveSeconds: number,
): Buffer {
  if (
    !Number.isInteger(keepAliveSeconds) ||
    keepAliveSeconds < 0 ||
    keepAliveSeconds > 65_535
  ) {
    throw new Error(
      "MQTT keep-alive must be between 0 and 65535 seconds",
    );
  }

  const keepAlive =
    Buffer.allocUnsafe(2);

  keepAlive.writeUInt16BE(
    keepAliveSeconds,
    0,
  );

  const variableHeader =
    Buffer.concat([
      mqttString("MQTT"),

      // MQTT protocol level 4 = MQTT 3.1.1
      Buffer.from([
        0x04,

        // CONNECT flags:
        // bit 1 = Clean Session
        0x02,
      ]),

      keepAlive,
    ]);

  const payload =
    mqttString(clientId);

  const remainingLength =
    variableHeader.length +
    payload.length;

  return Buffer.concat([
    // CONNECT packet type
    Buffer.from([
      0x10,
    ]),

    encodeRemainingLength(
      remainingLength,
    ),

    variableHeader,
    payload,
  ]);
}

/** Encode one MQTT UTF-8 string with its two-byte network-order length. */
function mqttString(
  value: string,
): Buffer {
  const bytes =
    Buffer.from(
      value,
      "utf8",
    );

  if (bytes.length > 65_535) {
    throw new Error(
      "MQTT string is too long",
    );
  }

  const length =
    Buffer.allocUnsafe(2);

  length.writeUInt16BE(
    bytes.length,
    0,
  );

  return Buffer.concat([
    length,
    bytes,
  ]);
}

/** Encode MQTT's variable-byte Remaining Length field. */
function encodeRemainingLength(
  value: number,
): Buffer {
  if (
    !Number.isInteger(value) ||
    value < 0 ||
    value > 268_435_455
  ) {
    throw new Error(
      "Invalid MQTT remaining length",
    );
  }

  const bytes: number[] = [];

  let remaining =
    value;

  do {
    let digit =
      remaining % 128;

    remaining =
      Math.floor(
        remaining / 128,
      );

    if (remaining > 0) {
      digit |= 0x80;
    }

    bytes.push(digit);
  } while (remaining > 0);

  return Buffer.from(bytes);
}

interface DecodedMqttPacket {
  readonly type: number;
  readonly flags: number;
  readonly payload: Buffer;
}

/**
 * Parse the first complete MQTT packet in a socket buffer.
 *
 * Returns null while more bytes are required.
 */
function readMqttPacket(
  buffer: Buffer,
): DecodedMqttPacket | null {
  if (buffer.length < 2) {
    return null;
  }

  const firstByte =
    buffer.readUInt8(0);

  const type =
    firstByte >> 4;

  const flags =
    firstByte & 0x0f;

  let multiplier = 1;
  let remainingLength = 0;
  let index = 1;
  let encodedBytes = 0;

  while (true) {
    if (index >= buffer.length) {
      return null;
    }

    const digit =
      buffer.readUInt8(index);

    index += 1;
    encodedBytes += 1;

    remainingLength +=
      (digit & 0x7f) *
      multiplier;

    if ((digit & 0x80) === 0) {
      break;
    }

    if (encodedBytes >= 4) {
      throw new Error(
        "Invalid MQTT Remaining Length",
      );
    }

    multiplier *= 128;
  }

  const packetEnd =
    index +
    remainingLength;

  if (buffer.length < packetEnd) {
    return null;
  }

  return {
    type,
    flags,
    payload:
      buffer.subarray(
        index,
        packetEnd,
      ),
  };
}

/**
 * Parse the endpoint returned by Mega.
 *
 * Accepted examples:
 *
 *   security-mqtt-ie.anker.com
 *   security-mqtt-ie.anker.com:8883
 *   mqtts://security-mqtt-ie.anker.com:8883
 */
function parseEndpoint(
  endpoint: string,
): {
  host: string;
  port: number;
} {
  const value =
    endpoint.trim();

  if (!value) {
    throw new Error(
      "Eufy MQTT endpoint is empty",
    );
  }

  if (
    /^[a-z][a-z0-9+.-]*:\/\//i.test(
      value,
    )
  ) {
    const url =
      new URL(value);

    if (!url.hostname) {
      throw new Error(
        "Eufy MQTT endpoint has no hostname",
      );
    }

    const port =
      url.port
        ? Number.parseInt(
          url.port,
          10,
        )
        : DEFAULT_MQTT_PORT;

    validatePort(port);

    return {
      host: url.hostname,
      port,
    };
  }

  const hostAndPort =
    /^([^:]+):(\d+)$/.exec(
      value,
    );

  if (hostAndPort) {
    const host =
      hostAndPort[1];

    const portText =
      hostAndPort[2];

    if (!host || !portText) {
      throw new Error(
        "Invalid Eufy MQTT endpoint",
      );
    }

    const port =
      Number.parseInt(
        portText,
        10,
      );

    validatePort(port);

    return {
      host,
      port,
    };
  }

  return {
    host: value,
    port: DEFAULT_MQTT_PORT,
  };
}

function validatePort(
  port: number,
): void {
  if (
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65_535
  ) {
    throw new Error(
      `Invalid Eufy MQTT port ${port}`,
    );
  }
}

/** Human-readable MQTT 3.1.1 CONNACK return code. */
function mqttConnackReason(
  code: number,
): string {
  switch (code) {
    case 0:
      return "connection accepted";

    case 1:
      return "unacceptable protocol version";

    case 2:
      return "identifier rejected";

    case 3:
      return "server unavailable";

    case 4:
      return "bad username or password";

    case 5:
      return "not authorized";

    default:
      return `unknown return code ${code}`;
  }
}