/**
 * Adapts Eufy's Mega cloud and PPCS camera protocols to the gateway contract.
 *
 * Startup authenticates one account, parses and filters inventory, retrieves
 * station DSK material, registers Android FCM delivery, and reports camera
 * identities to `GatewayState`. Push callbacks become motion, person, or doorbell press events
 * and verified JPEG snapshots. A live request creates a first-party PPCS
 * session and exposes only its byte stream to `LiveStreamManager`. This is the
 * sole production translation point from Eufy-specific data to normalized
 * provider callbacks; Home Assistant-specific naming stays downstream. The
 * provider also emits field-limited push summaries for support logs without
 * forwarding private event fields into the logger.
 */
import { join } from "node:path";

import type { HomeBaseState, InventoryDiagnostic } from "../domain/types.js";
import { createLogger } from "../logging.js";
import { MegaClient } from "../mega/client.js";
import { decodeEventImage, isJpeg } from "../mega/image.js";
import { MegaPushReceiver, type MegaPushEvent } from "../mega/push.js";
import { EslMqttClient } from "../mqtt/esl-client.js";
import { FirstPartyPpcsSession } from "../stream/first-party-ppcs.js";
import { HomeBasePpcsSession, type HomeBasePpcsState } from "../stream/homebase-ppcs.js";
import type { CameraProvider, CaptchaChallenge, CaptchaProvider, ProviderEvents } from "./provider.js";

const logger = createLogger("provider");

/** Credentials, storage, and transport limits for one Mega account. */
export interface EufyProviderConfig {
  readonly username: string;
  readonly password: string;
  readonly country: string;
  readonly persistentDirectory: string;
  readonly verifyCode?: string;
  readonly maxStreamSeconds: number;
}

/** Normalized Mega inventory row used to decide camera support and routing. */
export interface MegaInventoryDevice {
  readonly serial: string;
  readonly name: string;
  readonly model: string;
  readonly parentSerial: string;
  readonly deviceType: number | null;
  readonly category: string | null;
  readonly channel: number | null;
  readonly p2pDid: string | null;
  readonly p2pConnection: string | null;
  readonly cipherId: number | null;
  readonly adminUserId: string | null;
  readonly userName: string | null;
  readonly firmware: string | null;
}

/** Safe, grouped inventory evidence suitable for copied support logs. */
export interface InventoryLogSummary {
  readonly count: number;
  readonly model: string;
  readonly deviceType: number | null;
  readonly category: string | null;
  readonly hasParent: boolean;
  readonly hasChannel: boolean;
  readonly acceptedAsCamera: boolean;
  readonly stationPresent: boolean;
  readonly stationPpcsReady: boolean;
  readonly stationDskReady: boolean;
  readonly streamRoute: "homebase" | "direct" | "unavailable";
  readonly peerPpcsReady: boolean;
  readonly peerDskReady: boolean;
  readonly streamSupported: boolean;
}

/** Selects the peer that owns a camera's PPCS connection and DSK key. */
export interface PpcsStreamRoute {
  readonly peer: MegaInventoryDevice;
  readonly homeBaseAttached: boolean;
}

/**
 * Bridges Mega cloud observations and first-party PPCS streams into callbacks.
 *
 * Startup is deliberately ordered. The provider authenticates, discovers all
 * devices, obtains the station keys needed for camera sessions, then starts
 * push delivery. A stream request creates one PPCS session per camera and
 * closes it when the last consumer releases the source.
 */
export class EufyProvider implements CameraProvider, CaptchaProvider {
  readonly #client: MegaClient;
  readonly #devices = new Map<string, MegaInventoryDevice>();
  readonly #ppcsStreams = new Map<string, FirstPartyPpcsSession>();
  readonly #dskKeys = new Map<string, { readonly key: string; readonly expiresAt: number | null }>();
  readonly #cipherKeys = new Map<number, string>();
  readonly #pushSnapshotQueues = new Map<string, Promise<void>>();
  readonly #stations = new Map<string, HomeBaseState>();
  readonly #stationOperations = new Map<string, Promise<HomeBaseState>>();
  #push: MegaPushReceiver | null = null;
  #events: ProviderEvents | null = null;
  #captchaChallenge: CaptchaChallenge | null = null;
  #verificationRequired = false;
  #stationRefreshTimer: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly config: EufyProviderConfig) {
    this.#client = new MegaClient({
      email: config.username,
      password: config.password,
      country: config.country,
      persistentDirectory: config.persistentDirectory,
    });
  }

  async start(events: ProviderEvents): Promise<void> {
    this.#events = events;
    const auth = await this.#client.connect(this.config.verifyCode);
    if (auth.state !== "authenticated") {
      this.#captchaChallenge = auth.captcha ?? null;
      this.#verificationRequired = auth.state === "verification-required";
      const detail = auth.state === "captcha-required"
        ? "Open the add-on web interface to complete Eufy's CAPTCHA"
        : "Open the add-on web interface to enter Eufy's email verification code";
      events.connection("authentication-required", detail);
      return;
    }
    await this.#completeStartup(events);
  }

  async startStream(serial: string): Promise<void> {
    const device = this.#devices.get(serial);
    if (!device || !isSupportedMegaCamera(device)) throw new Error(`Unknown Eufy camera: ${serial}`);
    const route = ppcsStreamRoute(device, this.#devices);
    const peer = route?.peer;
    const dsk = peer ? this.#dskKeys.get(peer.serial) : null;

    // The production path is deliberately first-party Mega/PPCS.
    if (route && peer?.p2pDid && peer.p2pConnection && dsk && device.channel !== null) {
      this.#ppcsStreams.get(serial)?.close();
      const stream = new FirstPartyPpcsSession({
        stationSerial: peer.serial,
        p2pDid: peer.p2pDid,
        appConnection: peer.p2pConnection,
        dskKey: dsk.key,
        channel: device.channel,
        cameraModel: device.model,
        accountId: device.adminUserId,
        homeBaseAttached: route.homeBaseAttached,
        ...(route.homeBaseAttached ? {
          resolveCipherKey: async (cipherId: number) => {
            const cached = this.#cipherKeys.get(cipherId);
            if (cached) return cached;
            if (!peer.adminUserId) return undefined;
            try {
              const ciphers = await this.#client.getCiphers([cipherId], peer.adminUserId, peer.serial);
              for (const cipher of ciphers) {
                const id = typeof cipher.cipher_id === "number"
                  ? cipher.cipher_id
                  : Number(cipher.cipher_id);
                const key = typeof cipher.ecc_private_key === "string"
                  ? cipher.ecc_private_key
                  : "";
                if (Number.isInteger(id) && key) this.#cipherKeys.set(id, key);
              }
            } catch (error) {
              logger.warn(
                "cipher_lookup_unavailable",
                `Mega cipher lookup unavailable: ${safeError(error)}`,
              );
            }
            return this.#cipherKeys.get(cipherId);
          },
        } : {}),
        maxSeconds: this.config.maxStreamSeconds,
      });

      this.#ppcsStreams.set(serial, stream);
      await stream.start();
      this.#events?.streamStarted(serial, stream.output);

      stream.output.once("close", () => {
        if (this.#ppcsStreams.get(serial) !== stream) return;
        this.#ppcsStreams.delete(serial);
        this.#events?.streamStopped(serial);
      });

      return;
    }

    throw new Error("First-party PPCS camera transport is unavailable for this camera");
  }

  async stopStream(serial: string): Promise<void> {
    this.#ppcsStreams.get(serial)?.close();
    this.#ppcsStreams.delete(serial);
    this.#events?.streamStopped(serial);
  }

  async refreshStation(serial: string): Promise<HomeBaseState> {
    return this.#queueStationOperation(serial, false, async (session) => session.readState());
  }

  async setGuardMode(serial: string, mode: number): Promise<HomeBaseState> {
    if (![0, 1, 2, 3, 4, 5, 47, 63].includes(mode)) {
      throw new Error("Unsupported HomeBase guard mode");
    }
    return this.#writeStationValue(serial, "guardMode", mode, (session) => session.setGuardMode(mode));
  }

  async setAlarmVolume(serial: string, value: number): Promise<HomeBaseState> {
    if (!Number.isInteger(value) || value < 1 || value > 26) {
      throw new Error("HomeBase alarm volume must be from 1 to 26");
    }
    return this.#writeStationValue(serial, "alarmVolume", value, (session) => session.setAlarmVolume(value));
  }

  async setPromptVolume(serial: string, value: number): Promise<HomeBaseState> {
    if (!Number.isInteger(value) || value < 0 || value > 26) {
      throw new Error("HomeBase prompt volume must be from 0 to 26");
    }
    return this.#writeStationValue(serial, "promptVolume", value, (session) => session.setPromptVolume(value));
  }

  async setAlarmTone(serial: string, value: number): Promise<HomeBaseState> {
    if (value !== 1 && value !== 2) {
      throw new Error("HomeBase alarm tone must be 1 or 2");
    }
    return this.#writeStationValue(serial, "alarmTone", value, (session) => session.setAlarmTone(value));
  }

  async close(): Promise<void> {
    if (this.#stationRefreshTimer) clearInterval(this.#stationRefreshTimer);
    this.#stationRefreshTimer = null;

    await this.#push?.close();
    this.#push = null;

    for (const stream of this.#ppcsStreams.values()) stream.close();
    this.#ppcsStreams.clear();

    await Promise.allSettled(this.#stationOperations.values());
    this.#stationOperations.clear();

    this.#events = null;
  }

  getCaptchaChallenge(): CaptchaChallenge | null {
    return this.#captchaChallenge;
  }

  isVerificationRequired(): boolean {
    return this.#verificationRequired;
  }

  async submitCaptcha(answer: string): Promise<void> {
    if (!this.#captchaChallenge || !this.#events) {
      throw new Error("No Eufy CAPTCHA is waiting for an answer");
    }

    const result = await this.#client.connect(undefined, answer);

    if (result.state === "captcha-required") {
      this.#captchaChallenge = result.captcha ?? null;
      throw new Error("Eufy did not accept the CAPTCHA answer");
    }

    if (result.state === "verification-required") {
      this.#captchaChallenge = null;
      this.#verificationRequired = true;
      this.#events.connection(
        "authentication-required",
        "Eufy sent a six-digit verification code; enter it in the add-on web interface",
      );
      return;
    }

    this.#captchaChallenge = null;
    this.#verificationRequired = false;
    await this.#completeStartup(this.#events);
  }

  async submitVerification(code: string): Promise<void> {
    if (!this.#verificationRequired || !this.#events) {
      throw new Error("No Eufy verification is waiting for a code");
    }

    const result = await this.#client.connect(code);

    if (result.state !== "authenticated") {
      throw new Error("Eufy did not accept the verification code");
    }

    this.#verificationRequired = false;
    await this.#completeStartup(this.#events);
  }

  async #completeStartup(events: ProviderEvents): Promise<void> {
    let inventory;

    try {
      inventory = await this.#client.inventory();
    } catch (error) {
      if (!this.#client.isSessionInvalidError(error)) throw error;

      logger.warn(
        "session_invalidated",
        "Mega session was invalidated; signing in again",
      );

      const auth = await this.#client.connect(undefined, undefined, true);

      if (auth.state !== "authenticated") {
        this.#captchaChallenge = auth.captcha ?? null;
        this.#verificationRequired = auth.state === "verification-required";

        const detail = auth.state === "captcha-required"
          ? "Open the add-on web interface to complete Eufy's CAPTCHA"
          : "Open the add-on web interface to enter Eufy's email verification code";

        events.connection("authentication-required", detail);
        return;
      }

      inventory = await this.#client.inventory();
    }

    const devices = parseMegaInventory(inventory);

    this.#devices.clear();

    for (const device of devices) {
      this.#devices.set(device.serial, device);
    }

    /**
     * Experimental E31 transport probe.
     *
     * This deliberately stops immediately after MQTT CONNACK.
     *
     * It does NOT:
     * - subscribe to lock topics;
     * - publish MQTT messages;
     * - construct ESL payloads;
     * - send lock commands;
     * - send unlock commands.
     */
    const e31 = devices.find(
      (device) =>
        device.category === "eufy_security" &&
        device.deviceType === 205 &&
        device.model.startsWith("T85F0"),
    );

    if (e31) {
      logger.info(
        "e31_mqtt_probe_start",
        `E31 detected: model=${e31.model} device_type=${e31.deviceType}; testing Mega certificate provisioning and MQTT mTLS`,
      );

      try {
        const credentials = await this.#client.provisionLockMqttCert();

        logger.info(
          "e31_mqtt_cert_provisioned",
          "E31 MQTT client certificate provisioned successfully",
        );

        const mqtt = new EslMqttClient({
          credentials,
          log: (message) => {
            logger.info(
              "e31_mqtt_transport",
              message,
            );
          },
        });

        await mqtt.connect();

        logger.info(
          "e31_mqtt_probe_success",
          "E31 TLS/MQTT transport connected successfully",
        );

        mqtt.disconnect();
      } catch (error) {
        logger.warn(
          "e31_mqtt_probe_failed",
          `E31 MQTT transport probe failed: ${safeError(error)}`,
        );
      }
    }

    this.#dskKeys.clear();
    this.#cipherKeys.clear();

    const peerSerials = [
      ...new Set(
        devices
          .filter(
            (device) =>
              (!device.parentSerial || device.parentSerial === device.serial) &&
              device.p2pDid,
          )
          .map((device) => device.serial),
      ),
    ];

    if (peerSerials.length > 0) {
      try {
        for (
          const [serial, key] of Object.entries(
            await this.#client.dskKeys(peerSerials),
          )
        ) {
          this.#dskKeys.set(serial, key);
        }
      } catch (error) {
        logger.warn(
          "dsk_lookup_unavailable",
          `Mega DSK lookup unavailable: ${safeError(error)}`,
        );
      }
    }

    for (const device of devices) {
      if (!isSupportedMegaCamera(device)) continue;

      events.camera({
        serial: device.serial,
        name: device.name,
        model: device.model,
        stationSerial: device.parentSerial,
        doorbellSupported: isDoorbellDevice(device),
        streamSupported: isPpcsStreamSupported(
          device,
          this.#devices,
          new Set(this.#dskKeys.keys()),
        ),
      });
    }

    this.#stations.clear();

    for (const device of devices.filter(isHomeBase3)) {
      const station = initialHomeBaseState(device);
      this.#stations.set(device.serial, station);
      events.station(station);
    }

    const diagnostics = inventoryDiagnostics(devices);
    const summaries = inventoryLogSummaries(
      devices,
      new Set(this.#dskKeys.keys()),
    );

    logger.info(
      "inventory_loaded",
      `Mega inventory loaded: devices=${devices.length} accepted=${diagnostics.filter(({ acceptedAsCamera }) => acceptedAsCamera).length} groups=${summaries.length}`,
    );

    for (const summary of summaries) {
      logger.info(
        "inventory_group",
        [
          `count=${summary.count}`,
          `model=${JSON.stringify(summary.model)}`,
          `device_type=${summary.deviceType ?? "missing"}`,
          `category=${summary.category ?? "missing"}`,
          `accepted=${summary.acceptedAsCamera}`,
          `has_parent=${summary.hasParent}`,
          `has_channel=${summary.hasChannel}`,
          `station_present=${summary.stationPresent}`,
          `station_ppcs_ready=${summary.stationPpcsReady}`,
          `station_dsk_ready=${summary.stationDskReady}`,
          `stream_route=${summary.streamRoute}`,
          `peer_ppcs_ready=${summary.peerPpcsReady}`,
          `peer_dsk_ready=${summary.peerDskReady}`,
          `stream_supported=${summary.streamSupported}`,
        ].join(" "),
      );
    }

    events.inventory(diagnostics);

    await this.#push?.close();

    this.#push = new MegaPushReceiver(
      this.#client,
      join(this.config.persistentDirectory, "mega-push.json"),
      (event) => this.#handlePush(events, event),
    );

    await this.#push.start();

    events.connection(
      "connected",
      "Gateway events and snapshots are ready; live viewing requires a validated PPCS camera path",
    );

    await Promise.allSettled(
      [...this.#stations.keys()].map(
        (serial) => this.refreshStation(serial),
      ),
    );

    if (this.#stationRefreshTimer) {
      clearInterval(this.#stationRefreshTimer);
    }

    this.#stationRefreshTimer = setInterval(() => {
      for (const serial of this.#stations.keys()) {
        if (
          this.#stationOperations.has(serial) ||
          this.#stationHasActiveMedia(serial)
        ) {
          continue;
        }

        void this.refreshStation(serial).catch((error: unknown) => {
          logger.warn(
            "station_refresh_unavailable",
            `HomeBase state refresh unavailable: ${safeError(error)}`,
          );
        });
      }
    }, 60_000);

    this.#stationRefreshTimer.unref();
  }

  #handlePush(events: ProviderEvents, event: MegaPushEvent): void {
    const station = this.#stations.get(event.stationSerial);
    const stationIdentity = this.#devices.get(event.stationSerial);

    if (station && event.eventType === 9) {
      const updated = {
        ...station,
        guardMode: validGuardMode(event.guardMode)
          ? event.guardMode
          : station.guardMode,
        effectiveMode: validGuardMode(event.effectiveMode)
          ? event.effectiveMode
          : station.effectiveMode,
      };

      this.#stations.set(station.serial, updated);
      events.station(updated);
    } else if (
      station &&
      event.eventType === 10 &&
      event.alarmType !== null
    ) {
      const updated = {
        ...station,
        alarmActive: ![0, 1, 15, 16, 17].includes(event.alarmType),
      };

      this.#stations.set(station.serial, updated);
      events.station(updated);
    }

    const personName = personNameFromPush(event);

    events.pushDiagnostic({
      receivedAt: new Date().toISOString(),
      cameraSerial: event.cameraSerial,
      cameraName: event.cameraName,
      type: null,
      eventType: event.eventType,
      messageType: event.messageType,
      notificationStyle: event.notificationStyle,
      personName,
      hasPersonName: personName !== null,
      hasPictureUrl: event.pictureUrl !== null,
      hasFilePath: event.filePath !== null,
      hasFetchId: event.fetchId !== null,
      hasSenseId: event.senseId !== null,
    });

    logger.info(
      "push_received",
      safePushLogSummary(
        event,
        this.#devices.get(event.cameraSerial) ?? null,
        stationIdentity !== undefined && !stationIdentity.parentSerial,
        station !== undefined,
      ),
    );

    const device = this.#devices.get(event.cameraSerial);

    if (!device) return;

    if (
      event.eventType === 3103 &&
      isDoorbellDevice(device)
    ) {
      events.doorbell(event.cameraSerial, true);
      return;
    }

    if (!isCameraDetection(event.eventType)) return;

    if (event.eventType === 3101) {
      events.motion(event.cameraSerial, true);
    } else {
      events.person(event.cameraSerial, true, personName);
    }

    if (event.pictureUrl) {
      this.#queuePushSnapshot(events, event);
    }
  }

  async #writeStationValue(
    serial: string,
    field: "guardMode" | "alarmVolume" | "promptVolume" | "alarmTone",
    expected: number,
    write: (session: HomeBasePpcsSession) => Promise<void>,
  ): Promise<HomeBaseState> {
    return this.#queueStationOperation(
      serial,
      true,
      async (session) => {
        await write(session);

        const observed = await session.readState(false);

        if (observed[field] !== expected) {
          throw new Error(`HomeBase did not confirm ${field}`);
        }

        return observed;
      },
    );
  }

  #queueStationOperation(
    serial: string,
    interruptMedia: boolean,
    operation: (session: HomeBasePpcsSession) => Promise<HomeBasePpcsState>,
  ): Promise<HomeBaseState> {
    const previous =
      this.#stationOperations.get(serial) ??
      Promise.resolve(this.#requireStation(serial));

    const current = previous
      .catch(() => this.#requireStation(serial))
      .then(async () => {
        const identity = this.#devices.get(serial);

        if (
          !identity ||
          !isHomeBase3(identity) ||
          !identity.p2pDid ||
          !identity.adminUserId
        ) {
          throw new Error("HomeBase local command identity is unavailable");
        }

        if (interruptMedia) {
          await this.#stopStationMedia(serial);
        } else if (this.#stationHasActiveMedia(serial)) {
          return this.#requireStation(serial);
        }

        const session = new HomeBasePpcsSession({
          serial,
          p2pDid: identity.p2pDid,
          accountId: identity.adminUserId,
          userName: identity.userName ?? "Home Assistant",
        });

        try {
          await session.connect();

          const observed = await operation(session);

          const updated = mergeHomeBaseState(
            this.#requireStation(serial),
            observed,
          );

          this.#stations.set(serial, updated);
          this.#events?.station(updated);

          return updated;
        } catch (error) {
          const updated = {
            ...this.#requireStation(serial),
            connected: false,
          };

          this.#stations.set(serial, updated);
          this.#events?.station(updated);

          throw error;
        } finally {
          session.close();
        }
      });

    this.#stationOperations.set(serial, current);

    void current
      .finally(() => {
        if (this.#stationOperations.get(serial) === current) {
          this.#stationOperations.delete(serial);
        }
      })
      .catch(() => undefined);

    return current;
  }

  #requireStation(serial: string): HomeBaseState {
    const station = this.#stations.get(serial);

    if (!station) {
      throw new Error(`Unknown HomeBase: ${serial}`);
    }

    return station;
  }

  #stationHasActiveMedia(stationSerial: string): boolean {
    return [...this.#ppcsStreams.keys()].some(
      (serial) =>
        this.#devices.get(serial)?.parentSerial === stationSerial,
    );
  }

  async #stopStationMedia(stationSerial: string): Promise<void> {
    const serials = [...this.#ppcsStreams.keys()].filter(
      (serial) =>
        this.#devices.get(serial)?.parentSerial === stationSerial,
    );

    await Promise.all(
      serials.map(
        (serial) => this.stopStream(serial),
      ),
    );
  }

  #queuePushSnapshot(events: ProviderEvents, event: MegaPushEvent): void {
    const previous =
      this.#pushSnapshotQueues.get(event.cameraSerial) ??
      Promise.resolve();

    const current = previous
      .then(async () => {
        const picture = await downloadPushSnapshot(
          this.#client,
          event,
          this.#devices,
        );

        if (picture) {
          events.snapshot(
            event.cameraSerial,
            picture.data,
            "image/jpeg",
          );
        }
      })
      .catch((error: unknown) => {
        logger.warn(
          "push_snapshot_unavailable",
          `Eufy push snapshot unavailable: ${safeError(error)}`,
        );
      });

    this.#pushSnapshotQueues.set(
      event.cameraSerial,
      current,
    );

    void current
      .finally(() => {
        if (
          this.#pushSnapshotQueues.get(event.cameraSerial) === current
        ) {
          this.#pushSnapshotQueues.delete(event.cameraSerial);
        }
      })
      .catch(() => undefined);
  }
}

/** Download and decode the image referenced by one normalized push event. */
export async function downloadPushSnapshot(
  client: Pick<MegaClient, "download">,
  event: Pick<MegaPushEvent, "pictureUrl" | "stationSerial">,
  devices: ReadonlyMap<string, Pick<MegaInventoryDevice, "p2pDid">>,
): Promise<{ data: Buffer } | null> {
  if (!event.pictureUrl) return null;

  const encoded = await client.download(event.pictureUrl);

  if (isJpeg(encoded)) {
    return { data: encoded };
  }

  const p2pDid =
    devices.get(event.stationSerial)?.p2pDid;

  if (!p2pDid) {
    throw new Error(
      "event image cannot be decoded without its HomeBase identity",
    );
  }

  const decoded =
    decodeEventImage(
      encoded,
      p2pDid,
    );

  if (!isJpeg(decoded)) {
    throw new Error(
      "event image is not a valid JPEG",
    );
  }

  return {
    data: decoded,
  };
}

/** Parse and normalize the untrusted device list returned by Mega. */
export function parseMegaInventory(response: unknown): MegaInventoryDevice[] {
  if (
    !isRecord(response) ||
    !Array.isArray(response.devices)
  ) {
    return [];
  }

  const devices: MegaInventoryDevice[] = [];
  const seen = new Set<string>();

  for (const value of response.devices) {
    if (!isRecord(value)) continue;

    const serial =
      safeValue(
        value.device_sn,
        128,
      );

    if (!serial || seen.has(serial)) continue;

    seen.add(serial);

    const model =
      safeValue(
        value.device_model,
        100,
      ) ??
      "Unknown Eufy device";

    devices.push({
      serial,
      name:
        safeValue(
          value.device_name,
          100,
        ) ??
        model,
      model,
      parentSerial:
        safeValue(
          value.parent_sn,
          128,
        ) ??
        safeValue(
          value.station_sn,
          128,
        ) ??
        "",
      deviceType:
        integer(
          value.device_type,
        ),
      category:
        safeValue(
          value.category,
          100,
        ),
      channel:
        integer(
          value.device_channel,
        ) ??
        integer(
          value.channel,
        ),
      p2pDid:
        safeValue(
          value.p2p_did,
          128,
        ),
      p2pConnection:
        safeValue(
          value.p2p_conn,
          512,
        ) ??
        safeValue(
          value.app_conn,
          512,
        ),
      cipherId:
        integer(
          value.cipher_id,
        ),
      adminUserId:
        isRecord(value.member)
          ? safeValue(
            value.member.admin_user_id,
            128,
          )
          : null,
      userName:
        isRecord(value.member)
          ? safeValue(
            value.member.nick_name,
            128,
          )
          : null,
      firmware:
        safeValue(
          value.main_sw_version,
          100,
        ),
    });
  }

  const adminUserIds =
    new Map(
      devices
        .filter(
          (device) =>
            device.adminUserId,
        )
        .map(
          (device) =>
            [
              device.serial,
              device.adminUserId!,
            ],
        ),
    );

  return devices.map(
    (device) =>
      device.adminUserId ||
      !device.parentSerial
        ? device
        : {
          ...device,
          adminUserId:
            adminUserIds.get(
              device.parentSerial,
            ) ??
            null,
        },
  );
}

/** Return whether normalized inventory identifies the supported HomeBase 3. */
export function isHomeBase3(
  device: Pick<MegaInventoryDevice, "category" | "deviceType" | "model">,
): boolean {
  return (
    device.category === "eufy_security" &&
    device.deviceType === 18 &&
    device.model.startsWith("T8030")
  );
}

function initialHomeBaseState(
  device: MegaInventoryDevice,
): HomeBaseState {
  return {
    serial: device.serial,
    name: device.name,
    model: device.model,
    firmware: device.firmware,
    available: true,
    connected: false,
    guardMode: null,
    effectiveMode: null,
    alarmActive: null,
    alarmVolume: null,
    promptVolume: null,
    alarmTone: null,
    storage: {
      emmc: null,
      hdd: null,
    },
  };
}

function mergeHomeBaseState(
  existing: HomeBaseState,
  observed: HomeBasePpcsState,
): HomeBaseState {
  return {
    ...existing,
    firmware:
      observed.firmware ??
      existing.firmware,
    connected: true,
    guardMode: observed.guardMode,
    effectiveMode: observed.effectiveMode,
    alarmVolume: observed.alarmVolume,
    promptVolume: observed.promptVolume,
    alarmTone: observed.alarmTone,
    storage:
      observed.storage ??
      existing.storage,
  };
}

function validGuardMode(
  value: number | null,
): value is number {
  return (
    value !== null &&
    [0, 1, 2, 3, 4, 5, 47, 63].includes(value)
  );
}

/** Explain camera filtering decisions without exposing raw cloud payloads. */
export function inventoryDiagnostics(
  devices: readonly MegaInventoryDevice[],
): InventoryDiagnostic[] {
  return devices.map(
    (device) => ({
      serial: device.serial,
      name: device.name,
      model: device.model,
      sources: ["mega"],
      upstreamIsCamera: false,
      acceptedAsCamera:
        isSupportedMegaCamera(device),
      megaDeviceType:
        device.deviceType,
      category:
        device.category,
    }),
  );
}

/**
 * Group inventory classifications without exposing names or device serials.
 *
 * @param devices Normalized Mega inventory rows.
 * @param dskStationSerials Stations whose short-lived PPCS key was retrieved.
 * @returns Groups that explain camera acceptance and live-stream readiness.
 */
export function inventoryLogSummaries(
  devices: readonly MegaInventoryDevice[],
  dskStationSerials: ReadonlySet<string>,
): InventoryLogSummary[] {
  const bySerial =
    new Map(
      devices.map(
        (device) => [
          device.serial,
          device,
        ],
      ),
    );

  const groups =
    new Map<
      string,
      InventoryLogSummary
    >();

  for (const device of devices) {
    const station =
      device.parentSerial
        ? bySerial.get(
          device.parentSerial,
        )
        : undefined;

    const route =
      isSupportedMegaCamera(device)
        ? ppcsStreamRoute(
          device,
          bySerial,
        )
        : null;

    const peer =
      route?.peer;

    const streamRoute:
      InventoryLogSummary["streamRoute"] =
      route
        ? (
          route.homeBaseAttached
            ? "homebase"
            : "direct"
        )
        : "unavailable";

    const values = {
      model: device.model,
      deviceType:
        device.deviceType,
      category:
        device.category,
      hasParent:
        device.parentSerial.length > 0,
      hasChannel:
        device.channel !== null,
      acceptedAsCamera:
        isSupportedMegaCamera(device),
      stationPresent:
        station !== undefined,
      stationPpcsReady:
        Boolean(
          station?.p2pDid &&
          station.p2pConnection,
        ),
      stationDskReady:
        Boolean(
          station &&
          dskStationSerials.has(
            station.serial,
          ),
        ),
      streamRoute,
      peerPpcsReady:
        Boolean(
          peer?.p2pDid &&
          peer.p2pConnection,
        ),
      peerDskReady:
        Boolean(
          peer &&
          dskStationSerials.has(
            peer.serial,
          ),
        ),
      streamSupported:
        isPpcsStreamSupported(
          device,
          bySerial,
          dskStationSerials,
        ),
    };

    const key =
      JSON.stringify(values);

    const existing =
      groups.get(key);

    groups.set(
      key,
      {
        count:
          (existing?.count ?? 0) +
          1,
        ...values,
      },
    );
  }

  return [...groups.values()];
}

/** Return whether Mega metadata identifies a device as a supported camera. */
export function isSupportedMegaCamera(
  device: Pick<MegaInventoryDevice, "category" | "deviceType">,
): boolean {
  return (
    device.category === "eufy_security" &&
    (
      device.deviceType === 7 ||
      device.deviceType === 8 ||
      device.deviceType === 19 ||
      device.deviceType === 23 ||
      device.deviceType === 26 ||
      device.deviceType === 47 ||
      device.deviceType === 48 ||
      device.deviceType === 151 ||
      device.deviceType === 31 ||
      device.deviceType === 63 ||
      device.deviceType === 91 ||
      device.deviceType === 94 ||
      device.deviceType === 104 ||
      device.deviceType === 10005 ||
      device.deviceType === 10031
    )
  );
}

/**
 * Identify the peer that provides PPCS connectivity for one camera.
 *
 * A HomeBase child uses its parent station. A parentless row or a row that
 * names itself as its station is a standalone camera and owns its own peer
 * connection. A missing non-self parent remains unavailable rather than being
 * guessed as a direct camera.
 */
export function ppcsStreamRoute(
  device: MegaInventoryDevice,
  devicesBySerial: ReadonlyMap<string, MegaInventoryDevice>,
): PpcsStreamRoute | null {
  if (
    !device.parentSerial ||
    device.parentSerial === device.serial
  ) {
    return {
      peer: device,
      homeBaseAttached: false,
    };
  }

  const station =
    devicesBySerial.get(
      device.parentSerial,
    );

  return station
    ? {
      peer: station,
      homeBaseAttached: true,
    }
    : null;
}

/** Return whether the selected PPCS peer has every prerequisite to stream. */
export function isPpcsStreamSupported(
  device: MegaInventoryDevice,
  devicesBySerial: ReadonlyMap<string, MegaInventoryDevice>,
  dskPeerSerials: ReadonlySet<string>,
): boolean {
  if (!isSupportedMegaCamera(device)) {
    return false;
  }

  const route =
    ppcsStreamRoute(
      device,
      devicesBySerial,
    );

  return Boolean(
    route?.peer.p2pDid &&
    route.peer.p2pConnection &&
    device.channel !== null &&
    dskPeerSerials.has(
      route.peer.serial,
    ),
  );
}

/**
 * Summarize push routing for copyable logs without private device or event fields.
 *
 * @param stationPresent Whether the station serial matched any Mega inventory row.
 * @param stationManaged Whether the station has a supported local control entity.
 */
export function safePushLogSummary(
  event: Pick<
    MegaPushEvent,
    "eventType" | "messageType" | "notificationStyle" | "pictureUrl" | "alarmType"
  >,
  device: Pick<MegaInventoryDevice, "model" | "category" | "deviceType"> | null,
  stationPresent: boolean,
  stationManaged: boolean,
): string {
  const deviceKnown =
    device !== null;

  const cameraAccepted =
    device !== null &&
    isSupportedMegaCamera(device);

  let handling =
    "unhandled";

  if (
    stationManaged &&
    event.eventType === 9
  ) {
    handling =
      "station_guard";
  } else if (
    stationManaged &&
    event.eventType === 10 &&
    event.alarmType !== null
  ) {
    handling =
      "station_alarm";
  } else if (
    cameraAccepted &&
    event.eventType === 3103 &&
    device !== null &&
    isDoorbellDevice(device)
  ) {
    handling =
      "doorbell_press";
  } else if (
    cameraAccepted &&
    isCameraDetection(
      event.eventType,
    )
  ) {
    handling =
      event.eventType === 3101
        ? "motion"
        : "person";
  }

  const model =
    device?.model &&
    /^T[0-9]{3,4}(?:[A-Z]{1,2}|-[A-Z]{1,2})?$/.test(
      device.model,
    )
      ? device.model
      : "unknown";

  return [
    `model=${model}`,
    `device_known=${deviceKnown}`,
    `camera_accepted=${cameraAccepted}`,
    `station_present=${stationPresent}`,
    `station_managed=${stationManaged}`,
    `event_type=${safePushCode(event.eventType)}`,
    `message_type=${safePushCode(event.messageType)}`,
    `notification_style=${safePushCode(event.notificationStyle)}`,
    `handling=${handling}`,
    `picture_present=${event.pictureUrl !== null}`,
  ].join(" ");
}

function safePushCode(
  value: number | null,
): number | "missing" {
  return (
    value !== null &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= 65_535
  )
    ? value
    : "missing";
}

/** Extract a recognized name only from push events that represent a person. */
export function personNameFromPush(
  message: Pick<MegaPushEvent, "eventType" | "personName" | "content">,
): string | null {
  const structured =
    safeLabel(
      message.personName,
    );

  if (structured) {
    return isGenericPersonLabel(
      structured,
    )
      ? null
      : structured;
  }

  if (
    message.eventType !== 3102 &&
    message.eventType !== 3111
  ) {
    return null;
  }

  const content =
    message.content?.trim();

  if (
    !content ||
    content.length > 300
  ) {
    return null;
  }

  const match =
    /^(?:[^:]{1,100}:\s*)?(.{1,100}?)\s+(?:has been|was)\s+(?:spotted|detected)(?:\b|[.!])/i.exec(
      content,
    );

  const candidate =
    safeLabel(
      match?.[1] ??
      null,
    );

  return (
    candidate &&
    !isGenericPersonLabel(candidate)
  )
    ? candidate
    : null;
}

function isCameraDetection(
  eventType: number | null,
): boolean {
  return (
    eventType === 3101 ||
    eventType === 3102 ||
    eventType === 3111 ||
    eventType === 3112
  );
}

/** Identify supported Mega doorbells that should expose a press sensor. */
export function isDoorbellDevice(
  device: Pick<MegaInventoryDevice, "deviceType" | "category">,
): boolean {
  return (
    device.category === "eufy_security" &&
    [7, 91, 94, 10031].includes(
      device.deviceType ?? -1,
    )
  );
}

function isGenericPersonLabel(
  value: string,
): boolean {
  return /^(someone|stranger|unknown|unknown person|person)$/i.test(
    value,
  );
}

function safeError(
  error: unknown,
): string {
  return error instanceof Error
    ? (
      error.message ||
      error.name
    )
    : "Unknown error";
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

function safeValue(
  value: unknown,
  maxLength: number,
): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const candidate =
    value.trim();

  return (
    candidate.length > 0 &&
    candidate.length <= maxLength
  )
    ? candidate
    : null;
}

function safeLabel(
  value:
    | string
    | null
    | undefined,
): string | null {
  return safeValue(
    value,
    100,
  );
}

function integer(
  value: unknown,
): number | null {
  const parsed =
    typeof value === "number"
      ? value
      : typeof value === "string"
        ? Number.parseInt(
          value,
          10,
        )
        : NaN;

  return Number.isSafeInteger(parsed)
    ? parsed
    : null;
}