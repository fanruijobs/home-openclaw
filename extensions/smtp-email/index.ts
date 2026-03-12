import fs from "node:fs/promises";
import path from "node:path";
import net from "node:net";
import tls from "node:tls";
import { Type } from "@sinclair/typebox";
import type { AnyAgentTool, OpenClawPluginApi } from "openclaw/plugin-sdk";

type PluginConfig = {
  host?: string;
  port?: number;
  username?: string;
  password?: string;
  from?: string;
  useSsl?: boolean;
  useTls?: boolean;
};

type ResolvedConfig = {
  host: string;
  port: number;
  username?: string;
  password?: string;
  from: string;
  useSsl: boolean;
  useTls: boolean;
};

type ToolParams = {
  to: string | string[];
  subject: string;
  body?: string;
  html?: string;
  cc?: string | string[];
  bcc?: string | string[];
  from?: string;
  attach?: string | string[];
  smtp_host?: string;
  smtp_port?: number;
  smtp_username?: string;
  smtp_password?: string;
  use_ssl?: boolean;
  use_tls?: boolean;
  dry_run?: boolean;
};

const smtpEmailConfigSchema = {
  parse(value: unknown): PluginConfig {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return {};
    }
    const raw = value as Record<string, unknown>;
    return {
      host: typeof raw.host === "string" ? raw.host : undefined,
      port: typeof raw.port === "number" ? raw.port : undefined,
      username: typeof raw.username === "string" ? raw.username : undefined,
      password: typeof raw.password === "string" ? raw.password : undefined,
      from: typeof raw.from === "string" ? raw.from : undefined,
      useSsl: typeof raw.useSsl === "boolean" ? raw.useSsl : undefined,
      useTls: typeof raw.useTls === "boolean" ? raw.useTls : undefined,
    };
  },
  uiHints: {
    host: { label: "SMTP Host" },
    port: { label: "SMTP Port" },
    username: { label: "SMTP Username" },
    password: { label: "SMTP Password", sensitive: true },
    from: { label: "From Address" },
    useSsl: { label: "Use SSL" },
    useTls: { label: "Use STARTTLS" },
  },
};

const SmtpEmailToolSchema = Type.Object({
  to: Type.Union([
    Type.String({ description: "Recipient email or comma-separated recipients." }),
    Type.Array(Type.String({ description: "Recipient email address." })),
  ]),
  subject: Type.String(),
  body: Type.Optional(Type.String({ description: "Plain-text body." })),
  html: Type.Optional(Type.String({ description: "HTML body." })),
  cc: Type.Optional(
    Type.Union([
      Type.String({ description: "CC recipient or comma-separated recipients." }),
      Type.Array(Type.String()),
    ]),
  ),
  bcc: Type.Optional(
    Type.Union([
      Type.String({ description: "BCC recipient or comma-separated recipients." }),
      Type.Array(Type.String()),
    ]),
  ),
  from: Type.Optional(Type.String({ description: "Override From address." })),
  attach: Type.Optional(
    Type.Union([
      Type.String({ description: "Attachment path or comma-separated attachment paths." }),
      Type.Array(Type.String({ description: "Attachment path." })),
    ]),
  ),
  smtp_host: Type.Optional(Type.String()),
  smtp_port: Type.Optional(Type.Number()),
  smtp_username: Type.Optional(Type.String()),
  smtp_password: Type.Optional(Type.String()),
  use_ssl: Type.Optional(Type.Boolean()),
  use_tls: Type.Optional(Type.Boolean()),
  dry_run: Type.Optional(Type.Boolean()),
});

function boolFromEnv(raw: string | undefined): boolean | undefined {
  if (raw == null) {
    return undefined;
  }
  const normalized = raw.trim().toLowerCase();
  if (!normalized) {
    return undefined;
  }
  return ["1", "true", "yes", "on"].includes(normalized);
}

function listify(value: string | string[] | undefined): string[] {
  if (Array.isArray(value)) {
    return value.map((item) => item.trim()).filter(Boolean);
  }
  if (typeof value !== "string") {
    return [];
  }
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function ensureNonEmpty(value: string | undefined, message: string): string {
  const trimmed = value?.trim();
  if (!trimmed) {
    throw new Error(message);
  }
  return trimmed;
}

function resolveConfig(toolParams: ToolParams, pluginConfig: PluginConfig): ResolvedConfig {
  const gmailUsername = process.env.GMAIL_USERNAME?.trim() || undefined;
  const gmailPassword = process.env.GMAIL_APP_PASSWORD?.trim() || undefined;

  const host =
    toolParams.smtp_host?.trim() ||
    pluginConfig.host?.trim() ||
    process.env.SMTP_HOST?.trim() ||
    (gmailUsername && gmailPassword ? "smtp.gmail.com" : undefined);
  const username =
    toolParams.smtp_username?.trim() ||
    pluginConfig.username?.trim() ||
    process.env.SMTP_USERNAME?.trim() ||
    gmailUsername;
  const password =
    toolParams.smtp_password?.trim() ||
    pluginConfig.password?.trim() ||
    process.env.SMTP_PASSWORD?.trim() ||
    gmailPassword;
  const from =
    toolParams.from?.trim() ||
    pluginConfig.from?.trim() ||
    process.env.SMTP_FROM?.trim() ||
    username ||
    gmailUsername;

  const envPortRaw = process.env.SMTP_PORT?.trim();
  const envPort = envPortRaw ? Number.parseInt(envPortRaw, 10) : undefined;
  const port =
    toolParams.smtp_port ||
    pluginConfig.port ||
    envPort ||
    (host === "smtp.gmail.com" && gmailUsername && gmailPassword ? 465 : 587);

  const useSsl =
    toolParams.use_ssl ??
    pluginConfig.useSsl ??
    boolFromEnv(process.env.SMTP_USE_SSL) ??
    (host === "smtp.gmail.com" && gmailUsername && gmailPassword ? true : port === 465);
  const useTls =
    toolParams.use_tls ?? pluginConfig.useTls ?? boolFromEnv(process.env.SMTP_USE_TLS) ?? false;

  return {
    host: ensureNonEmpty(host, "SMTP host is required."),
    port,
    username,
    password,
    from: ensureNonEmpty(from, "SMTP from address is required."),
    useSsl,
    useTls,
  };
}

function encodeBase64Utf8(text: string): string {
  return Buffer.from(text, "utf8").toString("base64");
}

function escapeSmtpData(text: string): string {
  return text.replace(/\r?\n/g, "\r\n").replace(/^\./gm, "..");
}

function guessMimeType(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case ".txt":
      return "text/plain";
    case ".html":
    case ".htm":
      return "text/html";
    case ".json":
      return "application/json";
    case ".pdf":
      return "application/pdf";
    case ".csv":
      return "text/csv";
    case ".jpg":
    case ".jpeg":
      return "image/jpeg";
    case ".png":
      return "image/png";
    default:
      return "application/octet-stream";
  }
}

async function buildMimeMessage(params: {
  from: string;
  to: string[];
  cc: string[];
  subject: string;
  body?: string;
  html?: string;
  attachments: string[];
}): Promise<string> {
  const headers = [
    `From: ${params.from}`,
    `To: ${params.to.join(", ")}`,
    ...(params.cc.length > 0 ? [`Cc: ${params.cc.join(", ")}`] : []),
    `Subject: ${params.subject}`,
    "MIME-Version: 1.0",
  ];

  const textBody = params.body?.trim();
  const htmlBody = params.html?.trim();
  if (!textBody && !htmlBody) {
    throw new Error("Either body or html is required.");
  }

  if (params.attachments.length === 0 && textBody && !htmlBody) {
    return [
      ...headers,
      'Content-Type: text/plain; charset="utf-8"',
      "Content-Transfer-Encoding: base64",
      "",
      encodeBase64Utf8(textBody),
      "",
    ].join("\r\n");
  }

  const mixedBoundary = `openclaw-mixed-${Date.now().toString(36)}`;
  const altBoundary = `openclaw-alt-${(Date.now() + 1).toString(36)}`;
  const parts: string[] = [
    ...headers,
    `Content-Type: multipart/mixed; boundary="${mixedBoundary}"`,
    "",
    `--${mixedBoundary}`,
  ];

  if (textBody && htmlBody) {
    parts.push(
      `Content-Type: multipart/alternative; boundary="${altBoundary}"`,
      "",
      `--${altBoundary}`,
      'Content-Type: text/plain; charset="utf-8"',
      "Content-Transfer-Encoding: base64",
      "",
      encodeBase64Utf8(textBody),
      "",
      `--${altBoundary}`,
      'Content-Type: text/html; charset="utf-8"',
      "Content-Transfer-Encoding: base64",
      "",
      encodeBase64Utf8(htmlBody),
      "",
      `--${altBoundary}--`,
      "",
    );
  } else if (htmlBody) {
    parts.push(
      'Content-Type: text/html; charset="utf-8"',
      "Content-Transfer-Encoding: base64",
      "",
      encodeBase64Utf8(htmlBody),
      "",
    );
  } else if (textBody) {
    parts.push(
      'Content-Type: text/plain; charset="utf-8"',
      "Content-Transfer-Encoding: base64",
      "",
      encodeBase64Utf8(textBody),
      "",
    );
  }

  for (const attachment of params.attachments) {
    const data = await fs.readFile(attachment);
    const filename = path.basename(attachment);
    parts.push(
      `--${mixedBoundary}`,
      `Content-Type: ${guessMimeType(attachment)}; name="${filename}"`,
      "Content-Transfer-Encoding: base64",
      `Content-Disposition: attachment; filename="${filename}"`,
      "",
      data.toString("base64"),
      "",
    );
  }

  parts.push(`--${mixedBoundary}--`, "");
  return parts.join("\r\n");
}

class SmtpClient {
  private socket: net.Socket | tls.TLSSocket | null = null;
  private buffer = "";
  private lines: string[] = [];
  private waiters: Array<(line: string) => void> = [];

  constructor(
    private readonly host: string,
    private readonly port: number,
    private readonly useSsl: boolean,
  ) {}

  private attachSocket(socket: net.Socket | tls.TLSSocket) {
    this.socket = socket;
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      this.buffer += chunk;
      while (true) {
        const idx = this.buffer.indexOf("\n");
        if (idx === -1) {
          break;
        }
        const line = this.buffer.slice(0, idx + 1).replace(/\r?\n$/, "");
        this.buffer = this.buffer.slice(idx + 1);
        if (this.waiters.length > 0) {
          const waiter = this.waiters.shift();
          waiter?.(line);
        } else {
          this.lines.push(line);
        }
      }
    });
  }

  private async readLine(): Promise<string> {
    if (this.lines.length > 0) {
      return this.lines.shift() ?? "";
    }
    return await new Promise((resolve) => {
      this.waiters.push(resolve);
    });
  }

  private async readResponse(): Promise<{ code: number; message: string }> {
    const lines: string[] = [];
    let code = 0;
    while (true) {
      const line = await this.readLine();
      lines.push(line);
      const match = /^(\d{3})([ -])(.*)$/.exec(line);
      if (!match) {
        throw new Error(`Invalid SMTP response: ${line}`);
      }
      code = Number.parseInt(match[1] ?? "0", 10);
      if (match[2] === " ") {
        return { code, message: lines.join("\n") };
      }
    }
  }

  async connect(timeoutMs: number): Promise<void> {
    const socket = this.useSsl
      ? tls.connect({
          host: this.host,
          port: this.port,
          servername: this.host,
          timeout: timeoutMs,
        })
      : net.connect({ host: this.host, port: this.port, timeout: timeoutMs });
    await new Promise<void>((resolve, reject) => {
      socket.once("error", reject);
      if (this.useSsl) {
        socket.once("secureConnect", () => resolve());
      } else {
        socket.once("connect", () => resolve());
      }
    });
    this.attachSocket(socket);
    const greeting = await this.readResponse();
    if (greeting.code !== 220) {
      throw new Error(`SMTP connect failed: ${greeting.message}`);
    }
  }

  async command(line: string, expectedCodes: number[]): Promise<string> {
    if (!this.socket) {
      throw new Error("SMTP socket not connected.");
    }
    this.socket.write(`${line}\r\n`);
    const response = await this.readResponse();
    if (!expectedCodes.includes(response.code)) {
      throw new Error(`SMTP command failed (${line}): ${response.message}`);
    }
    return response.message;
  }

  async startTls(timeoutMs: number): Promise<void> {
    if (!this.socket || this.socket instanceof tls.TLSSocket) {
      return;
    }
    await this.command("STARTTLS", [220]);
    const upgraded = tls.connect({
      socket: this.socket,
      servername: this.host,
      timeout: timeoutMs,
    });
    await new Promise<void>((resolve, reject) => {
      upgraded.once("error", reject);
      upgraded.once("secureConnect", () => resolve());
    });
    this.buffer = "";
    this.lines = [];
    this.waiters = [];
    this.attachSocket(upgraded);
  }

  async quit(): Promise<void> {
    try {
      await this.command("QUIT", [221]);
    } catch {
      // ignore
    }
    this.socket?.end();
  }
}

async function sendMail(params: {
  config: ResolvedConfig;
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  body?: string;
  html?: string;
  attachments: string[];
  timeoutMs: number;
}): Promise<void> {
  const client = new SmtpClient(params.config.host, params.config.port, params.config.useSsl);
  try {
    await client.connect(params.timeoutMs);
    await client.command("EHLO openclaw.local", [250]);
    if (!params.config.useSsl && params.config.useTls) {
      await client.startTls(params.timeoutMs);
      await client.command("EHLO openclaw.local", [250]);
    }
    if (params.config.username) {
      await client.command("AUTH LOGIN", [334]);
      await client.command(Buffer.from(params.config.username, "utf8").toString("base64"), [334]);
      await client.command(Buffer.from(params.config.password ?? "", "utf8").toString("base64"), [
        235,
      ]);
    }
    await client.command(`MAIL FROM:<${params.config.from}>`, [250]);
    for (const recipient of [...params.to, ...params.cc, ...params.bcc]) {
      await client.command(`RCPT TO:<${recipient}>`, [250, 251]);
    }
    await client.command("DATA", [354]);
    const mime = await buildMimeMessage({
      from: params.config.from,
      to: params.to,
      cc: params.cc,
      subject: params.subject,
      body: params.body,
      html: params.html,
      attachments: params.attachments,
    });
    await client.command(`${escapeSmtpData(mime)}\r\n.`, [250]);
  } finally {
    await client.quit();
  }
}

export const __testing = {
  buildMimeMessage,
  listify,
  resolveConfig,
};

const plugin = {
  id: "smtp-email",
  name: "SMTP Email",
  description: "Send outbound email through SMTP.",
  configSchema: smtpEmailConfigSchema,
  register(api: OpenClawPluginApi) {
    const pluginConfig = smtpEmailConfigSchema.parse(api.pluginConfig);

    api.registerTool({
      name: "smtp-email",
      label: "SMTP Email",
      description:
        "Send email through SMTP. Supports plain text, HTML, cc, bcc, attachments, SSL, and STARTTLS.",
      parameters: SmtpEmailToolSchema,
      async execute(_id: string, rawParams: Record<string, unknown>) {
        const params = rawParams as unknown as ToolParams;
        const to = listify(params.to);
        const cc = listify(params.cc);
        const bcc = listify(params.bcc);
        const attachments = listify(params.attach);
        if (to.length === 0) {
          throw new Error("At least one recipient is required in `to`.");
        }
        const config = resolveConfig(params, pluginConfig);
        const subject = ensureNonEmpty(params.subject, "subject is required.");
        const body = params.body?.trim();
        const html = params.html?.trim();

        if (params.dry_run) {
          return {
            content: [
              {
                type: "text" as const,
                text:
                  `Dry run: would send email to ${to.join(", ")} with subject "${subject}". ` +
                  `Host=${config.host}:${config.port} ssl=${String(config.useSsl)} tls=${String(config.useTls)}`,
              },
            ],
            details: {
              dryRun: true,
              to,
              cc,
              bcc,
              subject,
              from: config.from,
              host: config.host,
              port: config.port,
            },
          };
        }

        await sendMail({
          config,
          to,
          cc,
          bcc,
          subject,
          body,
          html,
          attachments,
          timeoutMs: 30_000,
        });
        return {
          content: [
            {
              type: "text" as const,
              text: `Sent email to ${to.join(", ")} with subject "${subject}".`,
            },
          ],
          details: { to, cc, bcc, subject, from: config.from, host: config.host, port: config.port },
        };
      },
    } as AnyAgentTool);
  },
};

export default plugin;
