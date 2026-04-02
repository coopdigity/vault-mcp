export class VaultClient {
  private baseUrl: string;
  private token: string = "";
  private username: string;
  private password: string;

  constructor() {
    const url = process.env.VAULT_ADDR;
    const username = process.env.VAULT_USERNAME;
    const password = process.env.VAULT_PASSWORD;

    if (!url || !username || !password) {
      throw new Error("VAULT_ADDR, VAULT_USERNAME, and VAULT_PASSWORD must be set");
    }

    this.baseUrl = url.replace(/\/+$/, "");
    this.username = username;
    this.password = password;
  }

  async login(): Promise<void> {
    const res = await fetch(`${this.baseUrl}/v1/auth/userpass/login/${this.username}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: this.password }),
    });

    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`Vault login failed (${res.status}): ${body.slice(0, 500)}`);
    }

    const data = (await res.json()) as { auth: { client_token: string; lease_duration: number } };
    this.token = data.auth.client_token;
  }

  private async ensureAuthenticated(): Promise<void> {
    if (!this.token) {
      await this.login();
    }
  }

  private async request(path: string, options: RequestInit = {}): Promise<Response> {
    await this.ensureAuthenticated();

    const res = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers: {
        "X-Vault-Token": this.token,
        ...(options.headers as Record<string, string>),
      },
    });

    // Re-authenticate on 403 (token expired) and retry once
    if (res.status === 403) {
      await this.login();
      const retry = await fetch(`${this.baseUrl}${path}`, {
        ...options,
        headers: {
          "X-Vault-Token": this.token,
          ...(options.headers as Record<string, string>),
        },
      });
      if (!retry.ok) {
        const body = await retry.text().catch(() => "");
        throw new Error(`Vault ${retry.status}: ${body.slice(0, 500)}`);
      }
      return retry;
    }

    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`Vault ${res.status}: ${body.slice(0, 500)}`);
    }

    return res;
  }

  async readSecret(path: string, engine: string = "ci", version?: number): Promise<string> {
    const versionParam = version ? `?version=${version}` : "";
    const res = await this.request(`/v1/${engine}/data/${path}${versionParam}`);
    const data = (await res.json()) as {
      data: {
        data: Record<string, string>;
        metadata: { version: number; created_time: string; destroyed: boolean; deletion_time: string };
      };
    };

    const secrets = data.data.data;
    const metadata = data.data.metadata;

    const lines: string[] = [];
    lines.push(`Path: ${engine}/data/${path}`);
    lines.push(`Version: ${metadata.version}`);
    lines.push(`Created: ${metadata.created_time}`);
    lines.push(`\nKeys (${Object.keys(secrets).length}):`);
    for (const [key, value] of Object.entries(secrets)) {
      lines.push(`  ${key} = ${value}`);
    }

    return lines.join("\n");
  }

  async listSecrets(path: string, engine: string = "ci"): Promise<string> {
    const listPath = path ? `/${path}` : "";
    const res = await this.request(`/v1/${engine}/metadata${listPath}`, {
      method: "LIST",
    });
    const data = (await res.json()) as { data: { keys: string[] } };

    if (!data.data?.keys?.length) return "No secrets found at this path.";

    const lines: string[] = [];
    lines.push(`Path: ${engine}/metadata${listPath}`);
    lines.push(`\nEntries (${data.data.keys.length}):`);
    for (const key of data.data.keys) {
      const isFolder = key.endsWith("/");
      lines.push(`  ${isFolder ? "📁" : "🔑"} ${key}`);
    }

    return lines.join("\n");
  }

  async writeSecret(path: string, data: Record<string, string>, engine: string = "ci"): Promise<string> {
    const res = await this.request(`/v1/${engine}/data/${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data }),
    });
    const result = (await res.json()) as {
      data: { version: number; created_time: string };
    };

    return `Secret written to ${engine}/data/${path}\nVersion: ${result.data.version}\nCreated: ${result.data.created_time}`;
  }

  async deleteSecret(path: string, engine: string = "ci", versions?: number[]): Promise<string> {
    if (versions?.length) {
      await this.request(`/v1/${engine}/delete/${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ versions }),
      });
      return `Soft-deleted versions [${versions.join(", ")}] at ${engine}/${path}`;
    }

    await this.request(`/v1/${engine}/data/${path}`, { method: "DELETE" });
    return `Deleted latest version at ${engine}/data/${path}`;
  }

  async getSecretMetadata(path: string, engine: string = "ci"): Promise<string> {
    const res = await this.request(`/v1/${engine}/metadata/${path}`);
    const data = (await res.json()) as {
      data: {
        current_version: number;
        max_versions: number;
        oldest_version: number;
        created_time: string;
        updated_time: string;
        versions: Record<string, { created_time: string; destroyed: boolean; deletion_time: string }>;
      };
    };

    const meta = data.data;
    const lines: string[] = [];
    lines.push(`Path: ${engine}/metadata/${path}`);
    lines.push(`Current version: ${meta.current_version}`);
    lines.push(`Oldest version: ${meta.oldest_version}`);
    lines.push(`Max versions: ${meta.max_versions}`);
    lines.push(`Created: ${meta.created_time}`);
    lines.push(`Updated: ${meta.updated_time}`);
    lines.push(`\nVersions:`);
    for (const [ver, info] of Object.entries(meta.versions)) {
      const status = info.destroyed ? "destroyed" : info.deletion_time ? "deleted" : "active";
      lines.push(`  v${ver}: ${status} (${info.created_time})`);
    }

    return lines.join("\n");
  }

  async listMounts(): Promise<string> {
    const res = await this.request("/v1/sys/mounts");
    const data = (await res.json()) as Record<string, { type: string; description: string; options?: Record<string, string> }>;

    const lines: string[] = [];
    lines.push("Secret Engines:\n");
    for (const [mountPath, mount] of Object.entries(data)) {
      if (mountPath === "request_id" || mountPath === "lease_id" || mountPath === "renewable" || mountPath === "lease_duration" || mountPath === "wrap_info" || mountPath === "warnings" || mountPath === "auth") continue;
      if (typeof mount !== "object" || !mount.type) continue;
      lines.push(`  ${mountPath} (${mount.type})${mount.description ? ` — ${mount.description}` : ""}`);
    }

    return lines.join("\n");
  }

  async getHealth(): Promise<string> {
    const res = await fetch(`${this.baseUrl}/v1/sys/health`, {
      headers: { "X-Vault-Token": this.token },
    });
    const data = (await res.json()) as {
      initialized: boolean;
      sealed: boolean;
      standby: boolean;
      server_time_utc: number;
      version: string;
      cluster_name: string;
    };

    const lines: string[] = [];
    lines.push(`Vault Health:`);
    lines.push(`  Version: ${data.version}`);
    lines.push(`  Cluster: ${data.cluster_name}`);
    lines.push(`  Initialized: ${data.initialized}`);
    lines.push(`  Sealed: ${data.sealed}`);
    lines.push(`  Standby: ${data.standby}`);

    return lines.join("\n");
  }
}
