const SENSITIVE_KEY_RE = /token|password|secret|key|dsn|authorization|cookie/i;

const URL_QUERY_SECRET_RE = /([?&#])(token|password|secret|key|dsn|api[_-]?key|auth)(=)([^&\s#"']*)/gi;

// Catch loose key=value pairs in log lines that aren't inside a URL — e.g. env
// dumps, command-line args, or json-line meta. The leading boundary stops it
// from matching mid-identifier (e.g. `not_a_token`).
const BARE_SECRET_RE = /(^|[\s,;])(token|password|secret|api[_-]?key|auth(?:orization)?)(=|:\s*)([^\s,;"']+)/gi;

const REDACTED = "[REDACTED]";

export interface RedactionOptions {
  username?: string | undefined;
}

export function redactJsonValue(value: unknown, opts: RedactionOptions = {}): unknown {
  if (Array.isArray(value)) return value.map((entry) => redactJsonValue(entry, opts));
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
      if (SENSITIVE_KEY_RE.test(key) && typeof raw === "string" && raw.length > 0) {
        out[key] = REDACTED;
      } else {
        out[key] = redactJsonValue(raw, opts);
      }
    }
    return out;
  }
  if (typeof value === "string") return redactText(value, opts);
  return value;
}

export function redactText(text: string, opts: RedactionOptions = {}): string {
  let out = text.replace(URL_QUERY_SECRET_RE, (_match, sep, name, eq) => `${sep}${name}${eq}${REDACTED}`);
  out = out.replace(BARE_SECRET_RE, (_match, lead, name, sep) => `${lead}${name}${sep}${REDACTED}`);
  const username = opts.username;
  if (username && username.length > 1) {
    const escaped = username.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    out = out.replace(new RegExp(`/Users/${escaped}(?=[/"\\s])`, "g"), "/Users/<USER>");
    out = out.replace(new RegExp(`\\\\Users\\\\${escaped}(?=[\\\\"\\s])`, "g"), "\\Users\\<USER>");
    out = out.replace(new RegExp(`/home/${escaped}(?=[/"\\s])`, "g"), "/home/<USER>");
  }
  return out;
}

export function redactJsonText(text: string, opts: RedactionOptions = {}): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return redactText(text, opts);
  }
  return JSON.stringify(redactJsonValue(parsed, opts), null, 2);
}
