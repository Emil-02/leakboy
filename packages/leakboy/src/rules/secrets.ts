import type { Severity } from "../types.js";

export interface SecretRule {
  id: string;
  name: string;
  severity: Severity;
  pattern: RegExp;
  /** Which capture group holds the secret (default 0). */
  group?: number;
  /** Return false to drop a match (e.g. placeholders, low entropy). */
  validate?: (value: string, context: string) => boolean;
  /** Where to rotate/revoke it. */
  rotate?: string;
  note?: string;
}

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

const PLACEHOLDER = /(x{6,}|\*{4,}|your[_-]?|example|placeholder|dummy|changeme|redacted|<[^>]+>|\.\.\.|0{10,}|1234567890)/i;

const notPlaceholder = (v: string) => !PLACEHOLDER.test(v);
const random = (min: number) => (v: string) => notPlaceholder(v) && entropy(v) >= min;

export function decodeJwtPayload(token: string): Record<string, unknown> | undefined {
  const part = token.split(".")[1];
  if (!part) return undefined;
  try {
    return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

export const SECRET_RULES: SecretRule[] = [
  {
    id: "supabase-service-role",
    name: "Supabase service_role key",
    severity: "critical",
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g,
    validate: (v) => {
      const p = decodeJwtPayload(v);
      return p?.role === "service_role" || p?.role === "supabase_admin";
    },
    rotate: "https://supabase.com/dashboard/project/_/settings/api-keys",
    note: "This key bypasses Row Level Security: anyone who has it can read and change every row in your database.",
  },
  {
    id: "supabase-secret-key",
    name: "Supabase secret key",
    severity: "critical",
    pattern: /\bsb_secret_[A-Za-z0-9_-]{20,}/g,
    validate: notPlaceholder,
    rotate: "https://supabase.com/dashboard/project/_/settings/api-keys",
    note: "Secret keys bypass Row Level Security and must only live on the server.",
  },
  {
    id: "stripe-secret-live",
    name: "Stripe live secret key",
    severity: "critical",
    pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/g,
    validate: notPlaceholder,
    rotate: "https://dashboard.stripe.com/apikeys",
  },
  {
    id: "stripe-secret-test",
    name: "Stripe test secret key",
    severity: "medium",
    pattern: /\b(?:sk|rk)_test_[A-Za-z0-9]{20,}/g,
    validate: notPlaceholder,
    rotate: "https://dashboard.stripe.com/test/apikeys",
  },
  {
    id: "stripe-webhook-secret",
    name: "Stripe webhook signing secret",
    severity: "high",
    pattern: /\bwhsec_[A-Za-z0-9]{24,}/g,
    validate: random(3.5),
    rotate: "https://dashboard.stripe.com/webhooks",
  },
  {
    id: "openai",
    name: "OpenAI API key",
    severity: "critical",
    pattern: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}|\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{58,}/g,
    validate: random(4),
    rotate: "https://platform.openai.com/api-keys",
  },
  {
    id: "anthropic",
    name: "Anthropic API key",
    severity: "critical",
    pattern: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}/g,
    validate: notPlaceholder,
    rotate: "https://console.anthropic.com/settings/keys",
  },
  {
    id: "openrouter",
    name: "OpenRouter API key",
    severity: "critical",
    pattern: /\bsk-or-v1-[a-f0-9]{64}\b/g,
    rotate: "https://openrouter.ai/settings/keys",
  },
  {
    id: "groq",
    name: "Groq API key",
    severity: "critical",
    pattern: /\bgsk_[A-Za-z0-9]{48,}\b/g,
    validate: random(4),
    rotate: "https://console.groq.com/keys",
  },
  {
    id: "xai",
    name: "xAI API key",
    severity: "critical",
    pattern: /\bxai-[A-Za-z0-9]{70,}\b/g,
    validate: random(4),
    rotate: "https://console.x.ai",
  },
  {
    id: "huggingface",
    name: "Hugging Face token",
    severity: "high",
    pattern: /\bhf_[A-Za-z0-9]{34,}\b/g,
    validate: random(4),
    rotate: "https://huggingface.co/settings/tokens",
  },
  {
    id: "replicate",
    name: "Replicate API token",
    severity: "high",
    pattern: /\br8_[A-Za-z0-9]{37}\b/g,
    validate: random(4),
    rotate: "https://replicate.com/account/api-tokens",
  },
  {
    id: "google-ai",
    name: "Google AI (Gemini) API key",
    severity: "high",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    // Firebase web keys are public by design; only flag keys used against the Gemini API.
    validate: (_v, ctx) => /generativelanguage\.googleapis\.com|GoogleGenerativeAI|GoogleGenAI|gemini-[\d.]+-(?:pro|flash)/i.test(ctx),
    rotate: "https://aistudio.google.com/app/apikey",
    note: "Google API keys are fine in Firebase configs, but this one sits next to Gemini API calls, so anyone can spend your AI quota.",
  },
  {
    id: "aws-access-key",
    name: "AWS access key ID",
    severity: "high",
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    validate: (v) => notPlaceholder(v) && !/EXAMPLE$/.test(v),
    rotate: "https://console.aws.amazon.com/iam/home#/security_credentials",
  },
  {
    id: "aws-secret-key",
    name: "AWS secret access key",
    severity: "critical",
    pattern: /aws.{0,20}?secret.{0,20}?["'`:=\s]+([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])/gi,
    group: 1,
    validate: random(4.3),
    rotate: "https://console.aws.amazon.com/iam/home#/security_credentials",
  },
  {
    id: "github-token",
    name: "GitHub token",
    severity: "critical",
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g,
    validate: random(4),
    rotate: "https://github.com/settings/tokens",
  },
  {
    id: "gitlab-token",
    name: "GitLab token",
    severity: "critical",
    pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    validate: random(3.5),
    rotate: "https://gitlab.com/-/user_settings/personal_access_tokens",
  },
  {
    id: "slack-token",
    name: "Slack token",
    severity: "high",
    pattern: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g,
    validate: notPlaceholder,
    rotate: "https://api.slack.com/apps",
  },
  {
    id: "slack-webhook",
    name: "Slack incoming webhook",
    severity: "medium",
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/g,
    rotate: "https://api.slack.com/apps",
  },
  {
    id: "discord-webhook",
    name: "Discord webhook",
    severity: "medium",
    pattern: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{60,}/g,
  },
  {
    id: "telegram-bot",
    name: "Telegram bot token",
    severity: "high",
    pattern: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g,
    rotate: "https://t.me/BotFather",
  },
  {
    id: "sendgrid",
    name: "SendGrid API key",
    severity: "high",
    pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    rotate: "https://app.sendgrid.com/settings/api_keys",
  },
  {
    id: "resend",
    name: "Resend API key",
    severity: "high",
    pattern: /\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{24,}\b/g,
    validate: random(3.5),
    rotate: "https://resend.com/api-keys",
  },
  {
    id: "mailgun",
    name: "Mailgun API key",
    severity: "high",
    pattern: /\bkey-[a-f0-9]{32}\b/g,
    validate: random(3.5),
  },
  {
    id: "twilio",
    name: "Twilio API key",
    severity: "high",
    pattern: /\bSK[a-f0-9]{32}\b/g,
    validate: (v, ctx) => random(3.5)(v) && /twilio/i.test(ctx),
  },
  {
    id: "midtrans-server",
    name: "Midtrans server key",
    severity: "critical",
    pattern: /\b(?:SB-)?Mid-server-[A-Za-z0-9_-]{20,}/g,
    validate: notPlaceholder,
    rotate: "https://dashboard.midtrans.com/settings/config_info",
  },
  {
    id: "xendit",
    name: "Xendit secret key",
    severity: "critical",
    pattern: /\bxnd_(?:production|development)_[A-Za-z0-9]{40,}/g,
    validate: notPlaceholder,
    rotate: "https://dashboard.xendit.co/settings/developers#api-keys",
  },
  {
    id: "private-key",
    name: "Private key",
    severity: "critical",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
    note: "A private key is embedded in client-side code.",
  },
  {
    id: "firebase-service-account",
    name: "Google service account credentials",
    severity: "critical",
    pattern: /"type"\s*:\s*"service_account"/g,
    validate: (_v, ctx) => /private_key/.test(ctx),
    rotate: "https://console.cloud.google.com/iam-admin/serviceaccounts",
  },
  {
    id: "database-url",
    name: "Database connection string with password",
    severity: "critical",
    pattern: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?):\/\/[^:\s"'`/@]+:([^@\s"'`/]{6,})@[^\s"'`]+/g,
    validate: (v) => {
      const pw = /:\/\/[^:]+:([^@]+)@/.exec(v)?.[1] ?? "";
      return notPlaceholder(pw) && !/^(password|pass|postgres|root|secret|\$\{|%s|\{)/i.test(pw);
    },
  },
  {
    id: "jwt-secret",
    name: "JWT / session signing secret",
    severity: "high",
    pattern: /\b(?:JWT_SECRET|NEXTAUTH_SECRET|AUTH_SECRET|SESSION_SECRET|SUPABASE_JWT_SECRET)["'`]?\s*[:=]\s*["'`]([^"'`\s]{16,})["'`]/g,
    group: 1,
    validate: random(3.5),
  },
];

/** Shows just enough of a secret to recognise it, never enough to use it. */
export function maskSecret(value: string): string {
  if (value.startsWith("-----BEGIN")) return value;
  if (value.length <= 12) return `${value.slice(0, 2)}${"•".repeat(6)}`;
  const head = Math.min(8, Math.floor(value.length / 4));
  return `${value.slice(0, head)}${"•".repeat(8)}${value.slice(-4)}`;
}
