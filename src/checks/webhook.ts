import { type Check, type Finding, type SourceFile, lineAt } from '../types.js';

const CODE = /\.(?:[cm]?[jt]sx?)$/;
const WEBHOOK_PATH = /webhook/i;
// Event names only a payment or auth provider sends: a route that handles one is a webhook.
const PROVIDER_EVENT =
  /checkout\.session\.|invoice\.(?:paid|payment_)|customer\.subscription\.|payment_intent\.|charge\.(?:succeeded|refunded)|stripe\.webhooks/;
const STRIPE = /stripe|checkout\.session\.|customer\.subscription\.|payment_intent\.|invoice\./i;
const PAGES_API = /(^|\/)pages\/api\/.+\.[cm]?[jt]sx?$/;
const HANDLER =
  /export\s+(?:async\s+)?(?:function\s+|const\s+)POST\b|\b(?:app|router|server|api|routes)\.post\s*\(/;
const PAGES_HANDLER = /export\s+default\b/;
// Anything that checks who sent the request: a signature, an HMAC, a provider SDK verifier or a
// shared secret. Broad on purpose: a missed route is better than a wall of false alarms.
const VERIFY =
  /constructEvent|svix|verif|signature|hmac|timingSafeEqual|whsec_|webhook[-_]?secret|x-hub-|authorization|bearer/i;

const isWebhook = (file: SourceFile): boolean =>
  CODE.test(file.path) &&
  !/\.(?:test|spec)\./.test(file.path) &&
  (HANDLER.test(file.text) || (PAGES_API.test(file.path) && PAGES_HANDLER.test(file.text))) &&
  (WEBHOOK_PATH.test(file.path) || PROVIDER_EVENT.test(file.text));

export const webhooks: Check = ({ files }) => {
  const findings: Finding[] = [];
  for (const file of files) {
    if (!isWebhook(file) || VERIFY.test(file.text)) continue;
    const stripe = STRIPE.test(file.text) || STRIPE.test(file.path);
    findings.push({
      rule: 'webhook/unverified',
      severity: stripe ? 'high' : 'medium',
      title: `${stripe ? 'Stripe webhook' : 'Webhook'} handler never checks who sent the request`,
      file: file.path,
      line: lineAt(
        file.text,
        Math.max(0, file.text.search(HANDLER.test(file.text) ? HANDLER : PAGES_HANDLER)),
      ),
      why: stripe
        ? 'Anyone can POST a fake "checkout.session.completed" to this URL and get a free upgrade or order, because nothing proves the call came from Stripe.'
        : 'The URL is public: anyone can POST a made-up event and trigger whatever the handler does.',
      fix: stripe
        ? 'Read the raw body, then call stripe.webhooks.constructEvent(rawBody, request.headers["stripe-signature"], process.env.STRIPE_WEBHOOK_SECRET) and return 400 when it throws.'
        : 'Verify the provider signature (or a shared secret header) before reading the body, and return 401 when it does not match.',
    });
  }
  return findings;
};
