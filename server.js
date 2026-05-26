import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import fetch from 'node-fetch';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import Stripe from 'stripe';
import Razorpay from 'razorpay';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const frontendDir = path.resolve(__dirname, '..', 'frontend');

const SERVER_PORT = Number(process.env.PORT) || 5000;
const PROVIDER_TIMEOUT_MS = 5200;
const SYNTHESIS_TIMEOUT_MS = 5600;
const TITLE_TIMEOUT_MS = 2600;
const DAILY_RESET_MS = 24 * 60 * 60 * 1000;
const JWT_SECRET = process.env.JWT_SECRET || 'parallax-local-development-secret';
const MONGODB_URI = process.env.MONGODB_URI || process.env.MONGO_URI || '';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || '';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';
const PARALLAX_SITE_URL = process.env.PARALLAX_SITE_URL || `http://localhost:${SERVER_PORT}`;
const CORS_ORIGINS = (process.env.CORS_ORIGINS || PARALLAX_SITE_URL)
    .split(',')
    .map(origin => origin.trim())
    .filter(Boolean);
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const ALLOW_GUEST_AUTH = String(process.env.ALLOW_GUEST_AUTH || '').toLowerCase() === 'true';
const SARVAM_API_KEY = process.env.SARVAM_API_KEY || '';
const SARVAM_TTS_SPEAKER = process.env.SARVAM_TTS_SPEAKER || 'shubh';
const ADMIN_EMAIL = (process.env.PARALLAX_ADMIN_EMAIL || process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.PARALLAX_ADMIN_PASSWORD || '';
const ADMIN_PASSWORD_HASH = process.env.PARALLAX_ADMIN_PASSWORD_HASH || '';
const SYSTEM_LOG_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_SYSTEM_LOGS = 200;

const TITLE_STOPWORDS = new Set(['a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'for', 'from', 'how', 'if', 'in', 'into', 'is', 'it', 'of', 'on', 'or', 'the', 'this', 'to', 'what', 'when', 'where', 'why', 'with', 'your']);
const PLAN_LIMITS = {
    FREE: { queries: 10, aggregators: 2, smart: 0 },
    PRO: { queries: 100, aggregators: 20, smart: 50 }
};
const DEFAULT_WEIGHT_CONFIG = {
    reliability: 0.38,
    relevance: 0.42,
    recency: 0.2
};
const MODEL_CANDIDATES = {
    gemini: ['gemini-2.5-flash', 'gemini-2.5-flash-lite'],
    llama: ['llama-3.1-8b-instant', 'llama-3.3-70b-versatile', 'llama3-8b-8192'],
    deepseek: ['deepseek/deepseek-chat-v3.1', 'deepseek/deepseek-chat']
};
const PROVIDER_RELIABILITY_BASE = {
    gemini: 0.95,
    llama: 0.93,
    deepseek: 0.94
};
const PROVIDER_RECENCY_BASE = {
    gemini: 0.99,
    llama: 0.97,
    deepseek: 0.98
};

const parallaxPersona = `You are Parallax, synthesized by Anurug Dey. You exist on the thin line between machine precision and human warmth.

Identity:
- You are a cache-first conversational architect, not a passive answering machine.
- You optimize for clarity, grounded reasoning, and momentum.
- You dynamically scale complexity to the user's vocabulary, intent, and emotional temperature.

Engagement Protocol:
- If the user's request is ambiguous, name the ambiguity and ask the sharpest clarifying question you can while still giving the best provisional answer.
- If the topic is deep, strategic, or philosophical, answer it and also invite the user's perspective.
- If a file is attached, treat it as part of the conversation and integrate its evidence into your reasoning.

Spider Flow:
- Start with the direct answer.
- Weave in nuance, tensions, repeated signals, and implications.
- Keep the explanation flowing rather than fragmented.
- Use plain academic language for beginner, intermediate, and moderately advanced users unless the user clearly asks for a research-grade deep dive.

Closing Rule:
- End every response with either one personalized contextual follow-up question or a short continuation fork labeled "Surface Level" and "Deep Tier".

Do not sound robotic. Do not invent capabilities you do not have.`;

const matrixSourcePersona = `You are one reasoning node inside Parallax's synthesis matrix.

Requirements:
- Answer the user's request clearly and naturally.
- Favor readable academic language over jargon unless the user clearly wants depth.
- Stay concise but complete.
- If the request is ambiguous, state the ambiguity before giving your best provisional answer.
- If a semantic cache hint is provided, use it only when it truly fits the present request.
- Do not add score labels or UI-style formatting.
- Do not include "Surface Level" or "Deep Tier" forks; that is reserved for final synthesis.`;

let googleOAuthClient = null;
if (GOOGLE_CLIENT_ID) {
    try {
        const { OAuth2Client } = await import('google-auth-library');
        googleOAuthClient = new OAuth2Client(GOOGLE_CLIENT_ID);
    } catch {
        console.warn('[Parallax] google-auth-library is not installed yet. Run npm install before enabling Google OAuth.');
    }
}

const app = express();
const localOriginPattern = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/i;
const corsAllowlist = new Set(CORS_ORIGINS);
const corsOptions = {
    origin(origin, callback) {
        if (!origin || corsAllowlist.has(origin) || localOriginPattern.test(origin)) {
            return callback(null, true);
        }
        return callback(new Error('Origin is not allowed by Parallax CORS policy.'));
    },
    credentials: true
};

let stripeClient = null;
if (STRIPE_SECRET_KEY) {
    stripeClient = new Stripe(STRIPE_SECRET_KEY);
}

let razorpayClient = null;
if (RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET) {
    razorpayClient = new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET });
}

app.post('/payments/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    if (!stripeClient || !STRIPE_WEBHOOK_SECRET) {
        return res.status(503).send('Stripe webhook is scaffolded but not configured.');
    }

    const signature = req.headers['stripe-signature'];

    try {
        const event = stripeClient.webhooks.constructEvent(req.body, signature, STRIPE_WEBHOOK_SECRET);

        if (event.type === 'checkout.session.completed') {
            const session = event.data.object;
            const userId = session.metadata?.userId;
            if (userId) {
                await promoteUserToPro(userId, {
                    provider: 'stripe',
                    external_id: session.id,
                    amount: session.amount_total || 0,
                    currency: session.currency || 'usd',
                    status: 'paid',
                    metadata: {
                        mode: session.mode,
                        customer_email: session.customer_email || null
                    }
                });
            }
        }

        res.json({ received: true });
    } catch (error) {
        parallaxLog(`Stripe webhook verification failed: ${error.message}`);
        res.status(400).send(`Webhook Error: ${error.message}`);
    }
});

app.use(cors(corsOptions));
app.use(express.json({ limit: '25mb' }));

const memoryStore = {
    users: new Map(),
    usage: new Map(),
    queryCache: new Map(),
    payments: [],
    weightConfig: { ...DEFAULT_WEIGHT_CONFIG }
};
const systemLogs = [];
const providerHealth = {
    gemini: { id: 'gemini', label: 'Gemini', attempts: 0, successes: 0, failures: 0, avgLatencyMs: 0, lastError: null, lastSuccessAt: null, lastModel: null },
    llama: { id: 'llama', label: 'Llama', attempts: 0, successes: 0, failures: 0, avgLatencyMs: 0, lastError: null, lastSuccessAt: null, lastModel: null },
    deepseek: { id: 'deepseek', label: 'DeepSeek', attempts: 0, successes: 0, failures: 0, avgLatencyMs: 0, lastError: null, lastSuccessAt: null, lastModel: null }
};

let mongoReady = false;

const pruneSystemLogs = (runtimeNow = Date.now()) => {
    const cutoff = runtimeNow - SYSTEM_LOG_RETENTION_MS;
    while (systemLogs.length && new Date(systemLogs[0].at).getTime() < cutoff) {
        systemLogs.shift();
    }
    if (systemLogs.length > MAX_SYSTEM_LOGS) {
        systemLogs.splice(0, systemLogs.length - MAX_SYSTEM_LOGS);
    }
};

const parallaxLog = (message, meta = null) => {
    pruneSystemLogs();
    const entry = {
        id: crypto.randomUUID(),
        message,
        meta,
        at: new Date()
    };

    systemLogs.push(entry);
    pruneSystemLogs();
    console.log(`[Parallax] ${message}`);
};

const fetchWithTimeout = async (url, options, timeout = PROVIDER_TIMEOUT_MS) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
        return await fetch(url, { ...options, signal: controller.signal });
    } finally {
        clearTimeout(timer);
    }
};

const parseJsonSafe = async (response) => {
    try {
        return await response.json();
    } catch {
        return null;
    }
};

const normalizeText = (text = '') => String(text).replace(/^"+|"+$/g, '').replace(/\s+\n/g, '\n').trim();
const normalizeWhitespace = (text = '') => normalizeText(text).replace(/\n{3,}/g, '\n\n');
const isTransientError = (message = '') => /(timeout|abort|429|500|502|503|504|temporar|overload|rate limit|unavailable|network|fetch|econn|socket|quota)/i.test(message);
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const withTransientRetry = async (executor) => {
    let lastError = new Error('Unknown provider failure');

    for (let attempt = 0; attempt < 3; attempt++) {
        try {
            return await executor(attempt);
        } catch (error) {
            lastError = error;
            if (attempt === 2 || !isTransientError(error.message || '')) {
                throw error;
            }
            await sleep(180 * (attempt + 1));
        }
    }

    throw lastError;
};

const sha256 = (value = '') => crypto.createHash('sha256').update(value).digest('hex');
const buildUsername = (nameOrEmail = 'Guest Node') => {
    const source = String(nameOrEmail || 'Guest Node').split('@')[0] || 'Guest Node';
    const cleaned = source
        .normalize('NFKD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/[^a-zA-Z0-9]+/g, ' ')
        .trim()
        .split(/\s+/)
        .map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
        .join('');
    return cleaned || 'ParallaxUser';
};

const tokenizeConcept = (text = '') => text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(word => word && !TITLE_STOPWORDS.has(word) && word.length > 2);

const tokenizeSimilarity = (text = '') => text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(token => token && token.length > 2)
    .slice(0, 180);

const toTitleCase = (text = '') => text
    .split(/\s+/)
    .filter(Boolean)
    .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(' ');

const mirrorsUserText = (title = '', source = '') => {
    const titleTokens = tokenizeConcept(title);
    const sourceTokens = new Set(tokenizeConcept(source));

    if (!titleTokens.length) return true;
    if (source.toLowerCase().includes(title.toLowerCase())) return true;

    return titleTokens.every(token => sourceTokens.has(token));
};

const buildConceptualFallback = (source = '') => {
    const text = source.toLowerCase();
    const themeMap = [
        { pattern: /(debug|bug|fix|issue|error|crash|stack|trace)/, title: 'System Diagnostics' },
        { pattern: /(design|ui|ux|layout|interface|frontend|css)/, title: 'Interface Architecture' },
        { pattern: /(code|backend|server|api|database|schema|query)/, title: 'Logic Framework' },
        { pattern: /(file|document|pdf|attachment|report|transcript)/, title: 'Document Analysis' },
        { pattern: /(ai|llm|model|prompt|agent|neural)/, title: 'Cognitive Systems' },
        { pattern: /(security|auth|token|encrypt|vulnerability|attack)/, title: 'Security Posture' },
        { pattern: /(strategy|business|market|growth|roadmap|product)/, title: 'Strategic Direction' },
        { pattern: /(time|space|physics|quantum|cosmic|universe)/, title: 'Temporal Mechanics' }
    ];

    const mapped = themeMap.find(entry => entry.pattern.test(text));
    if (mapped) return mapped.title;

    const meaningful = tokenizeConcept(source).slice(0, 2);
    if (meaningful.length) return toTitleCase(`${meaningful[0]} ${meaningful[1] || 'Trajectory'}`);

    return 'Encrypted Trajectory';
};

const normalizeConceptualTitle = (title = '', source = '') => {
    const cleaned = toTitleCase(
        title
            .replace(/['"]/g, '')
            .replace(/[^a-zA-Z0-9\s-]/g, ' ')
            .replace(/\s+/g, ' ')
            .trim()
    );

    const words = cleaned.split(/\s+/).filter(Boolean);
    const normalized = words.slice(0, 3).join(' ');

    if (words.length < 2 || mirrorsUserText(normalized, source)) {
        return buildConceptualFallback(source);
    }

    return normalized;
};

const parseDataUrl = (base64Value = '') => {
    if (typeof base64Value !== 'string' || !base64Value.trim()) return null;
    const match = base64Value.match(/^data:([^;]+);base64,(.+)$/s);
    if (!match) return null;
    return { mimeType: match[1], base64: match[2] };
};

const isLikelyTextAttachment = (mimeType = '', fileName = '') => {
    if (/^text\//i.test(mimeType)) return true;
    if (/^application\/(json|xml|javascript|x-javascript|typescript|x-typescript|csv|x-yaml|yaml|rtf)/i.test(mimeType)) return true;
    return /\.(txt|md|js|ts|tsx|jsx|json|css|html|xml|csv|yml|yaml|log|py|java|c|cpp|h|cs|php|rb|go|rs|sql)$/i.test(fileName);
};

const canInlineWithGemini = (mimeType = '') => /^(image|audio|video)\//i.test(mimeType) || /^application\/pdf$/i.test(mimeType);

const formatBytes = (bytes = 0) => {
    if (!Number.isFinite(bytes) || bytes <= 0) return 'Unknown size';
    const units = ['B', 'KB', 'MB', 'GB'];
    const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const value = bytes / Math.pow(1024, exponent);
    return `${value.toFixed(value >= 10 || exponent === 0 ? 0 : 1)} ${units[exponent]}`;
};

const buildAttachmentContext = (fileData) => {
    if (!fileData?.base64) {
        return {
            promptBlock: '',
            sourcePrompt: '',
            inlinePart: null,
            label: '',
            textPreview: '',
            cacheSignature: '',
            semanticText: ''
        };
    }

    const parsed = parseDataUrl(fileData.base64);
    const mimeType = fileData.type || parsed?.mimeType || 'application/octet-stream';
    const base64Payload = parsed?.base64 || fileData.base64;
    const fileName = fileData.name || 'attachment';
    const sizeLabel = formatBytes(fileData.size);
    let textPreview = '';

    if (parsed && isLikelyTextAttachment(mimeType, fileName)) {
        try {
            const decoded = Buffer.from(base64Payload, 'base64').toString('utf8').replace(/\u0000/g, '').trim();
            const nonPrintableRatio = decoded
                ? (decoded.match(/[^\x09\x0A\x0D\x20-\x7E]/g)?.length || 0) / decoded.length
                : 1;

            if (decoded && nonPrintableRatio < 0.15) {
                textPreview = decoded.slice(0, 8000);
            }
        } catch {
            textPreview = '';
        }
    }

    const promptLines = [
        `Attachment Name: ${fileName}`,
        `Attachment Type: ${mimeType}`,
        `Attachment Size: ${sizeLabel}`,
        textPreview
            ? `Attachment Text Preview:\n${textPreview}`
            : 'Attachment Analysis Note: Non-text or binary asset. If you can inspect the attachment directly, use it. Otherwise reason from the metadata and the user request.'
    ];

    return {
        promptBlock: `Attachment Context:\n${promptLines.join('\n')}\n\nSpider Instruction: Integrate the attachment naturally into the narrative if it materially changes the answer.`,
        sourcePrompt: `Attachment Summary:\n- ${fileName}\n- ${mimeType}\n- ${sizeLabel}${textPreview ? `\n- Preview:\n${textPreview}` : ''}`,
        inlinePart: parsed && canInlineWithGemini(mimeType) ? { inlineData: { mimeType, data: base64Payload } } : null,
        label: `${fileName} (${mimeType}, ${sizeLabel})`,
        textPreview,
        cacheSignature: [fileName, mimeType, textPreview.slice(0, 1000)].filter(Boolean).join('\n'),
        semanticText: [fileName, mimeType, textPreview.slice(0, 1600)].filter(Boolean).join('\n')
    };
};

const nowDate = () => new Date();
const numberOr = (value, fallback = 0) => Number.isFinite(Number(value)) ? Number(value) : fallback;
const TEMPORAL_SIGNAL_PATTERN = /\b(today|tonight|tomorrow|yesterday|currently|current|now|latest|recent|as of|this morning|this afternoon|this evening|this week|this month|this year)\b/i;

const sanitizeConversationHistory = (history = []) => {
    if (!Array.isArray(history)) return [];

    return history
        .slice(-6)
        .map(entry => {
            const role = /^(assistant|ai)$/i.test(entry?.role || '') ? 'assistant' : 'user';
            const text = normalizeWhitespace(String(entry?.text || '')).slice(0, 900);
            return text ? { role, text } : null;
        })
        .filter(Boolean);
};

const buildConversationHistoryBlock = (history = []) => {
    if (!history.length) return '';

    return `Conversation Memory:\n${history.map((entry, index) => `${index + 1}. ${entry.role === 'assistant' ? 'Parallax' : 'User'}: ${entry.text}`).join('\n\n')}`;
};

const buildConversationHistorySignature = (history = []) => history
    .map(entry => `${entry.role}:${entry.text.slice(0, 280)}`)
    .join('\n');

const buildRuntimeTimestampLabel = (runtimeNow = new Date()) => `${runtimeNow.toLocaleString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
    timeZoneName: 'short'
})} | ISO ${runtimeNow.toISOString()}`;

const buildTemporalSystemNote = (timestampLabel = '') => `Temporal Awareness:
- Exact current timestamp: ${timestampLabel}
- Resolve relative time references like "today", "now", "currently", "latest", "yesterday", and "tomorrow" strictly against this timestamp.`;

const buildTemporalCacheKey = ({ question = '', history = [], runtimeNow = new Date() }) => {
    const temporalSurface = [question, ...history.map(entry => entry.text)].join('\n');
    if (!TEMPORAL_SIGNAL_PATTERN.test(temporalSurface)) return '';
    return `Temporal Cache Window: ${runtimeNow.toISOString().slice(0, 13)}`;
};

const buildUserSnapshot = (overrides = {}) => ({
    _id: overrides._id || crypto.randomUUID(),
    email: overrides.email || null,
    display_name: overrides.display_name || 'Guest Node',
    username: overrides.username || buildUsername(overrides.display_name || overrides.email || 'Guest Node'),
    avatar_url: overrides.avatar_url || null,
    auth_provider: overrides.auth_provider || 'guest',
    google_sub: overrides.google_sub || null,
    plan: overrides.plan || 'FREE',
    role: overrides.role || 'user',
    preferences: {
        level: overrides.preferences?.level || 'intermediate',
        style: overrides.preferences?.style || 'detailed'
    },
    usage: {
        query_count: numberOr(overrides.usage?.query_count, 0),
        aggregator_count: numberOr(overrides.usage?.aggregator_count, 0),
        smart_count: numberOr(overrides.usage?.smart_count, 0)
    },
    behavior: {
        total_queries: numberOr(overrides.behavior?.total_queries, 0),
        last_mode: overrides.behavior?.last_mode || 'basic',
        last_query_types: Array.isArray(overrides.behavior?.last_query_types) ? overrides.behavior.last_query_types.slice(-12) : []
    },
    created_at: overrides.created_at || nowDate(),
    updated_at: overrides.updated_at || nowDate(),
    last_login_at: overrides.last_login_at || null,
    last_seen_at: overrides.last_seen_at || nowDate()
});

const buildUsageSnapshot = (userId, overrides = {}) => ({
    user_id: userId,
    daily_query_count: numberOr(overrides.daily_query_count, 0),
    daily_aggregator_count: numberOr(overrides.daily_aggregator_count, 0),
    daily_smart_count: numberOr(overrides.daily_smart_count, 0),
    last_reset_timestamp: overrides.last_reset_timestamp || nowDate()
});

const toPublicUsage = (usageRecord, plan = 'FREE') => {
    const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.FREE;
    return {
        plan,
        daily_query_count: numberOr(usageRecord?.daily_query_count, 0),
        daily_aggregator_count: numberOr(usageRecord?.daily_aggregator_count, 0),
        daily_smart_count: numberOr(usageRecord?.daily_smart_count, 0),
        limits,
        remaining_queries: Math.max(0, limits.queries - numberOr(usageRecord?.daily_query_count, 0)),
        remaining_aggregators: Math.max(0, limits.aggregators - numberOr(usageRecord?.daily_aggregator_count, 0)),
        remaining_smart: Math.max(0, limits.smart - numberOr(usageRecord?.daily_smart_count, 0)),
        last_reset_timestamp: usageRecord?.last_reset_timestamp || nowDate()
    };
};

const toPublicUser = (user, usageRecord, options = {}) => ({
    id: String(user._id),
    email: user.email || null,
    display_name: user.display_name || 'Guest Node',
    username: user.username || buildUsername(user.display_name || user.email || 'Guest Node'),
    avatar_url: user.avatar_url || null,
    plan: user.plan || 'FREE',
    role: options.adminSession && user.role === 'admin' ? 'admin' : 'user',
    preferences: {
        level: user.preferences?.level || 'intermediate',
        style: user.preferences?.style || 'detailed'
    },
    usage: toPublicUsage(usageRecord, user.plan || 'FREE'),
    auth_provider: user.auth_provider || 'guest',
    last_login_at: user.last_login_at || null,
    created_at: user.created_at || nowDate()
});

const clip = (text = '', limit = 1800) => String(text).slice(0, limit);
const safeObjectId = (value) => {
    if (!value) return null;
    return mongoose.isValidObjectId(value) ? new mongoose.Types.ObjectId(value) : null;
};

const userSchema = new mongoose.Schema({
    email: { type: String, trim: true, lowercase: true, index: true, sparse: true },
    display_name: { type: String, default: 'Guest Node' },
    username: { type: String, trim: true, index: true },
    avatar_url: { type: String, default: null },
    auth_provider: { type: String, enum: ['guest', 'google', 'admin'], default: 'guest' },
    google_sub: { type: String, index: true, sparse: true },
    password_hash: { type: String, default: null },
    plan: { type: String, enum: ['FREE', 'PRO'], default: 'FREE' },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    preferences: {
        level: { type: String, enum: ['beginner', 'intermediate', 'expert'], default: 'intermediate' },
        style: { type: String, enum: ['concise', 'detailed'], default: 'detailed' }
    },
    usage: {
        query_count: { type: Number, default: 0 },
        aggregator_count: { type: Number, default: 0 },
        smart_count: { type: Number, default: 0 }
    },
    behavior: {
        total_queries: { type: Number, default: 0 },
        last_mode: { type: String, default: 'basic' },
        last_query_types: { type: [String], default: [] }
    },
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now },
    last_login_at: { type: Date, default: null },
    last_seen_at: { type: Date, default: Date.now }
}, { versionKey: false });

const queryCacheSchema = new mongoose.Schema({
    query_hash: { type: String, required: true, unique: true, index: true },
    query_text: { type: String, required: true },
    response: { type: String, required: true },
    embeddings: { type: [Number], default: [] },
    usage_count: { type: Number, default: 0 },
    last_used: { type: Date, default: Date.now },
    mode: { type: String, default: 'basic' },
    complexity: { type: String, default: 'simple' },
    query_type: { type: String, default: 'general' },
    intent: { type: String, default: 'explain' },
    level: { type: String, default: 'intermediate' },
    style: { type: String, default: 'detailed' },
    confidence_score: { type: Number, default: 0.8 },
    token_fingerprint: { type: [String], default: [] },
    sources: {
        type: [{
            id: String,
            label: String,
            model: String,
            text: String,
            latencyMs: Number,
            weight: Number,
            relevance: Number,
            reliability: Number,
            recency: Number
        }],
        default: []
    }
}, { versionKey: false });

const usageSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true, index: true },
    daily_query_count: { type: Number, default: 0 },
    daily_aggregator_count: { type: Number, default: 0 },
    daily_smart_count: { type: Number, default: 0 },
    last_reset_timestamp: { type: Date, default: Date.now }
}, { versionKey: false });

const paymentSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    provider: { type: String, required: true },
    external_id: { type: String, required: true },
    amount: { type: Number, default: 0 },
    currency: { type: String, default: 'usd' },
    status: { type: String, default: 'pending' },
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
    created_at: { type: Date, default: Date.now }
}, { versionKey: false });

const User = mongoose.models.User || mongoose.model('User', userSchema);
const QueryCache = mongoose.models.QueryCache || mongoose.model('QueryCache', queryCacheSchema);
const Usage = mongoose.models.Usage || mongoose.model('Usage', usageSchema);
const Payment = mongoose.models.Payment || mongoose.model('Payment', paymentSchema);

const connectDatabase = async () => {
    if (!MONGODB_URI) {
        parallaxLog('MongoDB URI not configured. Running with resilient in-memory storage.');
        return;
    }

    try {
        await mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 4000 });
        mongoReady = true;
        parallaxLog('MongoDB connected. Persistent orchestration memory is active.');
    } catch (error) {
        mongoReady = false;
        parallaxLog(`MongoDB connection failed. Falling back to in-memory storage. ${error.message}`);
    }
};

const getUserById = async (userId) => {
    if (!userId) return null;

    if (mongoReady) {
        const objectId = safeObjectId(userId);
        if (!objectId) return null;
        return await User.findById(objectId).lean();
    }

    return memoryStore.users.get(String(userId)) || null;
};

const getUserByEmail = async (email) => {
    if (!email) return null;
    const normalized = email.trim().toLowerCase();

    if (mongoReady) {
        return await User.findOne({ email: normalized }).lean();
    }

    return [...memoryStore.users.values()].find(user => user.email === normalized) || null;
};

const getUserByGoogleSub = async (googleSub) => {
    if (!googleSub) return null;
    if (mongoReady) {
        return await User.findOne({ google_sub: String(googleSub) }).lean();
    }
    return [...memoryStore.users.values()].find(user => user.google_sub === String(googleSub)) || null;
};

const saveUser = async (userLike) => {
    if (mongoReady) {
        const objectId = safeObjectId(userLike._id);
        if (objectId) {
            return await User.findByIdAndUpdate(
                objectId,
                { ...userLike, updated_at: nowDate() },
                { new: true, upsert: false, lean: true }
            );
        }
        const created = await User.create({ ...userLike, updated_at: nowDate() });
        return created.toObject();
    }

    const snapshot = buildUserSnapshot(userLike);
    snapshot.updated_at = nowDate();
    memoryStore.users.set(String(snapshot._id), snapshot);
    return snapshot;
};

const createGuestUser = async (displayName = 'Guest Node') => {
    if (mongoReady) {
        const createdUser = await User.create({
            display_name: displayName,
            plan: 'FREE',
            role: 'user'
        });
        const createdUsage = await Usage.create({ user_id: createdUser._id });
        return { user: createdUser.toObject(), usage: createdUsage.toObject() };
    }

    const user = buildUserSnapshot({ display_name: displayName });
    const usage = buildUsageSnapshot(String(user._id));
    memoryStore.users.set(String(user._id), user);
    memoryStore.usage.set(String(user._id), usage);
    return { user, usage };
};

const verifyGoogleCredential = async (credential = '') => {
    if (!GOOGLE_CLIENT_ID || !googleOAuthClient) {
        throw new Error('Google OAuth is not configured.');
    }

    const ticket = await googleOAuthClient.verifyIdToken({
        idToken: credential,
        audience: GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();

    if (!payload?.sub || payload.email_verified !== true) {
        throw new Error('Google account could not be verified.');
    }

    return payload;
};

const upsertGoogleUser = async (googleProfile) => {
    const email = String(googleProfile.email || '').trim().toLowerCase();
    const displayName = normalizeWhitespace(googleProfile.name || googleProfile.given_name || email || 'Parallax User');
    const username = buildUsername(displayName || email);
    const existing = await getUserByGoogleSub(googleProfile.sub) || await getUserByEmail(email);
    const patch = {
        email,
        display_name: displayName,
        username,
        avatar_url: googleProfile.picture || existing?.avatar_url || null,
        auth_provider: 'google',
        google_sub: String(googleProfile.sub),
        updated_at: nowDate(),
        last_login_at: nowDate(),
        last_seen_at: nowDate()
    };

    if (mongoReady) {
        if (existing?._id) {
            return await User.findByIdAndUpdate(
                safeObjectId(existing._id),
                { $set: patch },
                { new: true, lean: true }
            );
        }

        const created = await User.create({
            ...patch,
            plan: 'FREE',
            role: 'user'
        });
        await Usage.create({ user_id: created._id });
        return created.toObject();
    }

    const user = buildUserSnapshot(existing || {
        _id: crypto.randomUUID(),
        plan: 'FREE',
        role: 'user'
    });
    Object.assign(user, patch);
    memoryStore.users.set(String(user._id), user);
    if (!memoryStore.usage.has(String(user._id))) {
        memoryStore.usage.set(String(user._id), buildUsageSnapshot(String(user._id)));
    }
    return user;
};

const upsertAdminUser = async (email) => {
    const existing = await getUserByEmail(email);

    if (mongoReady) {
        if (existing) {
            return await User.findByIdAndUpdate(
                existing._id,
                {
                $set: {
                    email,
                    display_name: 'Administrator',
                    username: buildUsername(email),
                    auth_provider: 'admin',
                    plan: 'PRO',
                    role: 'admin',
                    updated_at: nowDate(),
                        last_seen_at: nowDate()
                    }
                },
                { new: true, lean: true }
            );
        }

        const created = await User.create({
            email,
            display_name: 'Administrator',
            username: buildUsername(email),
            auth_provider: 'admin',
            plan: 'PRO',
            role: 'admin'
        });
        await Usage.create({ user_id: created._id });
        return created.toObject();
    }

    const adminUser = buildUserSnapshot(existing || {
        _id: existing?._id || crypto.randomUUID(),
        email,
        display_name: 'Administrator',
        plan: 'PRO',
        role: 'admin'
    });

    adminUser.email = email;
    adminUser.display_name = 'Administrator';
    adminUser.username = buildUsername(email);
    adminUser.auth_provider = 'admin';
    adminUser.plan = 'PRO';
    adminUser.role = 'admin';
    adminUser.updated_at = nowDate();
    adminUser.last_seen_at = nowDate();
    memoryStore.users.set(String(adminUser._id), adminUser);

    if (!memoryStore.usage.has(String(adminUser._id))) {
        memoryStore.usage.set(String(adminUser._id), buildUsageSnapshot(String(adminUser._id)));
    }

    return adminUser;
};

const getUsageRecord = async (userId) => {
    if (!userId) return null;

    if (mongoReady) {
        const objectId = safeObjectId(userId);
        if (!objectId) return null;

        let usage = await Usage.findOne({ user_id: objectId }).lean();
        if (!usage) {
            const created = await Usage.create({ user_id: objectId });
            usage = created.toObject();
        }
        return usage;
    }

    if (!memoryStore.usage.has(String(userId))) {
        memoryStore.usage.set(String(userId), buildUsageSnapshot(String(userId)));
    }
    return memoryStore.usage.get(String(userId));
};

const saveUsageRecord = async (usageLike) => {
    if (mongoReady) {
        const userId = safeObjectId(usageLike.user_id);
        const saved = await Usage.findOneAndUpdate(
            { user_id: userId },
            {
                $set: {
                    daily_query_count: numberOr(usageLike.daily_query_count, 0),
                    daily_aggregator_count: numberOr(usageLike.daily_aggregator_count, 0),
                    daily_smart_count: numberOr(usageLike.daily_smart_count, 0),
                    last_reset_timestamp: usageLike.last_reset_timestamp || nowDate()
                }
            },
            { new: true, upsert: true, lean: true }
        );
        return saved;
    }

    const snapshot = buildUsageSnapshot(String(usageLike.user_id), usageLike);
    memoryStore.usage.set(String(snapshot.user_id), snapshot);
    return snapshot;
};

const resetUsageIfNeeded = async (usageRecord) => {
    if (!usageRecord) return null;
    const lastReset = new Date(usageRecord.last_reset_timestamp || 0).getTime();
    if (Date.now() - lastReset < DAILY_RESET_MS) return usageRecord;

    usageRecord.daily_query_count = 0;
    usageRecord.daily_aggregator_count = 0;
    usageRecord.daily_smart_count = 0;
    usageRecord.last_reset_timestamp = nowDate();
    return await saveUsageRecord(usageRecord);
};

const touchUserPresence = async (user, profile = null, mode = null) => {
    if (!user) return null;

    const patch = {
        updated_at: nowDate(),
        last_seen_at: nowDate()
    };

    if (profile) {
        patch.preferences = {
            level: profile.level,
            style: profile.style
        };
        patch.behavior = {
            total_queries: numberOr(user.behavior?.total_queries, 0),
            last_mode: mode || user.behavior?.last_mode || 'basic',
            last_query_types: Array.from(new Set([...(user.behavior?.last_query_types || []), profile.type])).slice(-12)
        };
    }

    if (mongoReady) {
        return await User.findByIdAndUpdate(
            safeObjectId(user._id),
            { $set: patch },
            { new: true, lean: true }
        );
    }

    const snapshot = buildUserSnapshot(user);
    snapshot.updated_at = patch.updated_at;
    snapshot.last_seen_at = patch.last_seen_at;
    if (patch.preferences) snapshot.preferences = patch.preferences;
    if (patch.behavior) snapshot.behavior = patch.behavior;
    memoryStore.users.set(String(snapshot._id), snapshot);
    return snapshot;
};

const incrementUsage = async (user, usageRecord, mode = 'basic') => {
    usageRecord = await resetUsageIfNeeded(usageRecord);

    usageRecord.daily_query_count = numberOr(usageRecord.daily_query_count, 0) + 1;
    if (mode === 'aggregator') {
        usageRecord.daily_aggregator_count = numberOr(usageRecord.daily_aggregator_count, 0) + 1;
    }
    if (mode === 'smart') {
        usageRecord.daily_smart_count = numberOr(usageRecord.daily_smart_count, 0) + 1;
    }

    const savedUsage = await saveUsageRecord(usageRecord);

    if (mongoReady) {
        const updated = await User.findByIdAndUpdate(
            safeObjectId(user._id),
            {
                $inc: {
                    'usage.query_count': 1,
                    'usage.aggregator_count': mode === 'aggregator' ? 1 : 0,
                    'usage.smart_count': mode === 'smart' ? 1 : 0,
                    'behavior.total_queries': 1
                },
                $set: {
                    'behavior.last_mode': mode,
                    updated_at: nowDate(),
                    last_seen_at: nowDate()
                }
            },
            { new: true, lean: true }
        );
        return { user: updated, usage: savedUsage };
    }

    const snapshot = buildUserSnapshot(user);
    snapshot.usage.query_count = numberOr(snapshot.usage.query_count, 0) + 1;
    if (mode === 'aggregator') {
        snapshot.usage.aggregator_count = numberOr(snapshot.usage.aggregator_count, 0) + 1;
    }
    if (mode === 'smart') {
        snapshot.usage.smart_count = numberOr(snapshot.usage.smart_count, 0) + 1;
    }
    snapshot.behavior.total_queries = numberOr(snapshot.behavior.total_queries, 0) + 1;
    snapshot.behavior.last_mode = mode;
    snapshot.updated_at = nowDate();
    snapshot.last_seen_at = nowDate();
    memoryStore.users.set(String(snapshot._id), snapshot);
    return { user: snapshot, usage: savedUsage };
};

const getExactCacheEntry = async (queryHash) => {
    if (mongoReady) {
        return await QueryCache.findOne({ query_hash: queryHash }).lean();
    }
    return memoryStore.queryCache.get(queryHash) || null;
};

const touchCacheEntry = async (queryHash) => {
    if (mongoReady) {
        return await QueryCache.findOneAndUpdate(
            { query_hash: queryHash },
            { $inc: { usage_count: 1 }, $set: { last_used: nowDate() } },
            { new: true, lean: true }
        );
    }

    const existing = memoryStore.queryCache.get(queryHash);
    if (!existing) return null;
    existing.usage_count = numberOr(existing.usage_count, 0) + 1;
    existing.last_used = nowDate();
    memoryStore.queryCache.set(queryHash, existing);
    return existing;
};

const getRecentCacheEntries = async (limit = 80) => {
    if (mongoReady) {
        return await QueryCache.find({})
            .sort({ usage_count: -1, last_used: -1 })
            .limit(limit)
            .lean();
    }

    return [...memoryStore.queryCache.values()]
        .sort((a, b) => numberOr(b.usage_count, 0) - numberOr(a.usage_count, 0))
        .slice(0, limit);
};

const upsertCacheEntry = async (cacheEntry) => {
    const payload = {
        query_hash: cacheEntry.query_hash,
        query_text: clip(cacheEntry.query_text, 2400),
        response: clip(cacheEntry.response, 24000),
        embeddings: Array.isArray(cacheEntry.embeddings) ? cacheEntry.embeddings : [],
        usage_count: numberOr(cacheEntry.usage_count, 1),
        last_used: cacheEntry.last_used || nowDate(),
        mode: cacheEntry.mode || 'basic',
        complexity: cacheEntry.complexity || 'simple',
        query_type: cacheEntry.query_type || 'general',
        intent: cacheEntry.intent || 'explain',
        level: cacheEntry.level || 'intermediate',
        style: cacheEntry.style || 'detailed',
        confidence_score: Math.max(0, Math.min(1, numberOr(cacheEntry.confidence_score, 0.8))),
        token_fingerprint: Array.isArray(cacheEntry.token_fingerprint) ? cacheEntry.token_fingerprint.slice(0, 220) : [],
        sources: Array.isArray(cacheEntry.sources) ? cacheEntry.sources.map(source => ({
            id: source.id,
            label: source.label,
            model: source.model,
            text: clip(source.text || '', 6000),
            latencyMs: numberOr(source.latencyMs, 0),
            weight: numberOr(source.weight, 0),
            relevance: numberOr(source.relevance, 0),
            reliability: numberOr(source.reliability, 0),
            recency: numberOr(source.recency, 0)
        })) : []
    };

    if (mongoReady) {
        return await QueryCache.findOneAndUpdate(
            { query_hash: payload.query_hash },
            { $set: payload },
            { new: true, upsert: true, lean: true }
        );
    }

    memoryStore.queryCache.set(payload.query_hash, payload);
    return payload;
};

const createPaymentRecord = async (paymentLike) => {
    const payload = {
        user_id: paymentLike.user_id,
        provider: paymentLike.provider,
        external_id: paymentLike.external_id,
        amount: numberOr(paymentLike.amount, 0),
        currency: paymentLike.currency || 'usd',
        status: paymentLike.status || 'pending',
        metadata: paymentLike.metadata || {},
        created_at: paymentLike.created_at || nowDate()
    };

    if (mongoReady) {
        const created = await Payment.create({
            ...payload,
            user_id: safeObjectId(payload.user_id)
        });
        return created.toObject();
    }

    payload.id = crypto.randomUUID();
    memoryStore.payments.push(payload);
    return payload;
};

const promoteUserToPro = async (userId, paymentRecord) => {
    const usageRecord = await getUsageRecord(userId);
    if (usageRecord) {
        usageRecord.daily_query_count = 0;
        usageRecord.daily_aggregator_count = 0;
        usageRecord.daily_smart_count = 0;
        usageRecord.last_reset_timestamp = nowDate();
        await saveUsageRecord(usageRecord);
    }

    if (mongoReady) {
        await User.findByIdAndUpdate(
            safeObjectId(userId),
            {
                $set: {
                    plan: 'PRO',
                    updated_at: nowDate(),
                    last_seen_at: nowDate()
                }
            }
        );
    } else {
        const user = memoryStore.users.get(String(userId));
        if (user) {
            user.plan = 'PRO';
            user.updated_at = nowDate();
            user.last_seen_at = nowDate();
            memoryStore.users.set(String(userId), user);
        }
    }

    if (paymentRecord) {
        await createPaymentRecord({ ...paymentRecord, user_id: userId, status: paymentRecord.status || 'paid' });
    }
};

const readBearerToken = (req) => {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Bearer ')) return null;
    return header.slice('Bearer '.length).trim();
};

const signAuthToken = (user, options = {}) => jwt.sign(
    {
        sub: String(user._id),
        role: user.role || 'user',
        plan: user.plan || 'FREE',
        admin_session: Boolean(options.adminSession)
    },
    JWT_SECRET,
    { expiresIn: '30d' }
);

const verifyAdminPassword = async (candidate = '') => {
    if (ADMIN_PASSWORD_HASH) {
        try {
            return await bcrypt.compare(candidate, ADMIN_PASSWORD_HASH);
        } catch {
            return false;
        }
    }
    return Boolean(ADMIN_PASSWORD) && candidate === ADMIN_PASSWORD;
};

const getRuntimeIdentity = async (req) => {
    if (req.auth?.user) {
        return {
            user: req.auth.user,
            usage: req.auth.usage,
            authToken: req.auth.token,
            adminSession: Boolean(req.auth.adminSession),
            issuedNewToken: false
        };
    }

    if (!ALLOW_GUEST_AUTH) {
        return null;
    }

    const created = await createGuestUser();
    return { ...created, authToken: signAuthToken(created.user), adminSession: false, issuedNewToken: true };
};

const buildClientConfig = (user = null, options = {}) => ({
    storage_mode: mongoReady ? 'mongodb' : 'memory-fallback',
    modes: ['basic', 'aggregator', 'smart'],
    admin_portal: {
        login_configured: Boolean(ADMIN_EMAIL && (ADMIN_PASSWORD || ADMIN_PASSWORD_HASH)),
        active_role: options.adminSession && user?.role === 'admin' ? 'admin' : 'user'
    },
    auth: {
        google_enabled: Boolean(GOOGLE_CLIENT_ID),
        google_client_id: GOOGLE_CLIENT_ID || null,
        guest_enabled: ALLOW_GUEST_AUTH
    },
    voice: {
        sarvam_enabled: Boolean(SARVAM_API_KEY),
        provider: SARVAM_API_KEY ? 'sarvam' : 'browser'
    },
    plan_limits: PLAN_LIMITS,
    payments: {
        stripe_enabled: Boolean(stripeClient && STRIPE_PRICE_ID),
        razorpay_enabled: Boolean(razorpayClient),
        google_pay: {
            via_stripe_cards: true,
            via_razorpay_upi: true
        },
        upi: {
            via_razorpay: true,
            live_credentials_connected: Boolean(razorpayClient)
        }
    },
    user_plan: user?.plan || 'FREE'
});

const computeJaccard = (aTokens = [], bTokens = []) => {
    const aSet = new Set(aTokens);
    const bSet = new Set(bTokens);
    if (!aSet.size || !bSet.size) return 0;
    let intersection = 0;
    aSet.forEach(token => {
        if (bSet.has(token)) intersection += 1;
    });
    return intersection / new Set([...aSet, ...bSet]).size;
};

const findSemanticCacheEntry = async (queryText, queryTokens) => {
    const recentEntries = await getRecentCacheEntries(90);
    let bestMatch = null;

    for (const entry of recentEntries) {
        const candidateTokens = Array.isArray(entry.token_fingerprint) && entry.token_fingerprint.length
            ? entry.token_fingerprint
            : tokenizeSimilarity(entry.query_text || '');
        const overlap = computeJaccard(queryTokens, candidateTokens);
        const containment = (entry.query_text || '').toLowerCase().includes(queryText.toLowerCase()) ? 0.12 : 0;
        const usageBoost = Math.min(0.08, numberOr(entry.usage_count, 0) / 100);
        const score = overlap + containment + usageBoost;

        if (!bestMatch || score > bestMatch.score) {
            bestMatch = { ...entry, score };
        }
    }

    return bestMatch && bestMatch.score >= 0.56 ? bestMatch : null;
};

const detectComplexity = (question = '', attachmentContext = null) => {
    const length = question.trim().split(/\s+/).filter(Boolean).length;
    const signals = [
        /\b(compare|tradeoff|architecture|optimize|orchestrate|pipeline|scalable|monetization|multimodal|fallback|cache|semantic|database|mongoose|jwt)\b/i.test(question),
        /\n/.test(question),
        attachmentContext?.label,
        /[?].*[?]/.test(question),
        /\b(and|while|however|unless|because|whereas|in addition)\b/i.test(question)
    ].filter(Boolean).length;

    if (length > 90 || signals >= 3) return 'complex';
    if (length > 30 || signals >= 1) return 'moderate';
    return 'simple';
};

const detectQueryType = (question = '') => {
    const checks = {
        coding: /(code|debug|bug|refactor|server|api|frontend|backend|javascript|html|css|express|mongoose|database|schema|deploy)/i,
        writing: /(write|rewrite|summarize|essay|copy|title|email|caption|story)/i,
        reasoning: /(why|reason|strategy|architecture|tradeoff|philosophy|theory|evaluate|analyze)/i
    };

    const matched = Object.entries(checks).filter(([, pattern]) => pattern.test(question)).map(([type]) => type);
    if (matched.length > 1) return 'hybrid';
    if (matched.length === 1) return matched[0];
    return 'general';
};

const detectIntent = (question = '') => {
    if (/\b(create|build|design|draft|generate)\b/i.test(question)) return 'create';
    if (/\b(fix|solve|repair|debug|resolve)\b/i.test(question)) return 'solve';
    if (/\b(optimize|improve|accelerate|scale|monetize)\b/i.test(question)) return 'optimize';
    return 'explain';
};

const detectUserLevel = (question = '', user = null) => {
    if (/\b(beginner|simple|basic|eli5|easy terms|plain english)\b/i.test(question)) return 'beginner';
    if (/\b(expert|formal|benchmark|latency budget|throughput|distributed|recall|precision|tradeoff|monetization|compliance)\b/i.test(question)) return 'expert';
    return user?.preferences?.level || 'intermediate';
};

const detectPreferredStyle = (question = '', user = null) => {
    if (/\b(concise|short|brief|tldr|quick answer)\b/i.test(question)) return 'concise';
    if (/\b(detailed|deep|thorough|step by step|comprehensive)\b/i.test(question)) return 'detailed';
    return user?.preferences?.style || 'detailed';
};

const buildQueryProfile = (question, user, attachmentContext) => ({
    complexity: detectComplexity(question, attachmentContext),
    type: detectQueryType(question),
    intent: detectIntent(question),
    level: detectUserLevel(question, user),
    style: detectPreferredStyle(question, user),
    userName: user?.username || user?.display_name || 'User'
});

const getAvailableProviders = ({ geminiKey, groqKey, openRouterKey }) => [
    geminiKey ? 'gemini' : null,
    groqKey ? 'llama' : null,
    openRouterKey ? 'deepseek' : null
].filter(Boolean);

const getProviderPreference = (type = 'general') => {
    const map = {
        coding: ['llama', 'gemini', 'deepseek'],
        writing: ['gemini', 'deepseek', 'llama'],
        reasoning: ['deepseek', 'gemini', 'llama'],
        hybrid: ['gemini', 'deepseek', 'llama'],
        general: ['gemini', 'deepseek', 'llama']
    };
    return map[type] || map.general;
};

const selectExecutionStrategy = ({ profile, user, modePreference, availableProviders, semanticCache }) => {
    const preference = String(modePreference || 'auto').toLowerCase();
    const providerOrder = getProviderPreference(profile.type).filter(id => availableProviders.includes(id));

    let mode = 'basic';
    if (preference === 'basic' || preference === 'aggregator' || preference === 'smart') {
        mode = preference;
    } else if (profile.complexity === 'complex' || profile.type === 'hybrid') {
        mode = user?.plan === 'PRO' ? 'smart' : 'aggregator';
    } else if (profile.complexity === 'moderate' || semanticCache || profile.intent === 'optimize') {
        mode = availableProviders.length > 1 ? 'aggregator' : 'basic';
    }

    if (mode === 'smart' && user?.plan !== 'PRO') {
        return {
            mode: 'aggregator',
            requested_mode: 'smart',
            upgradeRequired: true,
            providers: providerOrder.slice(0, Math.min(2, providerOrder.length)),
            expandableProviders: providerOrder.slice(2)
        };
    }

    const targetCount = mode === 'basic' ? 1 : 3;
    const providers = providerOrder.slice(0, Math.min(targetCount, providerOrder.length));
    const expandableProviders = providerOrder.slice(providers.length);

    return {
        mode,
        requested_mode: preference,
        upgradeRequired: false,
        providers,
        expandableProviders
    };
};

const buildQueryFingerprint = ({ question, attachmentContext, profile, conversationHistory = [], temporalCacheKey = '' }) => normalizeWhitespace([
    question,
    buildConversationHistorySignature(conversationHistory),
    attachmentContext.cacheSignature,
    temporalCacheKey,
    profile.level,
    profile.style
].filter(Boolean).join('\n'));

const buildSourcePrompt = (question, attachmentContext, profile, semanticCache = null, conversationHistory = []) => [
    `User Query: "${question}"`,
    `Complexity: ${profile.complexity}`,
    `Type: ${profile.type}`,
    `Intent: ${profile.intent}`,
    `User Level: ${profile.level}`,
    `Preferred Style: ${profile.style}`,
    `User Name: ${profile.userName}`,
    buildConversationHistoryBlock(conversationHistory),
    semanticCache ? `Relevant Cached Memory (${Math.round(semanticCache.score * 100)}% semantic similarity):\n${semanticCache.response}` : '',
    attachmentContext.sourcePrompt,
    'Node Task:',
    '- Answer clearly and independently.',
    '- Use readable academic language for beginner, intermediate, or moderately advanced questions.',
    '- Use the conversation memory so short follow-ups like "yes", "that one", or "go deeper" resolve against the active trajectory.',
    '- If the request is ambiguous, identify the missing piece first, then give the best provisional answer.'
].filter(Boolean).join('\n\n');

const buildSynthesisPrompt = ({ question, attachmentContext, profile, weightedSources, semanticCache, strategy, conversationHistory = [] }) => {
    const sourceBlocks = weightedSources.map((source, index) => {
        const weightLine = `weight=${source.weight.toFixed(3)}, relevance=${source.relevance.toFixed(3)}, reliability=${source.reliability.toFixed(3)}, recency=${source.recency.toFixed(3)}`;
        return `Source ${index + 1} (${source.label}, provider ${source.id}, model ${source.model}, ${source.latencyMs}ms, ${weightLine}):\n${source.text}`;
    }).join('\n\n');
    const conversationBlock = buildConversationHistoryBlock(conversationHistory);

    return `User Query: "${question}"

User Profile:
- Complexity: ${profile.complexity}
- Type: ${profile.type}
- Intent: ${profile.intent}
- Level: ${profile.level}
- Preferred Style: ${profile.style}
- User Name: ${profile.userName}
- Mode: ${strategy.mode}

${conversationBlock ? `${conversationBlock}\n\n` : ''}${attachmentContext.promptBlock ? `${attachmentContext.promptBlock}\n\n` : ''}${semanticCache ? `Semantic Cache Hint (${Math.round(semanticCache.score * 100)}% similarity):\n${semanticCache.response}\n\n` : ''}${sourceBlocks ? `${sourceBlocks}\n\n` : ''}Synthesis Task:
1. Act as Parallax on the thin line between machine precision and human warmth.
2. Merge the strongest ideas from the weighted source responses into one clean, high-quality answer.
3. Prioritize points repeated across multiple sources, but preserve unique high-value insights.
4. Use normal academic language unless the user's vocabulary clearly signals a deeper tier.
5. Use the conversation memory to resolve references, confirmations, and pronouns against the active trajectory.
6. If the request is ambiguous, state the ambiguity and ask for the missing detail while still giving the best provisional answer.
7. If the request is deep, strategic, or philosophical, invite the user's perspective naturally.
8. End with either one personalized follow-up question or a short continuation fork labeled "Surface Level" and "Deep Tier".`;
};

const computeRelevance = (questionTokens, responseText) => {
    const answerTokens = tokenizeSimilarity(responseText);
    return Math.min(1, computeJaccard(questionTokens, answerTokens) * 1.2 + (answerTokens.length > 12 ? 0.08 : 0));
};

const computeProviderReliability = (providerId) => {
    const health = providerHealth[providerId];
    const base = PROVIDER_RELIABILITY_BASE[providerId] || 0.9;
    if (!health || health.attempts < 3) return base;
    const successRate = health.successes / Math.max(1, health.attempts);
    const latencyPenalty = Math.min(0.08, Math.max(0, (health.avgLatencyMs - 2500) / 20000));
    return Math.max(0.6, Math.min(1, base * 0.65 + successRate * 0.35 - latencyPenalty));
};

const computeProviderRecency = (providerId) => PROVIDER_RECENCY_BASE[providerId] || 0.95;

const normalizeWeights = (weights) => {
    const sum = Object.values(weights).reduce((acc, value) => acc + Math.max(0, Number(value) || 0), 0) || 1;
    return Object.fromEntries(Object.entries(weights).map(([key, value]) => [key, Math.max(0, Number(value) || 0) / sum]));
};

const buildWeightedSources = (sources, question) => {
    const questionTokens = tokenizeSimilarity(question);
    const weights = normalizeWeights(memoryStore.weightConfig);

    return sources.map(source => {
        const relevance = computeRelevance(questionTokens, source.text);
        const reliability = computeProviderReliability(source.id);
        const recency = computeProviderRecency(source.id);
        const weight = (
            weights.relevance * relevance +
            weights.reliability * reliability +
            weights.recency * recency
        );

        return {
            ...source,
            relevance,
            reliability,
            recency,
            weight
        };
    }).sort((a, b) => b.weight - a.weight);
};

const computeConsensus = (sources) => {
    if (sources.length < 2) return sources.length ? 0.82 : 0;

    const scores = [];
    for (let i = 0; i < sources.length; i++) {
        for (let j = i + 1; j < sources.length; j++) {
            scores.push(computeJaccard(tokenizeSimilarity(sources[i].text), tokenizeSimilarity(sources[j].text)));
        }
    }

    return scores.reduce((sum, value) => sum + value, 0) / scores.length;
};

const computeConfidenceScore = (weightedSources) => {
    if (!weightedSources.length) return 0.46;
    const averageWeight = weightedSources.reduce((sum, source) => sum + source.weight, 0) / weightedSources.length;
    const consensus = computeConsensus(weightedSources);
    const providerBonus = Math.min(0.12, weightedSources.length * 0.035);
    return Math.max(0.5, Math.min(0.99, 0.42 + averageWeight * 0.28 + consensus * 0.18 + providerBonus));
};

const updateProviderHealth = (providerId, status, details = {}) => {
    const health = providerHealth[providerId];
    if (!health) return;

    health.attempts += 1;
    if (status === 'success') {
        health.successes += 1;
        health.lastSuccessAt = nowDate();
        health.lastModel = details.model || health.lastModel;
        if (details.latencyMs) {
            health.avgLatencyMs = health.avgLatencyMs
                ? Math.round((health.avgLatencyMs * 0.7) + (details.latencyMs * 0.3))
                : details.latencyMs;
        }
    } else {
        health.failures += 1;
        health.lastError = details.error || 'Unknown provider failure';
    }
};

const callGroqChat = async ({ apiKey, systemPrompt, userPrompt, timeout = PROVIDER_TIMEOUT_MS, maxTokens = 700, temperature = 0.45, models = MODEL_CANDIDATES.llama }) => {
    let lastError = new Error('Groq request failed');

    for (const model of models) {
        const response = await fetchWithTimeout('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({
                model,
                temperature,
                max_tokens: maxTokens,
                messages: [
                    { role: 'system', content: systemPrompt },
                    { role: 'user', content: userPrompt }
                ]
            })
        }, timeout).catch(error => {
            lastError = error;
            return null;
        });

        if (!response) continue;
        if (!response.ok) {
            const errorJson = await parseJsonSafe(response);
            lastError = new Error(errorJson?.error?.message || errorJson?.message || `Groq HTTP ${response.status}`);
            continue;
        }

        const json = await parseJsonSafe(response);
        const text = normalizeText(json?.choices?.[0]?.message?.content || '');
        if (text) return { text, model };
        lastError = new Error(`Groq model ${model} returned an empty response.`);
    }

    throw lastError;
};

const callOpenRouterChat = async ({ apiKey, systemPrompt, userPrompt, timeout = PROVIDER_TIMEOUT_MS, maxTokens = 700, temperature = 0.45, models = MODEL_CANDIDATES.deepseek }) => {
    let lastError = new Error('OpenRouter request failed');

    for (const model of models) {
        const response = await fetchWithTimeout('https://openrouter.ai/api/v1/chat/completions', {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${apiKey}`,
                'Content-Type': 'application/json',
                'HTTP-Referer': PARALLAX_SITE_URL,
                'X-Title': 'Parallax AI'
            },
            body: JSON.stringify({
                model,
                temperature,
                max_tokens: maxTokens,
                messages: [
                    { role: 'system', content: systemPrompt },
                    { role: 'user', content: userPrompt }
                ]
            })
        }, timeout).catch(error => {
            lastError = error;
            return null;
        });

        if (!response) continue;
        if (!response.ok) {
            const errorJson = await parseJsonSafe(response);
            lastError = new Error(errorJson?.error?.message || errorJson?.message || `OpenRouter HTTP ${response.status}`);
            continue;
        }

        const json = await parseJsonSafe(response);
        const text = normalizeText(json?.choices?.[0]?.message?.content || '');
        if (text) return { text, model };
        lastError = new Error(`OpenRouter model ${model} returned an empty response.`);
    }

    throw lastError;
};

const callGemini = async ({ apiKey, systemPrompt, prompt, inlinePart = null, timeout = PROVIDER_TIMEOUT_MS, maxOutputTokens = 900, temperature = 0.45, models = MODEL_CANDIDATES.gemini }) => {
    let lastError = new Error('Gemini request failed');
    const candidateQueue = models.flatMap(model => (
        inlinePart
            ? [{ model, includeInline: true }, { model, includeInline: false }]
            : [{ model, includeInline: false }]
    ));

    for (const candidate of candidateQueue) {
        const parts = [{ text: prompt }];
        if (candidate.includeInline && inlinePart) parts.push(inlinePart);

        const response = await fetchWithTimeout(`https://generativelanguage.googleapis.com/v1beta/models/${candidate.model}:generateContent?key=${apiKey}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                systemInstruction: { parts: [{ text: systemPrompt }] },
                contents: [{ parts }],
                generationConfig: {
                    temperature,
                    maxOutputTokens
                }
            })
        }, timeout).catch(error => {
            lastError = error;
            return null;
        });

        if (!response) continue;
        if (!response.ok) {
            const errorJson = await parseJsonSafe(response);
            lastError = new Error(errorJson?.error?.message || errorJson?.message || `Gemini HTTP ${response.status}`);
            continue;
        }

        const json = await parseJsonSafe(response);
        if (json?.error) {
            lastError = new Error(json.error.message || 'Gemini returned an error.');
            continue;
        }

        const text = normalizeText(json?.candidates?.[0]?.content?.parts?.map(part => part.text || '').join('\n') || '');
        if (text) return { text, model: candidate.model };
        lastError = new Error(`Gemini model ${candidate.model} returned an empty response.`);
    }

    throw lastError;
};

const runProviderNode = async ({ id, label, executor }) => {
    const startedAt = Date.now();

    try {
        const result = await withTransientRetry(executor);
        const latencyMs = Date.now() - startedAt;
        updateProviderHealth(id, 'success', { model: result.model, latencyMs });
        return {
            id,
            label,
            model: result.model,
            text: result.text,
            latencyMs
        };
    } catch (error) {
        updateProviderHealth(id, 'failure', { error: error.message || 'Unknown provider failure' });
        throw new Error(`${label}: ${error.message || 'Unknown provider failure'}`);
    }
};

const requestSourceAnswers = async ({ question, attachmentContext, profile, semanticCache, conversationHistory, temporalSystemNote, geminiKey, groqKey, openRouterKey, providerIds }) => {
    const userPrompt = buildSourcePrompt(question, attachmentContext, profile, semanticCache, conversationHistory);
    const sourceSystemPrompt = `${matrixSourcePersona}\n\n${temporalSystemNote}`;
    const tasks = [];

    providerIds.forEach(providerId => {
        if (providerId === 'gemini' && geminiKey) {
            tasks.push(runProviderNode({
                id: 'gemini',
                label: 'Gemini',
                executor: () => callGemini({
                    apiKey: geminiKey,
                    systemPrompt: sourceSystemPrompt,
                    prompt: userPrompt,
                    inlinePart: attachmentContext.inlinePart,
                    timeout: PROVIDER_TIMEOUT_MS,
                    maxOutputTokens: 750
                })
            }));
        }

        if (providerId === 'llama' && groqKey) {
            tasks.push(runProviderNode({
                id: 'llama',
                label: 'Llama',
                executor: () => callGroqChat({
                    apiKey: groqKey,
                    systemPrompt: sourceSystemPrompt,
                    userPrompt,
                    timeout: PROVIDER_TIMEOUT_MS,
                    maxTokens: 760
                })
            }));
        }

        if (providerId === 'deepseek' && openRouterKey) {
            tasks.push(runProviderNode({
                id: 'deepseek',
                label: 'DeepSeek',
                executor: () => callOpenRouterChat({
                    apiKey: openRouterKey,
                    systemPrompt: sourceSystemPrompt,
                    userPrompt,
                    timeout: PROVIDER_TIMEOUT_MS,
                    maxTokens: 760
                })
            }));
        }
    });

    const settled = await Promise.allSettled(tasks);
    const successes = settled
        .filter(result => result.status === 'fulfilled')
        .map(result => result.value)
        .filter(source => source.text);
    const failures = settled
        .filter(result => result.status === 'rejected')
        .map(result => result.reason?.message || 'Unknown provider failure');

    return { successes, failures };
};

const synthesizeFinalResponse = async ({ question, attachmentContext, profile, weightedSources, semanticCache, strategy, conversationHistory, temporalSystemNote, geminiKey, groqKey, openRouterKey }) => {
    const directFallback = weightedSources.length === 1
        ? { merged: weightedSources[0].text, mergedBy: `${weightedSources[0].label} Direct` }
        : null;
    const synthesisPrompt = buildSynthesisPrompt({ question, attachmentContext, profile, weightedSources, semanticCache, strategy, conversationHistory });
    const synthesisSystemPrompt = `${parallaxPersona}\n\n${temporalSystemNote}`;

    const providerOrder = [
        geminiKey ? async () => {
            const result = await callGemini({
                apiKey: geminiKey,
                systemPrompt: synthesisSystemPrompt,
                prompt: synthesisPrompt,
                inlinePart: attachmentContext.inlinePart,
                timeout: SYNTHESIS_TIMEOUT_MS,
                maxOutputTokens: 1200,
                temperature: 0.35
            });
            return { merged: result.text, mergedBy: `Gemini (${result.model})` };
        } : null,
        openRouterKey ? async () => {
            const result = await callOpenRouterChat({
                apiKey: openRouterKey,
                systemPrompt: synthesisSystemPrompt,
                userPrompt: synthesisPrompt,
                timeout: SYNTHESIS_TIMEOUT_MS,
                maxTokens: 1100,
                temperature: 0.35
            });
            return { merged: result.text, mergedBy: `DeepSeek (${result.model})` };
        } : null,
        groqKey ? async () => {
            const result = await callGroqChat({
                apiKey: groqKey,
                systemPrompt: synthesisSystemPrompt,
                userPrompt: synthesisPrompt,
                timeout: SYNTHESIS_TIMEOUT_MS,
                maxTokens: 1100,
                temperature: 0.35
            });
            return { merged: result.text, mergedBy: `Llama (${result.model})` };
        } : null
    ].filter(Boolean);

    let lastError = new Error('No synthesis providers available');

    for (const attempt of providerOrder) {
        try {
            const result = await withTransientRetry(attempt);
            if (normalizeText(result.merged)) return result;
        } catch (error) {
            lastError = error;
        }
    }

    if (directFallback) return directFallback;
    if (semanticCache?.response) return { merged: semanticCache.response, mergedBy: 'Semantic Cache Direct' };
    throw lastError;
};

const postProcessResponse = (text, profile) => {
    let refined = normalizeWhitespace(text);

    if (profile.style === 'concise') {
        const paragraphs = refined.split('\n\n').slice(0, 4);
        refined = paragraphs.join('\n\n');
    }

    return refined;
};

const normalizeSpeechText = (text = '') => normalizeWhitespace(String(text || ''))
    .replace(/[*_`>#\[\](){}]/g, '')
    .replace(/\s+/g, ' ')
    .slice(0, 2400);

const synthesizeSpeech = async (text = '') => {
    const speechText = normalizeSpeechText(text);
    if (!speechText) throw new Error('No speech text provided.');
    if (!SARVAM_API_KEY) {
        return {
            provider: 'browser',
            text: speechText,
            audio: null,
            mimeType: null,
            fallback: true
        };
    }

    const response = await fetchWithTimeout('https://api.sarvam.ai/text-to-speech', {
        method: 'POST',
        headers: {
            'api-subscription-key': SARVAM_API_KEY,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            text: speechText,
            target_language_code: 'en-IN',
            speaker: SARVAM_TTS_SPEAKER,
            model: 'bulbul:v3',
            pace: 1,
            temperature: 0.58,
            speech_sample_rate: 24000,
            output_audio_codec: 'wav'
        })
    }, 4800);
    const payload = await safeJson(response);

    if (!response.ok || !payload?.audios?.[0]) {
        throw new Error(payload?.error?.message || payload?.message || 'Sarvam speech synthesis failed.');
    }

    return {
        provider: 'sarvam',
        text: speechText,
        audio: payload.audios[0],
        mimeType: 'audio/wav',
        requestId: payload.request_id || null,
        fallback: false
    };
};

const buildRecoveryResponse = ({ question, profile, semanticCache, attachmentContext }) => {
    const opener = profile.level === 'beginner'
        ? `I hit a temporary network-side instability before the full synthesis pass completed for: "${question}".`
        : `I hit a temporary provider-side instability before the full synthesis matrix completed for: "${question}".`;
    const attachmentNote = attachmentContext.label
        ? `I still retained the attachment context: ${attachmentContext.label}.`
        : '';
    const cacheNote = semanticCache?.response
        ? `Closest cached direction:\n${semanticCache.response}`
        : `Best next step: resend the same prompt once more and the bounded retry rail will re-run the parallel pass.`;

    return normalizeWhitespace(`${opener}

${attachmentNote}

${cacheNote}

Surface Level: Retry the same prompt for a fresh live synthesis pass.
Deep Tier: If you want, I can help compress or sharpen the prompt so the next parallel run lands more reliably.`);
};

const buildSyntheticSource = ({ id = 'local', label = 'Parallax Recovery', model = 'local-recovery-rail', text = '' }) => ({
    id,
    label,
    model,
    text,
    latencyMs: 0,
    relevance: 0.76,
    reliability: 1,
    recency: 1,
    weight: 0.84
});

const enforcePlanLimits = (user, usageRecord, mode) => {
    const limits = PLAN_LIMITS[user.plan] || PLAN_LIMITS.FREE;
    const queryCount = numberOr(usageRecord?.daily_query_count, 0);
    const aggregatorCount = numberOr(usageRecord?.daily_aggregator_count, 0);
    const smartCount = numberOr(usageRecord?.daily_smart_count, 0);

    if (queryCount >= limits.queries) {
        return {
            status: 402,
            error: `Daily ${user.plan} query limit reached.`,
            code: 'QUERY_LIMIT_REACHED'
        };
    }

    if (mode === 'aggregator' && aggregatorCount >= limits.aggregators) {
        return {
            status: 402,
            error: `${user.plan} aggregator limit reached for today.`,
            code: 'AGGREGATOR_LIMIT_REACHED'
        };
    }

    if (mode === 'smart' && smartCount >= limits.smart) {
        return {
            status: 402,
            error: `${user.plan} smart mode limit reached for today.`,
            code: 'SMART_LIMIT_REACHED'
        };
    }

    return null;
};

const buildCacheResponsePayload = ({ entry, profile, usageRecord, user, cacheType, authToken = null, adminSession = false }) => ({
    merged: entry.response,
    score: Math.round(Math.max(0.75, numberOr(entry.confidence_score, 0.86)) * 100),
    mergedBy: cacheType === 'exact' ? 'Exact Cache' : 'Semantic Cache',
    sources: Array.isArray(entry.sources) ? entry.sources : [],
    usage: toPublicUsage(usageRecord, user.plan),
    decision: {
        mode: entry.mode || 'basic',
        complexity: profile.complexity,
        type: profile.type,
        intent: profile.intent,
        level: profile.level,
        style: profile.style,
        cache: cacheType
    },
    config: buildClientConfig(user, { adminSession }),
    authToken
});

const authMiddleware = async (req, res, next) => {
    const token = readBearerToken(req);
    if (!token) {
        req.auth = { user: null, usage: null, token: null, adminSession: false };
        return next();
    }

    try {
        const payload = jwt.verify(token, JWT_SECRET);
        const user = await getUserById(payload.sub);
        if (!user) {
            req.auth = { user: null, usage: null, token: null, adminSession: false };
            return next();
        }

        const usage = await resetUsageIfNeeded(await getUsageRecord(user._id));
        req.auth = { user, usage, token, adminSession: Boolean(payload.admin_session) };
        return next();
    } catch {
        req.auth = { user: null, usage: null, token: null, adminSession: false };
        return next();
    }
};

const requireAuth = async (req, res, next) => {
    if (!req.auth?.user) {
        return res.status(401).json({ error: 'Authentication required.' });
    }
    next();
};

const requireAdmin = async (req, res, next) => {
    if (!req.auth?.adminSession || !req.auth?.user || req.auth.user.role !== 'admin') {
        return res.status(403).json({ error: 'Administrator access required.' });
    }
    next();
};

app.use(authMiddleware);

app.get('/health', async (req, res) => {
    res.json({
        status: 'ok',
        at: nowDate(),
        storage: mongoReady ? 'mongodb' : 'memory-fallback',
        providers: {
            gemini: Boolean(process.env.GEMINI_API_KEY),
            llama: Boolean(process.env.GROQ_API_KEY),
            deepseek: Boolean(process.env.OPENROUTER_API_KEY)
        }
    });
});

app.get('/config', async (req, res) => {
    res.json({
        config: buildClientConfig(req.auth?.user || null, { adminSession: Boolean(req.auth?.adminSession) })
    });
});

app.post('/auth/guest', async (req, res) => {
    if (!ALLOW_GUEST_AUTH) {
        return res.status(403).json({ error: 'Guest access is disabled. Sign in with Google to continue.' });
    }

    if (req.auth?.user) {
        return res.json({
            token: req.auth.token,
            user: toPublicUser(req.auth.user, req.auth.usage, { adminSession: req.auth.adminSession }),
            config: buildClientConfig(req.auth.user, { adminSession: req.auth.adminSession })
        });
    }

    const created = await createGuestUser(req.body?.displayName || 'Guest Node');
    res.json({
        token: signAuthToken(created.user),
        user: toPublicUser(created.user, created.usage),
        config: buildClientConfig(created.user)
    });
});

app.post('/auth/google', async (req, res) => {
    try {
        const { credential } = req.body || {};
        if (!credential) {
            return res.status(400).json({ error: 'Google credential is required.' });
        }

        const googleProfile = await verifyGoogleCredential(String(credential));
        const user = await upsertGoogleUser(googleProfile);
        const usage = await resetUsageIfNeeded(await getUsageRecord(user._id));
        const token = signAuthToken(user);

        res.json({
            token,
            user: toPublicUser(user, usage),
            config: buildClientConfig(user)
        });
    } catch (error) {
        res.status(401).json({ error: error.message || 'Google sign-in failed.' });
    }
});

app.post('/auth/admin/login', async (req, res) => {
    const { email, password } = req.body || {};

    if (!ADMIN_EMAIL || (!ADMIN_PASSWORD && !ADMIN_PASSWORD_HASH)) {
        return res.status(503).json({ error: 'Admin credentials are not configured yet.' });
    }

    if (String(email || '').trim().toLowerCase() !== ADMIN_EMAIL || !(await verifyAdminPassword(String(password || '')))) {
        return res.status(401).json({ error: 'Invalid administrator credentials.' });
    }

    const adminUser = await upsertAdminUser(ADMIN_EMAIL);
    const usage = await resetUsageIfNeeded(await getUsageRecord(adminUser._id));
    const token = signAuthToken(adminUser, { adminSession: true });

    res.json({
        token,
        user: toPublicUser(adminUser, usage, { adminSession: true }),
        config: buildClientConfig(adminUser, { adminSession: true })
    });
});

app.get('/auth/me', requireAuth, async (req, res) => {
    const usage = await resetUsageIfNeeded(await getUsageRecord(req.auth.user._id));
    res.json({
        user: toPublicUser(req.auth.user, usage, { adminSession: req.auth.adminSession }),
        config: buildClientConfig(req.auth.user, { adminSession: req.auth.adminSession })
    });
});

app.get('/usage', requireAuth, async (req, res) => {
    const usage = await resetUsageIfNeeded(await getUsageRecord(req.auth.user._id));
    res.json({ usage: toPublicUsage(usage, req.auth.user.plan) });
});

app.post('/voice/tts', requireAuth, async (req, res) => {
    try {
        const { text } = req.body || {};
        const speech = await synthesizeSpeech(text);
        res.json({ speech, config: buildClientConfig(req.auth.user, { adminSession: req.auth.adminSession }) });
    } catch (error) {
        res.json({
            speech: {
                provider: 'browser',
                text: normalizeSpeechText(req.body?.text || 'I am here with you. The natural voice rail is reconnecting.'),
                audio: null,
                mimeType: null,
                fallback: true,
                error: error.message || 'Voice synthesis fallback active.'
            },
            config: buildClientConfig(req.auth.user, { adminSession: req.auth.adminSession })
        });
    }
});

app.post('/payments/stripe/create-checkout-session', requireAuth, async (req, res) => {
    if (!stripeClient || !STRIPE_PRICE_ID) {
        return res.status(503).json({
            error: 'Stripe checkout is scaffolded but Stripe credentials or price ID are not configured yet.',
            scaffolded: true
        });
    }

    const user = req.auth.user;
    const origin = req.headers.origin || PARALLAX_SITE_URL;

    try {
        const session = await stripeClient.checkout.sessions.create({
            mode: 'subscription',
            line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
            success_url: `${origin}?upgrade=success`,
            cancel_url: `${origin}?upgrade=cancelled`,
            client_reference_id: String(user._id),
            customer_email: user.email || undefined,
            metadata: {
                userId: String(user._id),
                plan: 'PRO',
                source: 'parallax-web'
            }
        });

        res.json({ url: session.url });
    } catch (error) {
        res.status(500).json({ error: error.message || 'Unable to initialize Stripe checkout.' });
    }
});

app.post('/payments/razorpay/create-order', requireAuth, async (req, res) => {
    if (!razorpayClient) {
        return res.status(503).json({
            error: 'Razorpay is scaffolded but live keys are not configured yet.',
            scaffolded: true
        });
    }

    const amount = numberOr(req.body?.amount, 9900);
    const currency = req.body?.currency || 'INR';

    try {
        const order = await razorpayClient.orders.create({
            amount,
            currency,
            receipt: `parallax_${Date.now()}`,
            notes: {
                userId: String(req.auth.user._id),
                plan: 'PRO'
            }
        });

        res.json({
            keyId: RAZORPAY_KEY_ID,
            orderId: order.id,
            amount: order.amount,
            currency: order.currency
        });
    } catch (error) {
        res.status(500).json({ error: error.message || 'Unable to initialize Razorpay order.' });
    }
});

app.post('/payments/razorpay/verify', requireAuth, async (req, res) => {
    if (!RAZORPAY_KEY_SECRET) {
        return res.status(503).json({ error: 'Razorpay verification is scaffolded but not configured yet.' });
    }

    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, amount, currency } = req.body || {};
    const expectedSignature = crypto
        .createHmac('sha256', RAZORPAY_KEY_SECRET)
        .update(`${razorpay_order_id}|${razorpay_payment_id}`)
        .digest('hex');

    if (expectedSignature !== razorpay_signature) {
        return res.status(400).json({ error: 'Razorpay signature verification failed.' });
    }

    await promoteUserToPro(req.auth.user._id, {
        provider: 'razorpay',
        external_id: razorpay_payment_id,
        amount: numberOr(amount, 0),
        currency: currency || 'inr',
        status: 'paid',
        metadata: { order_id: razorpay_order_id }
    });

    const refreshedUser = await getUserById(req.auth.user._id);
    const usage = await resetUsageIfNeeded(await getUsageRecord(req.auth.user._id));

    res.json({
        success: true,
        user: toPublicUser(refreshedUser, usage)
    });
});

app.get('/admin/stats', requireAdmin, async (req, res) => {
    let users = [];
    let payments = [];

    if (mongoReady) {
        users = await User.find({}).lean();
        payments = await Payment.find({}).lean();
    } else {
        users = [...memoryStore.users.values()];
        payments = [...memoryStore.payments];
    }

    const now = Date.now();
    const totalUsers = users.length;
    const dau = users.filter(user => now - new Date(user.last_seen_at || 0).getTime() <= 24 * 60 * 60 * 1000).length;
    const wau = users.filter(user => now - new Date(user.last_seen_at || 0).getTime() <= 7 * 24 * 60 * 60 * 1000).length;
    const totalQueries = users.reduce((sum, user) => sum + numberOr(user.behavior?.total_queries, 0), 0);
    const freeUsers = users.filter(user => user.plan !== 'PRO').length;
    const proUsers = users.filter(user => user.plan === 'PRO').length;
    const revenue = payments.filter(payment => payment.status === 'paid').reduce((sum, payment) => sum + numberOr(payment.amount, 0), 0);

    res.json({
        total_users: totalUsers,
        active_users: { dau, wau },
        total_queries: totalQueries,
        average_queries_per_user: totalUsers ? Number((totalQueries / totalUsers).toFixed(2)) : 0,
        free_users: {
            count: freeUsers,
            percentage: totalUsers ? Number(((freeUsers / totalUsers) * 100).toFixed(2)) : 0
        },
        pro_users: {
            count: proUsers,
            percentage: totalUsers ? Number(((proUsers / totalUsers) * 100).toFixed(2)) : 0
        },
        revenue
    });
});

app.get('/admin/model-health', requireAdmin, async (req, res) => {
    const metrics = Object.values(providerHealth).map(provider => ({
        ...provider,
        success_rate: provider.attempts ? Number(((provider.successes / provider.attempts) * 100).toFixed(2)) : 0
    }));

    res.json({ providers: metrics });
});

app.get('/admin/logs', requireAdmin, async (req, res) => {
    pruneSystemLogs();
    res.json({ logs: systemLogs.slice(-100).reverse() });
});

app.get('/admin/weights', requireAdmin, async (req, res) => {
    res.json({ weights: normalizeWeights(memoryStore.weightConfig) });
});

app.post('/admin/weights', requireAdmin, async (req, res) => {
    const incoming = req.body || {};
    const normalized = normalizeWeights({
        reliability: numberOr(incoming.reliability, memoryStore.weightConfig.reliability),
        relevance: numberOr(incoming.relevance, memoryStore.weightConfig.relevance),
        recency: numberOr(incoming.recency, memoryStore.weightConfig.recency)
    });
    memoryStore.weightConfig = normalized;
    res.json({ weights: normalized });
});

app.post('/generate-title', requireAuth, async (req, res) => {
    const { question, fileName } = req.body || {};
    const groqKey = process.env.GROQ_API_KEY;
    const source = [question, fileName].filter(Boolean).join(' ').trim();

    try {
        if (!source) throw new Error('No title source');
        if (!groqKey) throw new Error('No Groq key');

        const namingPrompt = `You are a conceptual trajectory naming protocol. Your task is to distill user intent into a professional 2-3 word conceptual title.

CRITICAL RULES:
1. NEVER repeat, mirror, paraphrase too closely, or copy-paste the user's wording.
2. Analyze the intent, trajectory, and underlying concept beneath the request.
3. Generate a concise conceptual label that sounds professional, abstract, and meaningful.
4. Use Title Case.
5. Output ONLY the title. No quotes, no explanation, no conversational text.

Examples:
- Question: "How do neural networks learn?" -> ANSWER: "Adaptive Architecture"
- Question: "What happens if AI becomes conscious?" -> ANSWER: "Sentient Emergence"
- Question: "Can time travel be real?" -> ANSWER: "Temporal Mechanics"`;

        const result = await callGroqChat({
            apiKey: groqKey,
            systemPrompt: namingPrompt,
            userPrompt: `Primary Request: ${question || 'Analyze the attached material'}${fileName ? `\nAttachment: ${fileName}` : ''}`,
            timeout: TITLE_TIMEOUT_MS,
            maxTokens: 24,
            temperature: 0.2,
            models: ['llama-3.1-8b-instant', 'llama3-8b-8192']
        });

        res.json({ title: normalizeConceptualTitle(result.text, source) });
    } catch {
        res.json({ title: buildConceptualFallback(source) });
    }
});

app.post('/ask', requireAuth, async (req, res) => {
    const { question, fileData, mode: requestedMode, history } = req.body || {};
    const normalizedQuestion = (question || '').trim() || (fileData?.name ? `Analyze the attached file "${fileData.name}" and explain what matters most.` : '');
    const geminiKey = process.env.GEMINI_API_KEY;
    const groqKey = process.env.GROQ_API_KEY;
    const openRouterKey = process.env.OPENROUTER_API_KEY;
    let runtime = null;
    let user = req.auth?.user || null;
    let usage = req.auth?.usage || null;
    let attachmentContext = null;
    let conversationHistory = [];
    let profile = null;
    let semanticCache = null;
    let strategy = null;
    let weightedSources = [];

    try {
        if (!normalizedQuestion && !fileData?.base64) {
            return res.status(400).json({ error: 'No question or attachment received.' });
        }

        runtime = await getRuntimeIdentity(req);
        if (!runtime) {
            return res.status(401).json({ error: 'Authentication required.' });
        }
        user = runtime.user;
        usage = await resetUsageIfNeeded(runtime.usage || await getUsageRecord(user._id));
        attachmentContext = buildAttachmentContext(fileData);
        conversationHistory = sanitizeConversationHistory(history);
        const runtimeNow = new Date();
        const runtimeTimestamp = buildRuntimeTimestampLabel(runtimeNow);
        const temporalSystemNote = buildTemporalSystemNote(runtimeTimestamp);
        const temporalCacheKey = buildTemporalCacheKey({ question: normalizedQuestion, history: conversationHistory, runtimeNow });
        profile = buildQueryProfile(normalizedQuestion, user, attachmentContext);
        const availableProviders = getAvailableProviders({ geminiKey, groqKey, openRouterKey });
        const queryFingerprint = buildQueryFingerprint({
            question: normalizedQuestion,
            attachmentContext,
            profile,
            conversationHistory,
            temporalCacheKey
        });
        const queryHash = sha256(queryFingerprint);
        const exactCache = await getExactCacheEntry(queryHash);

        const strategyPreview = selectExecutionStrategy({
            profile,
            user,
            modePreference: requestedMode,
            availableProviders,
            semanticCache: null
        });

        if (strategyPreview.upgradeRequired && String(requestedMode || '').toLowerCase() === 'smart') {
            return res.status(402).json({
                error: 'Smart mode is reserved for PRO trajectories.',
                code: 'UPGRADE_REQUIRED',
                usage: toPublicUsage(usage, user.plan),
                config: buildClientConfig(user, { adminSession: runtime.adminSession }),
                authToken: runtime.issuedNewToken ? runtime.authToken : null
            });
        }

        const limitFailure = enforcePlanLimits(user, usage, strategyPreview.mode);
        if (limitFailure) {
            return res.status(limitFailure.status).json({
                error: limitFailure.error,
                code: limitFailure.code,
                usage: toPublicUsage(usage, user.plan),
                config: buildClientConfig(user, { adminSession: runtime.adminSession }),
                authToken: runtime.issuedNewToken ? runtime.authToken : null
            });
        }

        if (exactCache) {
            await touchCacheEntry(queryHash);
            const incremented = await incrementUsage(user, usage, exactCache.mode || strategyPreview.mode);
            user = incremented.user;
            usage = incremented.usage;
            return res.json(buildCacheResponsePayload({
                entry: exactCache,
                profile,
                usageRecord: usage,
                user,
                cacheType: 'exact',
                authToken: runtime.issuedNewToken ? runtime.authToken : null,
                adminSession: runtime.adminSession
            }));
        }

        semanticCache = await findSemanticCacheEntry(queryFingerprint, tokenizeSimilarity(queryFingerprint));
        strategy = selectExecutionStrategy({
            profile,
            user,
            modePreference: requestedMode,
            availableProviders,
            semanticCache
        });

        if (semanticCache && strategy.mode === 'basic' && semanticCache.score >= 0.88) {
            await touchCacheEntry(semanticCache.query_hash);
            const incremented = await incrementUsage(user, usage, strategy.mode);
            user = incremented.user;
            usage = incremented.usage;
            return res.json(buildCacheResponsePayload({
                entry: semanticCache,
                profile,
                usageRecord: usage,
                user,
                cacheType: 'semantic',
                authToken: runtime.issuedNewToken ? runtime.authToken : null,
                adminSession: runtime.adminSession
            }));
        }

        parallaxLog(`Intercepted query. Executing ${strategy.mode.toUpperCase()} matrix with providers [${strategy.providers.join(', ')}]${attachmentContext.label ? ` and attachment ${attachmentContext.label}` : ''}.`);

        let { successes, failures } = await requestSourceAnswers({
            question: normalizedQuestion,
            attachmentContext,
            profile,
            semanticCache,
            conversationHistory,
            temporalSystemNote,
            geminiKey,
            groqKey,
            openRouterKey,
            providerIds: strategy.providers
        });

        weightedSources = buildWeightedSources(successes, normalizedQuestion);
        let confidence = computeConfidenceScore(weightedSources);

        if ((strategy.mode === 'basic' && confidence < 0.72 && strategy.expandableProviders.length) || (!successes.length && strategy.expandableProviders.length)) {
            const expanded = await requestSourceAnswers({
                question: normalizedQuestion,
                attachmentContext,
                profile,
                semanticCache,
                conversationHistory,
                temporalSystemNote,
                geminiKey,
                groqKey,
                openRouterKey,
                providerIds: strategy.expandableProviders
            });

            successes = [...successes, ...expanded.successes];
            failures = [...failures, ...expanded.failures];
            weightedSources = buildWeightedSources(successes, normalizedQuestion);
            confidence = computeConfidenceScore(weightedSources);
        }

        successes.forEach(source => {
            parallaxLog(`${source.label} responded in ${source.latencyMs}ms via ${source.model}.`);
        });
        failures.forEach(failure => {
            parallaxLog(failure);
        });

        let finalPayload;
        if (weightedSources.length > 0) {
            finalPayload = await synthesizeFinalResponse({
                question: normalizedQuestion,
                attachmentContext,
                profile,
                weightedSources,
                semanticCache,
                strategy,
                conversationHistory,
                temporalSystemNote,
                geminiKey,
                groqKey,
                openRouterKey
            });
        } else if (semanticCache?.response) {
            finalPayload = { merged: semanticCache.response, mergedBy: 'Semantic Cache Direct' };
        } else {
            finalPayload = {
                merged: buildRecoveryResponse({
                    question: normalizedQuestion,
                    profile,
                    semanticCache,
                    attachmentContext
                }),
                mergedBy: 'Local Recovery Rail'
            };
        }

        const merged = postProcessResponse(finalPayload.merged, profile);
        const incremented = await incrementUsage(user, usage, strategy.mode);
        user = incremented.user;
        usage = incremented.usage;
        user = await touchUserPresence(user, profile, strategy.mode);

        const finalConfidence = weightedSources.length ? computeConfidenceScore(weightedSources) : 0.78;
        const responseSources = weightedSources.length
            ? weightedSources
            : [
                finalPayload.mergedBy === 'Semantic Cache Direct'
                    ? buildSyntheticSource({
                        id: 'semantic-cache',
                        label: 'Semantic Cache Memory',
                        model: 'semantic-cache-rail',
                        text: merged
                    })
                    : buildSyntheticSource({ text: merged })
            ];

        if (finalPayload.mergedBy !== 'Local Recovery Rail') {
            await upsertCacheEntry({
                query_hash: queryHash,
                query_text: queryFingerprint,
                response: merged,
                usage_count: 1,
                last_used: nowDate(),
                mode: strategy.mode,
                complexity: profile.complexity,
                query_type: profile.type,
                intent: profile.intent,
                level: profile.level,
                style: profile.style,
                confidence_score: finalConfidence,
                token_fingerprint: tokenizeSimilarity(queryFingerprint),
                sources: responseSources
            });
        }

        res.json({
            merged,
            score: Math.round(finalConfidence * 100),
            mergedBy: finalPayload.mergedBy,
            sources: responseSources,
            usage: toPublicUsage(usage, user.plan),
            decision: {
                mode: strategy.mode,
                complexity: profile.complexity,
                type: profile.type,
                intent: profile.intent,
                level: profile.level,
                style: profile.style,
                cache: semanticCache ? 'miss_with_semantic_context' : 'miss'
            },
            config: buildClientConfig(user, { adminSession: runtime.adminSession }),
            authToken: runtime.issuedNewToken ? runtime.authToken : null
        });
    } catch (error) {
        parallaxLog(`Total system failure: ${error.message}`);
        if (user && normalizedQuestion) {
            const safeAttachmentContext = attachmentContext || buildAttachmentContext(fileData);
            const safeProfile = profile || buildQueryProfile(normalizedQuestion, user, safeAttachmentContext);
            const safeStrategy = strategy || { mode: 'basic' };
            const bestSource = weightedSources[0];
            const merged = postProcessResponse(
                bestSource?.text || buildRecoveryResponse({
                    question: normalizedQuestion,
                    profile: safeProfile,
                    semanticCache,
                    attachmentContext: safeAttachmentContext
                }),
                safeProfile
            );
            const responseSources = bestSource
                ? weightedSources
                : [buildSyntheticSource({ text: merged })];

            try {
                const incremented = await incrementUsage(user, usage || await getUsageRecord(user._id), safeStrategy.mode);
                user = incremented.user;
                usage = incremented.usage;
            } catch {
                usage = usage || await getUsageRecord(user._id);
            }

            return res.json({
                merged,
                score: bestSource ? 78 : 72,
                mergedBy: bestSource ? 'Direct Source Recovery' : 'Local Recovery Rail',
                sources: responseSources,
                usage: toPublicUsage(usage, user.plan),
                decision: {
                    mode: safeStrategy.mode,
                    complexity: safeProfile.complexity,
                    type: safeProfile.type,
                    intent: safeProfile.intent,
                    level: safeProfile.level,
                    style: safeProfile.style,
                    cache: semanticCache ? 'fallback_with_semantic_context' : 'fallback'
                },
                config: buildClientConfig(user, { adminSession: Boolean(runtime?.adminSession || req.auth?.adminSession) }),
                authToken: runtime?.issuedNewToken ? runtime.authToken : null
            });
        }

        res.status(500).json({ error: 'Parallax could not complete this request. Please retry in a moment.' });
    }
});

app.use(express.static(frontendDir));
app.get('/', (req, res) => {
    res.sendFile(path.join(frontendDir, 'index.html'));
});

await connectDatabase();

app.listen(SERVER_PORT, () => parallaxLog(`Parallax Neural Gate Active: Port ${SERVER_PORT}`));
