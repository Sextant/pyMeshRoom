// What MeshCore apps put inside a message's text, as the MeshTrax message format describes it
// (github.com/venamartin/meshtrax, docs/message-format.md): reactions, and the hash that ties one to its message.
import { concatBytes, u32le, utf8Encode } from "./bytes.js";
import { sha256 } from "./hash.js";

const CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz";

// The quick-reaction row, as MeshTrax offers it.
export const QUICK_REACTIONS = ["👍", "❤️", "😂", "🎉", "👏", "🔥", "😮", "😢", "🙏", "👀", "✅", "💯"];

// meshcore-open's frozen r: table (decode only: its hash can't be reproduced outside Dart, so such a reaction is
// shown, but not attached to a message).
const LEGACY_EMOJI = [
  "👍", "❤️", "😂", "🎉", "👏", "🔥",
  "😀", "😃", "😄", "😁", "😅", "😂", "🤣", "😊", "😇", "🙂", "🙃", "😉", "😌", "😍", "🥰", "😘", "😗", "😙", "😚",
  "😋", "😛", "😝", "😜", "🤪", "🤨", "🧐", "🤓", "😎", "🥸", "🤩", "🥳", "😏", "😒", "😞", "😔", "😟", "😕", "🙁",
  "😣", "😖", "😫", "😩", "🥺", "😢", "😭", "😤", "😠", "😡", "🤬", "🤯", "😳", "🥵", "🥶", "😱", "😨", "😰", "😥",
  "😓", "🤗", "🤔", "🤭", "🤫", "🤥", "😶",
  "👍", "👎", "👊", "✊", "🤛", "🤜", "🤞", "✌️", "🤟", "🤘", "👌", "🤌", "🤏", "👈", "👉", "👆", "👇", "☝️", "👋",
  "🤚", "🖐️", "✋", "🖖", "👏", "🙌", "👐", "🤲", "🤝", "🙏", "✍️", "💅", "🤳", "💪",
  "❤️", "🧡", "💛", "💚", "💙", "💜", "🖤", "🤍", "🤎", "💔", "❤️‍🔥", "❤️‍🩹", "💕", "💞", "💓", "💗", "💖", "💘",
  "💝", "💟", "💌", "💢", "💥", "💫", "💦", "💨", "🕳️", "💬", "👁️‍🗨️", "🗨️", "🗯️", "💭",
  "🎉", "🎊", "🎈", "🎁", "🎀", "🪅", "🪆", "🏆", "🥇", "🥈", "🥉", "⚽", "⚾", "🥎", "🏀", "🏐", "🏈", "🏉", "🎾",
  "🥏", "🎳", "🏏", "🏑", "🏒", "🥍", "🏓", "🏸", "🥊", "🥋", "🥅", "⛳", "🔥", "⭐", "🌟", "✨", "⚡", "💡", "🔦",
  "🏮", "🪔", "📱", "💻", "⌚", "📷", "📺", "📻", "🎵", "🎶", "🚀",
];

// A message's hash, as reactions name it: the first 5 bytes of SHA-256(UTF-8 text + its sender timestamp, u32 LE),
// in 8 characters of lowercase Crockford Base32.
export function messageHash(text, ts) {
  const d = sha256(concatBytes(utf8Encode(text), u32le(ts >>> 0)));
  let bits = 0n;
  for (let i = 0; i < 5; i++) bits = (bits << 8n) | BigInt(d[i]);
  let out = "";
  for (let shift = 35n; shift >= 0n; shift -= 5n) out += CROCKFORD[Number((bits >> shift) & 31n)];
  return out;
}

function crockford(raw) {
  if (raw.length !== 8) return null;
  let out = "";
  for (let ch of raw.toLowerCase()) {
    if (ch === "o") ch = "0";
    if (ch === "i" || ch === "l") ch = "1";
    if (!CROCKFORD.includes(ch)) return null;
    out += ch;
  }
  return out;
}

const looksLikeEmoji = (s) => {
  const cps = [...s].map((c) => c.codePointAt(0));
  return cps.length > 0 && cps.length <= 8 && (cps[0] >= 0x2000 || cps.some((c) => c === 0xfe0f || c === 0x20e3));
};

// A reaction's text -> {emoji, hash, targetSender} (MeshCore One: "@[Name]👍\nhash", older "👍@[Name]\nhash", or in a DM
// "👍\nhash"), {emoji, legacy: true} (meshcore-open's "r:HASH:INDEX"), or null. A MeshCore One reaction looks like any
// two-line message, so it only counts as one when its hash finds the message.
export function parseReaction(text) {
  const legacy = /^r:([0-9a-f]{4}):([0-9a-f]{2})$/.exec(text);
  if (legacy) {
    const emoji = LEGACY_EMOJI[parseInt(legacy[2], 16)];
    return emoji ? { emoji, legacy: true } : null;
  }
  const nl = text.lastIndexOf("\n");
  if (nl < 0) return null;
  const hash = crockford(text.slice(nl + 1));
  let head = text.slice(0, nl);
  if (!hash || head.includes("\n")) return null;
  let targetSender = null;
  if (head.startsWith("@[")) {
    const close = head.lastIndexOf("]");
    if (close < 3) return null;
    targetSender = head.slice(2, close);
    head = head.slice(close + 1);
  } else {
    const at = head.indexOf("@[");
    if (at >= 0) {
      if (!head.endsWith("]")) return null;
      targetSender = head.slice(at + 2, -1);
      if (!targetSender) return null;
      head = head.slice(0, at);
    }
  }
  return looksLikeEmoji(head) ? { emoji: head, hash, targetSender } : null;
}

// The text to send for a reaction: in a channel or a room, naming the message's author; in a DM, without.
export function reactionText(emoji, hash, author = null) {
  return (author ? "@[" + author + "]" : "") + emoji + "\n" + hash;
}

// The forms a message's text may have been hashed in, the one to send with first: trimmed of tabs and Unicode spaces at
// the ends (never newlines), mentions kept, as MeshCore One holds it; as received; without leading "@[Name] " mentions
// (as some apps show it); and without leading mentions in either form, "@[Name] " or reply markup "@[Name]\n".
export function hashTexts(text) {
  const trimmed = text.replace(/^[\t\p{Zs}]+|[\t\p{Zs}]+$/gu, "");
  const display = trimmed.replace(/^(?:@\[[^\]]+\] )+/, "");
  const bare = trimmed.replace(/^(?:@\[[^\]]+\][ \n]?)+/, "");
  return [...new Set([trimmed, text, display, bare])];
}

// A message of nothing but emoji, at most 5: shown large.
export function emojiOnly(text) {
  const t = text.trim();
  if (!t || /[\p{L}\p{N}]/u.test(t.replace(/[\u{1F1E6}-\u{1F1FF}]/gu, ""))) return false;
  const parts = [...new Intl.Segmenter(undefined, { granularity: "grapheme" }).segment(t)].filter((s) => s.segment.trim());
  return parts.length <= 5 && parts.every((s) => /\p{Extended_Pictographic}|\p{Regional_Indicator}|⃣/u.test(s.segment));
}

// ---------------------------------------------------------------- replies (MeshCore One's format, as MeshTrax uses it)

const collapse = (s) => s.replace(/\s+/g, " ").trim();
const chars = (s) => Array.from(s);                       // (characters, not UTF-16 units: an emoji counts once)
const stripMentions = (s) => s.replace(/^(?:@\[[^\]]+\][ \n]?)+/, "");

// A reply's wire text: "@[Name]\n>{first 10 characters of theirs}..\n{reply}" (".." only when theirs was longer). Theirs
// leaves out a leading mention of the one replying (me). When it doesn't fit maxBytes, the quote shrinks to 6
// characters, then goes, leaving "@[Name]\n{reply}". -> the text, or null when the reply alone doesn't fit.
export function buildReply(name, original, body, maxBytes, me = "") {
  let theirs = collapse(original);
  if (me && theirs.startsWith("@[" + me + "]")) theirs = collapse(theirs.slice(me.length + 3));
  const fits = (t) => utf8Encode(t).length <= maxBytes;
  for (const n of [10, 6]) {
    const c = chars(theirs);
    const quote = c.slice(0, n).join("").trim() + (c.length > n ? ".." : "");
    const t = "@[" + name + "]\n>" + quote + "\n" + body;
    if (quote.replace(/\.\.$/, "") && fits(t)) return t;
  }
  const t = "@[" + name + "]\n" + body;
  return fits(t) ? t : null;
}

// A reply's parts, or null: {name, quote (may be ""), body, partial: the quote was cut}. MeshCore One's
// "@[Name]\n>quote..\nreply" (and "@[Name]\nreply" with no quote line), and meshcore-open's "@[Name] re:quote…reply".
// A plain mention ("@[Name] hello") isn't a reply.
export function parseReply(text) {
  let m = /^@\[([^\]\n]+)\]\n>([^\n]*)\n([\s\S]*)$/.exec(text);
  if (m) {
    const partial = m[2].endsWith("..");
    return { name: m[1], quote: partial ? m[2].slice(0, -2) : m[2], body: m[3], partial };
  }
  m = /^@\[([^\]\n]+)\] re:([\s\S]*?)(?:…|\.\.\.)\s*([\s\S]*)$/i.exec(text);
  if (m) return { name: m[1], quote: m[2], body: m[3], partial: true };
  m = /^@\[([^\]\n]+)\]\n(?!>)([\s\S]+)$/.exec(text);
  if (m) return { name: m[1], quote: "", body: m[2], partial: false };
  return null;
}

// Whether a message's text is the one a reply quotes: it starts with the quote, ignoring case, runs of whitespace and
// leading mentions on both sides.
export function quoteMatches(original, quote) {
  const norm = (s) => collapse(stripMentions(collapse(s))).toLowerCase();
  const q = norm(quote);
  return !!q && norm(original).startsWith(q);
}
