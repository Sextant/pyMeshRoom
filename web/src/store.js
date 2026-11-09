// What this browser remembers, in localStorage. Every access is guarded: storage can be off or full.

const PREFIX = "meshcore-web.";

function read(key, fallback) {
  try {
    const v = localStorage.getItem(PREFIX + key);
    return v == null ? fallback : JSON.parse(v);
  } catch {
    return fallback;
  }
}

function write(key, value) {
  try {
    if (value === undefined) localStorage.removeItem(PREFIX + key);
    else localStorage.setItem(PREFIX + key, JSON.stringify(value));
  } catch {
    // (private mode, quota): this session still works, it just won't be remembered
  }
}

// {url, name, remember, privateKey?, pagePassword?}: the keys only when "remember" was ticked
export const loadSettings = () => read("settings", {});
export const saveSettings = (s) => write("settings", s);

// The message of the day this browser was asked not to show again (its hash): a new one shows.
export const loadMotdHidden = () => read("motd.hidden", null);
export const saveMotdHidden = (h) => write("motd.hidden", h);

// The emoji picker's recently used, most recent first.
export const loadRecentEmoji = () => read("emoji.recent", []);
export const saveRecentEmoji = (list) => write("emoji.recent", list);

// Per identity (its public key), so two identities in one browser don't share channels or history.
export const loadChannels = (pubHex) => read("channels." + pubHex.slice(0, 16), null);
export const saveChannels = (pubHex, list) => write("channels." + pubHex.slice(0, 16), list);
export const loadHistory = (pubHex) => read("history." + pubHex.slice(0, 16), {});
export const saveHistory = (pubHex, h) => write("history." + pubHex.slice(0, 16), h);

// Contacts (with routes and joined rooms), and the open conversations, per identity too.
export const loadContacts = (pubHex) => read("contacts." + pubHex.slice(0, 16), []);
export const saveContacts = (pubHex, list) => write("contacts." + pubHex.slice(0, 16), list);
export const loadConversations = (pubHex) => read("conversations." + pubHex.slice(0, 16), { dms: [], last: null });
export const saveConversations = (pubHex, c) => write("conversations." + pubHex.slice(0, 16), c);

// How far this browser has caught up, per identity and server: the last backlog seq it has.
export const loadCursor = (pubHex, server) => {
  const c = read("cursor." + pubHex.slice(0, 16), null);
  return c && c.server === server ? c.seq : null;
};
export const saveCursor = (pubHex, server, seq) => write("cursor." + pubHex.slice(0, 16), { server, seq });

export function forgetEverything() {
  try {
    for (const k of Object.keys(localStorage)) if (k.startsWith(PREFIX)) localStorage.removeItem(k);
  } catch {
    // nothing stored, or nothing reachable
  }
}
