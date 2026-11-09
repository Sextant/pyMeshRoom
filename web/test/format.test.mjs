// Reactions as the MeshTrax message format and MeshCore One describe them; the vectors and cases are MeshTrax's own
// (test/reaction_helper_test.dart).
import assert from "node:assert/strict";
import { test } from "node:test";
import { buildReply, emojiOnly, hashTexts, messageHash, parseReaction, parseReply, quoteMatches, reactionText } from "../src/format.js";

test("message hash: MeshCore One's pinned reference vectors", () => {
  assert.equal(messageHash("Hello", 1234567890), "66nf5k51");
  assert.equal(messageHash("Hello there!", 1234567890), "hqgk5p39");
  assert.equal(messageHash("Hello", 1234567891), "g4g6ht01");
  assert.equal(messageHash("", 0), "vwzp3604");
  assert.equal(messageHash("héllo wörld 👍", 1700000000), "x1cm5x6b");
});

test("reactions: every shape the apps send", () => {
  assert.deepEqual(parseReaction("@[AlphaNode]👍\nb45pc4ek"), { emoji: "👍", hash: "b45pc4ek", targetSender: "AlphaNode" });
  assert.deepEqual(parseReaction("👍@[AlphaNode]\n66nf5k51"), { emoji: "👍", hash: "66nf5k51", targetSender: "AlphaNode" });
  assert.deepEqual(parseReaction("❤️@[Vacasity]\nd68tbhcs"), { emoji: "❤️", hash: "d68tbhcs", targetSender: "Vacasity" });
  assert.deepEqual(parseReaction("👍\n66nf5k51"), { emoji: "👍", hash: "66nf5k51", targetSender: null });
  assert.equal(parseReaction("👍\nX1CM5X6B").hash, "x1cm5x6b");
  assert.equal(parseReaction("👍\ng4g6htOl").hash, "g4g6ht01");
  assert.ok(parseReaction("1️⃣\n66nf5k51"));
  assert.deepEqual(parseReaction("r:1a2b:00"), { emoji: "👍", legacy: true });
  const back = parseReaction(reactionText("🔥", "66nf5k51", "Bob"));
  assert.deepEqual(back, { emoji: "🔥", hash: "66nf5k51", targetSender: "Bob" });
});

test("reactions: prose and malformed text are not reactions", () => {
  for (const t of ["Hi\nabcdefgh", "Hello\n66nf5k51", "@[Bob]\n>❤️ok\ntomorrow", "👍66nf5k51", "👍\n66nf5k5", "👍\n66nf5k511",
    "👍\nuuuuuuuu", "👍@[]\n66nf5k51", "@[]👍\n66nf5k51", "@[AlphaNode]\n66nf5k51", "", "r:1a2b:ff"])
    assert.equal(parseReaction(t), null, JSON.stringify(t));
});

test("text forms tried when matching, and emoji-only messages", () => {
  assert.deepEqual(hashTexts(" @[Bob] hello\t"), ["@[Bob] hello", " @[Bob] hello\t", "hello"]);
  assert.deepEqual(hashTexts("plain"), ["plain"]);
  assert.deepEqual(hashTexts("hi\u00a0"), ["hi", "hi\u00a0"]);                       // (a no-break space is trimmed too)
  assert.deepEqual(hashTexts("@[Bob]\n>quote\nreply"), ["@[Bob]\n>quote\nreply", ">quote\nreply"]);
  assert.equal(emojiOnly("👍"), true);
  assert.equal(emojiOnly("🎉 🎉 🔥"), true);
  assert.equal(emojiOnly("👍👍👍👍👍👍"), false);
  assert.equal(emojiOnly("ok 👍"), false);
  assert.equal(emojiOnly("123"), false);
});

test("replies, as MeshCore One and MeshTrax write them", () => {
  assert.equal(buildReply("GWQ∆🍓", "Heading to the  trailhead now", "Nice!", 160), "@[GWQ∆🍓]\n>Heading to..\nNice!");
  assert.equal(buildReply("Bob", "short", "ok", 160), "@[Bob]\n>short\nok");                          // (no ".." when whole)
  assert.equal(buildReply("Bob", "@[Me] are you there yet?", "yes", 160, "Me"), "@[Bob]\n>are you th..\nyes");
  assert.equal(buildReply("Bob", "🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉", "!", 160), "@[Bob]\n>🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉..\n!");
  const body = "x".repeat(140);
  assert.equal(buildReply("Bob", "Heading to the trailhead", body, 160), "@[Bob]\n>Headin..\n" + body);   // shrinks
  assert.equal(buildReply("Bob", "Heading to the trailhead", "y".repeat(150), 160), "@[Bob]\n" + "y".repeat(150));
  assert.equal(buildReply("Bob", "hi", "z".repeat(160), 160), null);
  assert.deepEqual(parseReply("@[GWQ∆🍓]\n>Heading to..\nNice!"), { name: "GWQ∆🍓", quote: "Heading to", body: "Nice!", partial: true });
  assert.deepEqual(parseReply("@[Bob]\n>short\nok\nmore"), { name: "Bob", quote: "short", body: "ok\nmore", partial: false });
  assert.deepEqual(parseReply("@[Bob] Re:what time…  noon"), { name: "Bob", quote: "what time", body: "noon", partial: true });
  assert.deepEqual(parseReply("@[Bob]\nsure"), { name: "Bob", quote: "", body: "sure", partial: false });
  assert.equal(parseReply("@[Bob] hello"), null);                                                  // a mention, not a reply
  assert.equal(quoteMatches("@[Me]  Heading TO the trailhead", "heading to"), true);
  assert.equal(quoteMatches("Somewhere else", "heading to"), false);
});
