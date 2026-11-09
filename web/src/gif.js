// GIFs: a Giphy link in a message (as people paste them from giphy.com) is shown as the GIF itself.
// Only Giphy's own image hosts are ever loaded, by id, so a message can't make the page fetch anything else.

// As the MeshTrax message format reads them, standing alone (separated by spaces or line breaks): meshcore-open's
// g:ID; giphy.com/gifs/[slug-]ID (also /embed/, /clips/, /stickers/); media[0-4].giphy.com/media/[v1.../]ID/...;
// i.giphy.com/[media/]ID[.gif]. The scheme is optional on the links.
const GIPHY_RE = new RegExp(
  "(?<=^|\\s)(?:" +
    "g:([A-Za-z0-9_-]{12,64})" +
    "|(?:https?://)?(?:" +
      "(?:www\\.)?giphy\\.com/(?:gifs|embed|clips|stickers)/(?:[\\w-]*-)?([A-Za-z0-9]{6,40})" +
      "|media\\d?\\.giphy\\.com/media/(?:v1\\.[\\w.=-]+/)?([A-Za-z0-9]{6,40})" +
      "|i\\.giphy\\.com/(?:media/)?([A-Za-z0-9]{6,40})" +
    ")[^\\s]*" +
  ")(?=$|\\s)",
  "g",
);

// [{start, end, id}] for each Giphy link in the text, in order.
export function findGifs(text) {
  const out = [];
  for (const m of String(text).matchAll(GIPHY_RE)) {
    out.push({ start: m.index, end: m.index + m[0].length, id: m[1] || m[2] || m[3] || m[4] });
  }
  return out;
}

export const gifUrl = (id) => "https://media.giphy.com/media/" + id + "/giphy.gif";
export const gifFallbackUrl = (id) => "https://i.giphy.com/" + id + ".gif";
export const gifPageUrl = (id) => "https://giphy.com/gifs/" + id;
// A small rendition, for the GIF picker.
export const gifThumbUrl = (id) => "https://media.giphy.com/media/" + id + "/200w.gif";
