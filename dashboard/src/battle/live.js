// LIVE mode transport (Stage 7 #13, D48/D49). The ONLY module of the dashboard that opens a
// connection, and only one kind: a same-origin Server-Sent Events stream from the read-only
// live server (liveserver/), relative URL "events". Opened from file:// (REPLAY), the page
// makes no network request at all: liveAvailable() is false and nothing here runs.

export function liveAvailable(loc = typeof window !== "undefined" ? window.location : null) {
  return !!loc && loc.protocol === "http:" && (loc.hostname === "127.0.0.1" || loc.hostname === "localhost");
}

// Subscribe to the live server. onEvent(ev) per event; onStatus("connecting" | "open" |
// "reconnecting"). Returns a close function. The browser resumes with Last-Event-ID itself.
export function connectLive(onEvent, onStatus) {
  if (!liveAvailable()) return () => {};
  const src = new EventSource("events");
  onStatus("connecting");
  src.onopen = () => onStatus("open");
  src.onerror = () => onStatus("reconnecting");
  src.onmessage = (m) => {
    try {
      onEvent(JSON.parse(m.data));
    } catch {
      /* a malformed message is skipped; the server only sends JSON */
    }
  };
  return () => src.close();
}
