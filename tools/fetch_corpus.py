"""Collect real HTTP/2 response header blocks, grouped per connection.

One trace equals one origin: the HPACK dynamic table is per connection, so the
encoder state that matters is the ordered sequence of header blocks a single
server sends on a single connection. We load a page, pull its subresource URLs
out of the HTML, and request them over the same pooled client, which is what a
browser does.
"""
import json
import re
import sys
import time
from collections import OrderedDict
from urllib.parse import urljoin, urlsplit

import httpx

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# Connection specific fields are illegal in HTTP/2 (RFC 9113 section 8.2.2).
# httpx normalises h2 pseudo headers away, so we re-add :status explicitly.
HOP_BY_HOP = {"connection", "keep-alive", "transfer-encoding", "upgrade",
              "proxy-connection", "te"}

_EXT = r"js|css|png|jpg|jpeg|gif|svg|webp|woff2?|ico|json"
SRC_RE = re.compile(
    rb"""(?:src|href)\s*=\s*["']([^"'>\s]+\.(?:%s))""" % _EXT.encode(),
    re.I)

SITES = [
    "https://en.wikipedia.org/wiki/HTTP/2",
    "https://github.com/python/cpython",
    "https://www.cloudflare.com/",
    "https://stackoverflow.com/questions/tagged/http2",
    "https://news.ycombinator.com/",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    "https://www.nytimes.com/",
    "https://pypi.org/project/httpx/",
    "https://www.reddit.com/r/programming/",
    "https://arxiv.org/list/cs.NI/recent",
]

MAX_PER_HOST = 60
MIN_BLOCKS = 8


def block_from(resp):
    """Render one response as an ordered HTTP/2 header block."""
    out = [(":status", str(resp.status_code))]
    for name, value in resp.headers.multi_items():
        low = name.lower()
        if low in HOP_BY_HOP:
            continue
        out.append((low, value))
    return out


def collect(client, urls, per_host):
    for url in urls:
        host = urlsplit(url).netloc
        if len(per_host.get(host, ())) >= MAX_PER_HOST:
            continue
        try:
            with client.stream("GET", url) as resp:
                if resp.http_version != "HTTP/2":
                    continue
                per_host.setdefault(host, []).append({
                    "path": urlsplit(str(resp.url)).path or "/",
                    "fields": block_from(resp),
                })
        except Exception:
            continue


def main(out_path):
    per_host = OrderedDict()
    headers = {"user-agent": CHROME_UA,
               "accept": "text/html,application/xhtml+xml,image/avif,image/webp,*/*;q=0.8",
               "accept-language": "en-US,en;q=0.9",
               "accept-encoding": "gzip, deflate, br"}
    started = time.time()
    with httpx.Client(http2=True, timeout=20.0, follow_redirects=True,
                      headers=headers,
                      limits=httpx.Limits(max_keepalive_connections=20)) as client:
        for site in SITES:
            try:
                page = client.get(site)
            except Exception as exc:
                print("  page failed", site, type(exc).__name__, flush=True)
                continue
            if page.http_version == "HTTP/2":
                host = urlsplit(str(page.url)).netloc
                per_host.setdefault(host, []).append({
                    "path": urlsplit(str(page.url)).path or "/",
                    "fields": block_from(page),
                })
            found = []
            seen = set()
            for raw in SRC_RE.findall(page.content[:900_000]):
                url = urljoin(str(page.url), raw.decode("utf8", "replace"))
                if not url.startswith("https://") or url in seen:
                    continue
                seen.add(url)
                found.append(url)
            collect(client, found[:220], per_host)
            done = sum(len(v) for v in per_host.values())
            print("  %-34s blocks=%d  %.0fs" % (site, done, time.time() - started),
                  flush=True)

    traces = [{"origin": host, "blocks": blocks}
              for host, blocks in per_host.items() if len(blocks) >= MIN_BLOCKS]
    traces.sort(key=lambda t: -len(t["blocks"]))
    with open(out_path, "w", encoding="utf8") as fh:
        json.dump({"direction": "response", "traces": traces}, fh)
    print("traces=%d blocks=%d fields=%d" % (
        len(traces), sum(len(t["blocks"]) for t in traces),
        sum(len(b["fields"]) for t in traces for b in t["blocks"])))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data/response_traces.json")
