#!/usr/bin/env python3
"""Build fingerprinted dashboard files for Workers Static Assets.

The files under dashboard/ stay unhashed. The native server and its tests
serve those exact paths. Wrangler uploads only the directory this script
writes, and the wasm Worker does not embed the bytes.
"""

import hashlib
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "dashboard"
OUT = ROOT / "build" / "dashboard-assets"
DASH = OUT / "dashboard"

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'self'; base-uri 'none'; "
    "frame-ancestors 'none'; form-action 'self'"
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


def read(relative: str) -> bytes:
    path = SRC / relative
    if not path.is_file():
        sys.exit(f"missing dashboard file: {path}")
    return path.read_bytes()


def write_hashed(relative: str, data: bytes) -> str:
    directory, name = relative.rsplit("/", 1) if "/" in relative else ("", relative)
    stem, extension = name.rsplit(".", 1)
    filename = f"{stem}.{digest(data)}.{extension}"
    target = DASH / directory / filename if directory else DASH / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    prefix = f"/dashboard/{directory}" if directory else "/dashboard"
    return f"{prefix}/{filename}"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        sys.exit(f"{label} expected one {old!r}, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    DASH.mkdir(parents=True)
    (DASH / "locales").mkdir()

    app_js = write_hashed("app.js", read("app.js"))
    memory_js = write_hashed("memory.js", read("memory.js"))
    style_css = write_hashed("style.css", read("style.css"))
    en_json = write_hashed("locales/en.json", read("locales/en.json"))
    zh_json = write_hashed("locales/zh.json", read("locales/zh.json"))

    i18n = read("i18n.js").decode()
    i18n = replace_once(
        i18n,
        "return fetch('/dashboard/locales/' + lang + '.json', { credentials: 'same-origin' })",
        "var localeUrls = "
        + '{"en":"'
        + en_json
        + '","zh":"'
        + zh_json
        + '"};\n'
        + "    return fetch(localeUrls[lang], { credentials: 'same-origin' })",
        "i18n.js",
    )
    i18n_js = write_hashed("i18n.js", i18n.encode())

    html = read("index.html").decode()
    for old, new, label in (
        ('href="/dashboard/style.css"', f'href="{style_css}"', "style.css"),
        ('src="/dashboard/i18n.js"', f'src="{i18n_js}"', "i18n.js"),
        ('src="/dashboard/memory.js"', f'src="{memory_js}"', "memory.js"),
        ('src="/dashboard/app.js"', f'src="{app_js}"', "app.js"),
    ):
        html = replace_once(html, old, new, label)
    encoded = html.encode()
    (OUT / "index.html").write_bytes(encoded)
    (DASH / "index.html").write_bytes(encoded)

    # A header set twice is comma-joined, so Cache-Control is only on
    # fingerprinted files. HTML keeps the platform default
    # (public, max-age=0, must-revalidate). These rules do not apply to
    # Worker responses; API and auth responses stay no-store in the Worker.
    (OUT / "_headers").write_text(
        "\n".join(
            [
                "# Security headers for static assets. Do not repeat Cache-Control here.",
                "/*",
                "\tX-Content-Type-Options: nosniff",
                "\tReferrer-Policy: no-referrer",
                f"\tContent-Security-Policy: {CSP}",
                "\tStrict-Transport-Security: max-age=31536000",
                "",
                "/dashboard/*.js",
                "\tCache-Control: public, max-age=31536000, immutable",
                "",
                "/dashboard/*.css",
                "\tCache-Control: public, max-age=31536000, immutable",
                "",
                "/dashboard/locales/*",
                "\tCache-Control: public, max-age=31536000, immutable",
                "",
            ]
        )
    )


if __name__ == "__main__":
    main()
