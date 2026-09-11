#!/usr/bin/env python3
import time
import urllib.request
import urllib.error

URL = "https://negrito-ommar.onrender.com/"
INTERVAL_SECONDS = 10 * 60
TIMEOUT_SECONDS = 25


def ping():
    request = urllib.request.Request(
        URL,
        method="GET",
        headers={
            "User-Agent": "RenderKeepAlive/1.0",
            "Cache-Control": "no-cache",
        },
    )

    started = time.monotonic()

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            elapsed = time.monotonic() - started
            print(
                f"[OK] HTTP {response.status} | "
                f"{elapsed:.2f}s | {URL}",
                flush=True,
            )

    except urllib.error.HTTPError as e:
        elapsed = time.monotonic() - started
        print(
            f"[HTTP] {e.code} | {elapsed:.2f}s | {URL}",
            flush=True,
        )

    except Exception as e:
        elapsed = time.monotonic() - started
        print(
            f"[ERROR] {type(e).__name__}: {e} | "
            f"{elapsed:.2f}s | {URL}",
            flush=True,
        )


def main():
    print("Render Keep Alive iniciado.")
    print(f"URL: {URL}")
    print("Intervalo: 10 minutos")
    print("Ctrl+C para detenerlo.\n", flush=True)

    while True:
        ping()
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
