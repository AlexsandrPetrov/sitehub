"""Entry point: start uvicorn with the port / TLS configured in the admin panel."""
import logging

import uvicorn

from . import config, db, tls


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("sitehub")
    db.init()
    host = config.get("host") or "0.0.0.0"
    port = config.get_int("port", 8080)
    kwargs = {}
    mode = config.get("ssl_mode")
    if mode != "off":
        pair = tls.usable(mode)
        if pair:
            kwargs = {"ssl_certfile": str(pair[0]), "ssl_keyfile": str(pair[1])}
        else:
            # Never lock the admin out: fall back to plain HTTP if the certificate is broken.
            log.error("SSL mode '%s' selected but certificate is missing/invalid - starting WITHOUT TLS", mode)
            db.audit("ssl_fallback", None, None, f"mode={mode}: сертификат недоступен, запуск по HTTP")
    log.info("SiteHub listening on %s://%s:%s", "https" if kwargs else "http", host, port)
    uvicorn.run("sitehub.app:app", host=host, port=port, proxy_headers=False, server_header=False,
                access_log=False, log_level="info", **kwargs)


if __name__ == "__main__":
    main()
