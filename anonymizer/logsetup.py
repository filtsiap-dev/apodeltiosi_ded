"""Third-party loggers are configured on purpose, not inherited by accident.

``ANON_LOG_LEVEL=DEBUG`` is a reasonable thing for an operator to do when a
document is behaving strangely. Without this module it is also a data breach:
the OpenAI SDK logs its request options at DEBUG, and those options include
``messages`` — the prompt, which is the document. Turning up the application's
own verbosity must not turn on somebody else's.

So the SDK and HTTP loggers get their level set explicitly, and it is not
inherited from the root. This overrides ``OPENAI_LOG=debug`` as well, which is
the other way the same bodies reach a log.

Levels only, never handlers: the application's formatting and destination are
decided in one place (``anonymizer.api.configure_logging``), and adding a second
handler here would duplicate every line.
"""

from __future__ import annotations

import logging

# Loggers that are capable of printing the document, or the credentials used to
# send it, and the ceiling each is held to whatever the application level is.
#
#   openai    - `openai._base_client` logs "Request options" at DEBUG, including
#               the `messages` payload. That payload is the document text.
#   httpx     - one INFO line per request (method and URL). Harmless, and noisy
#               at one line per provider call, so it is held at WARNING too.
#   httpcore  - DEBUG traces of connection and header activity.
THIRD_PARTY_LOG_LEVELS: dict[str, int] = {
    "openai": logging.WARNING,
    "httpx": logging.WARNING,
    "httpcore": logging.WARNING,
}


def clamp_third_party_loggers() -> None:
    """Hold the SDK and HTTP loggers at WARNING, whatever the app level is.

    Called from every entry point that configures logging — the HTTP service and
    the CLI — because both can be run with a raised level and both would
    otherwise inherit it.
    """
    for name, level in THIRD_PARTY_LOG_LEVELS.items():
        logging.getLogger(name).setLevel(level)


__all__ = ["THIRD_PARTY_LOG_LEVELS", "clamp_third_party_loggers"]
