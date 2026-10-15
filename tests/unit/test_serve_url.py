"""The auth token must never travel in a URL the server can see.

A query string ends up in the uvicorn access log ("GET /?token=... 200"),
in the browser's history and, for any subresource loaded before the
dashboard strips it, in a Referer header. The fragment is never sent to a
server, so it is the only URL slot the hand-off can safely use.
"""

import webbrowser

from click.testing import CliRunner

from mcrataway.cli import main
from mcrataway.server.auth import ensure_token


def test_serve_does_not_put_token_in_a_query_string(monkeypatch) -> None:
    opened: list[str] = []
    monkeypatch.setattr(webbrowser, "open", opened.append)
    monkeypatch.setattr("uvicorn.run", lambda *args, **kwargs: None)

    result = CliRunner().invoke(main, ["serve"])
    assert result.exit_code == 0, result.output

    token = ensure_token()
    assert opened, "serve did not open a browser URL"
    assert "?token=" not in opened[0], opened[0]
    assert opened[0].endswith(f"/#token={token}"), opened[0]
    assert f"?token={token}" not in result.output


def test_serve_opens_nothing_with_no_browser(monkeypatch) -> None:
    opened: list[str] = []
    monkeypatch.setattr(webbrowser, "open", opened.append)
    monkeypatch.setattr("uvicorn.run", lambda *args, **kwargs: None)

    result = CliRunner().invoke(main, ["serve", "--no-browser"])

    assert result.exit_code == 0, result.output
    assert opened == []
