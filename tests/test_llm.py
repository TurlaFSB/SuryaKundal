"""The Ollama client against a fake server (no real model needed)."""

import json

import httpx
import pytest

from surya_kundal.cli import main
from surya_kundal.llm.ollama import LLMError, OllamaClient, check_model


def _client(handler):
    return OllamaClient(
        "http://ollama.test/", client=httpx.Client(transport=httpx.MockTransport(handler))
    )


def _ok(request):
    if request.url.path == "/api/tags":
        return httpx.Response(200, json={"models": [{"name": "qwen2.5-coder:7b"}, {"name": "b"}]})
    sent = json.loads(request.content)
    assert sent["stream"] is False and sent["format"] == "json"
    return httpx.Response(
        200,
        json={
            "response": '{"tool": "uname", "purpose": "prints system info"}',
            "eval_count": 20,
            "eval_duration": 2_000_000_000,
        },
    )


def test_models_and_generation():
    client = _client(_ok)
    assert client.base_url == "http://ollama.test"
    assert client.models() == ["b", "qwen2.5-coder:7b"]
    result, valid = check_model(client, "qwen2.5-coder:7b")
    assert valid and result.tokens_per_second == pytest.approx(10.0)


def test_invalid_json_is_reported_not_raised():
    client = _client(lambda r: httpx.Response(200, json={"response": "sure! here you go"}))
    result, valid = check_model(client, "m")
    assert not valid and result.tokens_per_second is None


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(404, json={}), "not found"),
        (httpx.Response(500), "HTTP 500"),
        (httpx.Response(200, text="<html>"), "not JSON"),
        (httpx.Response(200, json=[1]), "unexpected"),
        (httpx.Response(200, json={"models": 3}), "unexpected"),
    ],
)
def test_bad_replies_raise_llmerror(response, message):
    with pytest.raises(LLMError, match=message):
        _client(lambda r: response).models()


def test_missing_text_and_network_failures():
    with pytest.raises(LLMError, match="no text"):
        _client(lambda r: httpx.Response(200, json={"x": 1})).generate("m", "p")

    def refuse(request):
        raise httpx.ConnectError("boom")

    def slow(request):
        raise httpx.ReadTimeout("slow")

    with pytest.raises(LLMError, match="cannot reach"):
        _client(refuse).models()
    with pytest.raises(LLMError, match="timed out"):
        _client(slow).models()


def test_url_must_be_http():
    with pytest.raises(LLMError):
        OllamaClient("ollama.local:11434")


def test_long_output_is_capped():
    client = _client(lambda r: httpx.Response(200, json={"response": "x" * 50_000}))
    assert len(client.generate("m", "p").text) == 20_000


def test_cli_check(monkeypatch, capsys):
    monkeypatch.chdir("/")
    monkeypatch.setattr(
        "surya_kundal.cli.OllamaClient",
        lambda url: OllamaClient(url, client=httpx.Client(transport=httpx.MockTransport(_ok))),
    )
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    assert main(["llm", "check", "--model", "qwen2.5-coder:7b"]) == 0
    out = capsys.readouterr().out
    assert "10.0 tok/s" in out and "JSON valid" in out
    assert main(["llm", "check", "--model", "ghost"]) == 1
    assert "not installed" in capsys.readouterr().out


def test_cli_check_when_server_is_down(monkeypatch, capsys):
    monkeypatch.chdir("/")

    def refuse(request):
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(
        "surya_kundal.cli.OllamaClient",
        lambda url: OllamaClient(url, client=httpx.Client(transport=httpx.MockTransport(refuse))),
    )
    assert main(["llm", "check"]) == 2
    assert "cannot reach" in capsys.readouterr().err
