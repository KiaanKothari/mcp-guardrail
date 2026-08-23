from mcp_guardrail.scan import scan_text


def test_detects_openai_style_key():
    text = 'OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890ABCD'
    findings = scan_text(text, "config.env")
    assert any("OpenAI" in f.label for f in findings)


def test_detects_github_token():
    text = '{"env": {"GITHUB_TOKEN": "ghp_1234567890abcdef1234567890abcdef1234"}}'
    findings = scan_text(text, "mcp.json")
    assert any("GitHub" in f.label for f in findings)


def test_detects_aws_access_key_id():
    text = "aws_access_key_id = AKIAABCDEFGHIJKLMNOP"
    findings = scan_text(text, ".env")
    assert any("AWS Access Key" in f.label for f in findings)


def test_detects_private_key_block():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----"
    findings = scan_text(text, "id_rsa")
    assert any("private key" in f.label.lower() for f in findings)


def test_ignores_placeholder_values():
    text = 'api_key = "YOUR_API_KEY_HERE"'
    findings = scan_text(text, "config.yaml")
    assert findings == []


def test_ignores_env_var_reference():
    text = 'api_key: "${OPENAI_API_KEY}"'
    findings = scan_text(text, "config.yaml")
    assert findings == []


def test_masks_secret_in_preview():
    text = 'token = "sk-ant-abcdefghijklmnopqrstuvwxyz123456"'
    findings = scan_text(text, "config.yaml")
    assert findings
    for f in findings:
        assert "abcdefghij" not in f.preview
