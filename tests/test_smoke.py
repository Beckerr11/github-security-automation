from src.audit import build_rows, render_markdown


def test_render_markdown_contains_table_headers() -> None:
    rows = [
        {
            "owner": "Beckerr11",
            "repository": "demo",
            "visibility": "public",
            "dependabot_open_alerts": 0,
            "branch_protected": True,
            "required_reviews": 1,
            "conversation_resolution": True,
            "allow_force_push": False,
            "allow_deletions": False,
        }
    ]

    output = render_markdown("Beckerr11", rows)
    assert "# GitHub Security Audit - Beckerr11" in output
    assert "| Repository | Visibility | Dependabot Open |" in output
    assert "| demo | public | 0 | True | 1 | True | False | False |" in output


def test_build_rows_uses_repo_and_protection_data(monkeypatch) -> None:
    repos = [
        {
            "name": "repo-a",
            "full_name": "Beckerr11/repo-a",
            "default_branch": "main",
            "private": False,
            "archived": False,
            "fork": False,
        }
    ]

    def fake_dep(_: str, __: str | None) -> int:
        return 2

    def fake_protection(_: str, __: str, ___: str | None) -> dict:
        return {
            "protected": True,
            "required_reviews": 1,
            "conversation_resolution": True,
            "allow_force_push": False,
            "allow_deletions": False,
        }

    monkeypatch.setattr("src.audit.fetch_dependabot_alerts_count", fake_dep)
    monkeypatch.setattr("src.audit.fetch_branch_protection", fake_protection)

    rows = build_rows("Beckerr11", repos, "token")
    assert len(rows) == 1
    assert rows[0]["repository"] == "repo-a"
    assert rows[0]["dependabot_open_alerts"] == 2
    assert rows[0]["required_reviews"] == 1