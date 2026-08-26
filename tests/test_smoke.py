import datetime as dt

from src.audit import (
    build_rows,
    compute_compliance,
    compute_risk_score,
    fetch_repos,
    render_markdown,
    summarize_rows,
)


def test_compute_compliance_and_risk_score() -> None:
    row = {
        "branch_protected": False,
        "required_reviews": 0,
        "conversation_resolution": False,
        "enforce_admins": False,
        "allow_force_push": True,
        "allow_deletions": True,
        "dependabot_open_alerts": 3,
        "code_scanning_open_alerts": 1,
        "secret_scanning_open_alerts": 1,
        "stale": True,
    }

    compliant, reasons = compute_compliance(row, min_reviews=1)
    assert compliant is False
    assert "branch_not_protected" in reasons
    assert "secret_scanning_alerts_open" in reasons
    assert "admin_bypass_allowed" in reasons
    assert compute_risk_score(row) >= 60


def test_unknown_security_evidence_is_not_scored_as_failure() -> None:
    row = {
        "branch_protected": None,
        "required_reviews": None,
        "conversation_resolution": None,
        "enforce_admins": None,
        "allow_force_push": None,
        "allow_deletions": None,
        "dependabot_open_alerts": None,
        "code_scanning_open_alerts": None,
        "secret_scanning_open_alerts": None,
        "stale": False,
    }

    compliant, reasons = compute_compliance(row, min_reviews=1)
    assert compliant is None
    assert reasons == ["evidence_unavailable"]
    assert compute_risk_score(row) == 0

    summary = summarize_rows([{**row, "compliant": compliant, "risk_score": 0}])
    assert summary["compliant"] == 0
    assert summary["non_compliant"] == 0
    assert summary["unknown"] == 1


def test_fetch_repos_paginates_until_no_next_link(monkeypatch) -> None:
    class FakeResponse:
        def __init__(self, payload, link: str = "") -> None:
            self._payload = payload
            self.headers = {"Link": link} if link else {}

        def raise_for_status(self) -> None:
            return None

        def json(self):
            return self._payload

    calls: list[str] = []

    def fake_get(url: str, **_: object) -> FakeResponse:
        calls.append(url)
        if "page=2" in url:
            return FakeResponse(
                [
                    {
                        "name": "repo-b",
                        "full_name": "Beckerr11/repo-b",
                        "default_branch": "main",
                        "private": False,
                        "archived": False,
                        "fork": False,
                        "updated_at": "2026-08-20T00:00:00Z",
                    }
                ]
            )
        return FakeResponse(
            [
                {
                    "name": "repo-a",
                    "full_name": "Beckerr11/repo-a",
                    "default_branch": "main",
                    "private": False,
                    "archived": False,
                    "fork": False,
                    "updated_at": "2026-08-21T00:00:00Z",
                }
            ],
            '<https://api.github.com/users/Beckerr11/repos?per_page=100&sort=updated&page=2>; rel="next"',
        )

    monkeypatch.setattr("src.audit.requests.get", fake_get)

    repos = fetch_repos("Beckerr11", "token")
    assert [repo["name"] for repo in repos] == ["repo-a", "repo-b"]
    assert len(calls) == 2


def test_render_markdown_contains_summary_and_table() -> None:
    rows = [
        {
            "owner": "Beckerr11",
            "repository": "demo",
            "visibility": "public",
            "dependabot_open_alerts": 0,
            "code_scanning_open_alerts": 0,
            "secret_scanning_open_alerts": 0,
            "updated_at": "2026-01-10T10:00:00Z",
            "stale": False,
            "branch_protected": True,
            "required_reviews": 1,
            "conversation_resolution": True,
            "enforce_admins": True,
            "allow_force_push": False,
            "allow_deletions": False,
            "compliant": True,
            "risk_score": 0,
            "reasons": [],
            "recommendations": [],
        }
    ]

    summary = summarize_rows(rows)
    output = render_markdown("Beckerr11", rows, summary)
    assert "# GitHub Security Audit - Beckerr11" in output
    assert "- Repos auditados: 1" in output
    assert "- Evidencia insuficiente: 0" in output
    assert "| Repository | Visibility | Dependabot |" in output
    assert "| demo | public | 0 | 0 | 0 | False | True | 1 | True | True | False | False | ok | 0 |" in output


def test_build_rows_uses_repo_and_protection_data(monkeypatch) -> None:
    repos = [
        {
            "name": "repo-a",
            "full_name": "Beckerr11/repo-a",
            "default_branch": "main",
            "private": False,
            "archived": False,
            "fork": False,
            "updated_at": (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=200)).isoformat(),
        }
    ]

    def fake_dep(_: str, __: str | None) -> int:
        return 2

    def fake_code(_: str, __: str | None) -> int:
        return 0

    def fake_secret(_: str, __: str | None) -> int:
        return 0

    def fake_protection(_: str, __: str, ___: str | None) -> dict:
        return {
            "protected": True,
            "required_reviews": 1,
            "conversation_resolution": True,
            "enforce_admins": True,
            "allow_force_push": False,
            "allow_deletions": False,
        }

    monkeypatch.setattr("src.audit.fetch_dependabot_alerts_count", fake_dep)
    monkeypatch.setattr("src.audit.fetch_code_scanning_alerts_count", fake_code)
    monkeypatch.setattr("src.audit.fetch_secret_scanning_alerts_count", fake_secret)
    monkeypatch.setattr("src.audit.fetch_branch_protection", fake_protection)

    rows = build_rows("Beckerr11", repos, "token", stale_days=180)
    assert len(rows) == 1
    assert rows[0]["repository"] == "repo-a"
    assert rows[0]["dependabot_open_alerts"] == 2
    assert rows[0]["stale"] is True
    assert rows[0]["compliant"] is False
