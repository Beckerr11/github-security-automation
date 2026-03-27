#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
from typing import Any

import requests

API_BASE = "https://api.github.com"


def build_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_repos(owner: str, token: str | None) -> list[dict[str, Any]]:
    url = f"{API_BASE}/users/{owner}/repos?per_page=100&sort=updated"
    response = requests.get(url, headers=build_headers(token), timeout=30)
    response.raise_for_status()
    repos = response.json()

    return [
        {
            "name": repo["name"],
            "full_name": repo["full_name"],
            "default_branch": repo.get("default_branch", "main"),
            "private": bool(repo.get("private", False)),
            "archived": bool(repo.get("archived", False)),
            "fork": bool(repo.get("fork", False)),
            "updated_at": repo.get("updated_at"),
        }
        for repo in repos
        if not repo.get("archived") and not repo.get("fork")
    ]


def paginated_alert_count(url: str, token: str | None) -> int | None:
    if not token:
        return None

    count = 0
    next_url = url

    while next_url:
        response = requests.get(next_url, headers=build_headers(token), timeout=30)
        if response.status_code in (403, 404):
            return None
        response.raise_for_status()

        payload = response.json()
        if not isinstance(payload, list):
            return None

        count += len(payload)

        link_header = response.headers.get("Link", "")
        if 'rel="next"' not in link_header:
            break

        next_url = ""
        for part in link_header.split(","):
            if 'rel="next"' in part:
                left = part.split(";")[0].strip()
                next_url = left.strip("<>")
                break

    return count


def fetch_dependabot_alerts_count(full_name: str, token: str | None) -> int | None:
    url = f"{API_BASE}/repos/{full_name}/dependabot/alerts?state=open&per_page=100"
    return paginated_alert_count(url, token)


def fetch_code_scanning_alerts_count(full_name: str, token: str | None) -> int | None:
    url = f"{API_BASE}/repos/{full_name}/code-scanning/alerts?state=open&per_page=100"
    return paginated_alert_count(url, token)


def fetch_secret_scanning_alerts_count(full_name: str, token: str | None) -> int | None:
    url = f"{API_BASE}/repos/{full_name}/secret-scanning/alerts?state=open&per_page=100"
    return paginated_alert_count(url, token)


def fetch_branch_protection(full_name: str, branch: str, token: str | None) -> dict[str, Any]:
    if not token:
        return {"protected": None}

    url = f"{API_BASE}/repos/{full_name}/branches/{branch}/protection"
    response = requests.get(url, headers=build_headers(token), timeout=30)

    if response.status_code == 404:
        return {
            "protected": False,
            "required_reviews": 0,
            "conversation_resolution": False,
            "allow_force_push": None,
            "allow_deletions": None,
        }

    response.raise_for_status()
    payload = response.json()

    required_reviews = 0
    if payload.get("required_pull_request_reviews"):
        required_reviews = int(payload["required_pull_request_reviews"].get("required_approving_review_count", 0))

    return {
        "protected": True,
        "required_reviews": required_reviews,
        "conversation_resolution": bool(payload.get("required_conversation_resolution", {}).get("enabled", False)),
        "allow_force_push": payload.get("allow_force_pushes", {}).get("enabled"),
        "allow_deletions": payload.get("allow_deletions", {}).get("enabled"),
    }


def parse_iso_datetime(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return dt.datetime.fromisoformat(value)
    except ValueError:
        return None


def is_repo_stale(updated_at: str | None, stale_days: int) -> bool:
    parsed = parse_iso_datetime(updated_at)
    if not parsed:
        return False

    now = dt.datetime.now(dt.timezone.utc)
    age = now - parsed.astimezone(dt.timezone.utc)
    return age.days >= stale_days


def compute_compliance(row: dict[str, Any], min_reviews: int) -> tuple[bool, list[str]]:
    reasons: list[str] = []

    if row["branch_protected"] is not True:
        reasons.append("branch_not_protected")

    if int(row["required_reviews"] or 0) < min_reviews:
        reasons.append("insufficient_reviews")

    if row["conversation_resolution"] is not True:
        reasons.append("conversation_resolution_disabled")

    if row["allow_force_push"] is True:
        reasons.append("force_push_allowed")

    if row["allow_deletions"] is True:
        reasons.append("branch_deletion_allowed")

    dep = row["dependabot_open_alerts"]
    if dep is not None and int(dep) > 0:
        reasons.append("dependabot_alerts_open")

    code_scanning = row["code_scanning_open_alerts"]
    if code_scanning is not None and int(code_scanning) > 0:
        reasons.append("code_scanning_alerts_open")

    secret_scanning = row["secret_scanning_open_alerts"]
    if secret_scanning is not None and int(secret_scanning) > 0:
        reasons.append("secret_scanning_alerts_open")

    if row["stale"]:
        reasons.append("repository_stale")

    return (len(reasons) == 0, reasons)


def compute_risk_score(row: dict[str, Any]) -> int:
    score = 0

    if row["branch_protected"] is not True:
        score += 35
    if int(row["required_reviews"] or 0) == 0:
        score += 20
    if row["conversation_resolution"] is not True:
        score += 10
    if row["allow_force_push"] is True:
        score += 15
    if row["allow_deletions"] is True:
        score += 10

    dep = row["dependabot_open_alerts"]
    if dep is not None:
        score += min(int(dep) * 4, 20)

    code_scanning = row["code_scanning_open_alerts"]
    if code_scanning is not None:
        score += min(int(code_scanning) * 6, 24)

    secret_scanning = row["secret_scanning_open_alerts"]
    if secret_scanning is not None:
        score += min(int(secret_scanning) * 8, 24)

    if row["stale"]:
        score += 8

    return min(score, 100)


def recommendations_from_reasons(reasons: list[str]) -> list[str]:
    mapping = {
        "branch_not_protected": "Ativar branch protection no branch principal.",
        "insufficient_reviews": "Exigir no minimo uma aprovacao de PR.",
        "conversation_resolution_disabled": "Exigir resolucao de conversas antes do merge.",
        "force_push_allowed": "Desativar force push no branch principal.",
        "branch_deletion_allowed": "Desativar exclusao do branch principal.",
        "dependabot_alerts_open": "Priorizar correcoes de alertas Dependabot.",
        "code_scanning_alerts_open": "Corrigir alertas de code scanning em aberto.",
        "secret_scanning_alerts_open": "Revogar e rotacionar segredos expostos.",
        "repository_stale": "Revisar atividade do repo e arquivar se nao for mais usado.",
    }
    return [mapping[reason] for reason in reasons if reason in mapping]


def build_rows(
    owner: str,
    repos: list[dict[str, Any]],
    token: str | None,
    min_reviews: int = 1,
    stale_days: int = 180,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for repo in repos:
        dep_count = fetch_dependabot_alerts_count(repo["full_name"], token)
        code_scanning_count = fetch_code_scanning_alerts_count(repo["full_name"], token)
        secret_scanning_count = fetch_secret_scanning_alerts_count(repo["full_name"], token)
        protection = fetch_branch_protection(repo["full_name"], repo["default_branch"], token)
        stale = is_repo_stale(repo.get("updated_at"), stale_days)

        row = {
            "owner": owner,
            "repository": repo["name"],
            "visibility": "private" if repo["private"] else "public",
            "updated_at": repo.get("updated_at"),
            "stale": stale,
            "dependabot_open_alerts": dep_count,
            "code_scanning_open_alerts": code_scanning_count,
            "secret_scanning_open_alerts": secret_scanning_count,
            "branch_protected": protection.get("protected"),
            "required_reviews": protection.get("required_reviews"),
            "conversation_resolution": protection.get("conversation_resolution"),
            "allow_force_push": protection.get("allow_force_push"),
            "allow_deletions": protection.get("allow_deletions"),
        }

        compliant, reasons = compute_compliance(row, min_reviews)
        row["compliant"] = compliant
        row["reasons"] = reasons
        row["recommendations"] = recommendations_from_reasons(reasons)
        row["risk_score"] = compute_risk_score(row)

        rows.append(row)

    return rows


def summarize_rows(rows: list[dict[str, Any]]) -> dict[str, int]:
    total = len(rows)
    compliant = sum(1 for row in rows if row["compliant"])
    non_compliant = total - compliant
    high_risk = sum(1 for row in rows if int(row["risk_score"]) >= 60)
    dep_open = sum(1 for row in rows if (row["dependabot_open_alerts"] or 0) > 0)
    code_open = sum(1 for row in rows if (row["code_scanning_open_alerts"] or 0) > 0)
    secret_open = sum(1 for row in rows if (row["secret_scanning_open_alerts"] or 0) > 0)
    stale = sum(1 for row in rows if row["stale"])

    return {
        "total": total,
        "compliant": compliant,
        "non_compliant": non_compliant,
        "high_risk": high_risk,
        "repos_with_dependabot_alerts": dep_open,
        "repos_with_code_scanning_alerts": code_open,
        "repos_with_secret_scanning_alerts": secret_open,
        "stale_repositories": stale,
    }


def render_markdown(owner: str, rows: list[dict[str, Any]], summary: dict[str, int]) -> str:
    generated_at = dt.datetime.now(dt.timezone.utc).isoformat()
    lines = [
        f"# GitHub Security Audit - {owner}",
        "",
        f"Gerado em: {generated_at}",
        "",
        "## Resumo",
        f"- Repos auditados: {summary['total']}",
        f"- Compliant: {summary['compliant']}",
        f"- Nao compliant: {summary['non_compliant']}",
        f"- Alto risco (>=60): {summary['high_risk']}",
        f"- Repos com alertas Dependabot: {summary['repos_with_dependabot_alerts']}",
        f"- Repos com alertas code scanning: {summary['repos_with_code_scanning_alerts']}",
        f"- Repos com alertas secret scanning: {summary['repos_with_secret_scanning_alerts']}",
        f"- Repos stale: {summary['stale_repositories']}",
        "",
        "## Detalhes",
        "| Repository | Visibility | Dependabot | Code Scan | Secret Scan | Stale | Protected | Reviews | Conversation | Force Push | Delete | Compliance | Risk |",
        "|---|---|---:|---:|---:|---|---|---:|---|---|---|---|---:|",
    ]

    for row in rows:
        dep = row["dependabot_open_alerts"]
        dep_text = str(dep) if dep is not None else "n/a"
        code = row["code_scanning_open_alerts"]
        code_text = str(code) if code is not None else "n/a"
        secret = row["secret_scanning_open_alerts"]
        secret_text = str(secret) if secret is not None else "n/a"
        compliance = "ok" if row["compliant"] else "pendente"
        lines.append(
            "| {repository} | {visibility} | {dep} | {code} | {secret} | {stale} | {protected} | {reviews} | {conversation} | {force_push} | {deletions} | {compliance} | {risk} |".format(
                repository=row["repository"],
                visibility=row["visibility"],
                dep=dep_text,
                code=code_text,
                secret=secret_text,
                stale=row["stale"],
                protected=row["branch_protected"],
                reviews=row["required_reviews"],
                conversation=row["conversation_resolution"],
                force_push=row["allow_force_push"],
                deletions=row["allow_deletions"],
                compliance=compliance,
                risk=row["risk_score"],
            )
        )

    lines.extend(["", "## Top Riscos"])
    top_rows = sorted(rows, key=lambda row: int(row["risk_score"]), reverse=True)[:5]
    for row in top_rows:
        reasons = ", ".join(row["reasons"]) if row["reasons"] else "sem pendencias"
        lines.append(f"- {row['repository']}: risco {row['risk_score']} ({reasons})")

    return "\n".join(lines) + "\n"


def write_reports(prefix: str, owner: str, rows: list[dict[str, Any]], summary: dict[str, int]) -> tuple[str, str, str]:
    json_path = f"{prefix}.json"
    md_path = f"{prefix}.md"
    csv_path = f"{prefix}.csv"

    payload = {
        "owner": owner,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "summary": summary,
        "rows": rows,
    }

    with open(json_path, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)

    with open(md_path, "w", encoding="utf-8") as fp:
        fp.write(render_markdown(owner, rows, summary))

    with open(csv_path, "w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(
            fp,
            fieldnames=[
                "owner",
                "repository",
                "visibility",
                "updated_at",
                "stale",
                "dependabot_open_alerts",
                "code_scanning_open_alerts",
                "secret_scanning_open_alerts",
                "branch_protected",
                "required_reviews",
                "conversation_resolution",
                "allow_force_push",
                "allow_deletions",
                "compliant",
                "risk_score",
                "reasons",
                "recommendations",
            ],
        )
        writer.writeheader()
        for row in rows:
            csv_row = row.copy()
            csv_row["reasons"] = ",".join(row.get("reasons", []))
            csv_row["recommendations"] = " | ".join(row.get("recommendations", []))
            writer.writerow(csv_row)

    return json_path, md_path, csv_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit de seguranca de repositorios GitHub")
    parser.add_argument("--owner", default="Beckerr11", help="Conta/owner do GitHub")
    parser.add_argument("--token-env", default="GITHUB_TOKEN", help="Nome da variavel de ambiente com token da API")
    parser.add_argument("--output-prefix", default="security-report", help="Prefixo dos arquivos de saida")
    parser.add_argument("--min-reviews", type=int, default=1, help="Quantidade minima de aprovacoes esperadas")
    parser.add_argument("--stale-days", type=int, default=180, help="Dias sem atividade para marcar repo como stale")
    parser.add_argument("--fail-on-findings", action="store_true", help="Retorna codigo 2 se houver repos nao compliant")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    token = os.getenv(args.token_env)

    repos = fetch_repos(args.owner, token)
    rows = build_rows(
        args.owner,
        repos,
        token,
        min_reviews=args.min_reviews,
        stale_days=args.stale_days,
    )
    summary = summarize_rows(rows)
    json_path, md_path, csv_path = write_reports(args.output_prefix, args.owner, rows, summary)

    print(f"Repos auditados: {summary['total']}")
    print(f"Compliant: {summary['compliant']} | Nao compliant: {summary['non_compliant']}")
    print(f"JSON: {json_path}")
    print(f"Markdown: {md_path}")
    print(f"CSV: {csv_path}")

    if args.fail_on_findings and summary["non_compliant"] > 0:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
