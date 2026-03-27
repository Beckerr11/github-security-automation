#!/usr/bin/env python3
from __future__ import annotations

import argparse
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
        }
        for repo in repos
        if not repo.get("archived") and not repo.get("fork")
    ]


def fetch_dependabot_alerts_count(full_name: str, token: str | None) -> int | None:
    if not token:
        return None

    url = f"{API_BASE}/repos/{full_name}/dependabot/alerts?state=open&per_page=1"
    response = requests.get(url, headers=build_headers(token), timeout=30)
    if response.status_code in (403, 404):
        return None
    response.raise_for_status()
    return len(response.json())


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


def build_rows(owner: str, repos: list[dict[str, Any]], token: str | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for repo in repos:
        dep_count = fetch_dependabot_alerts_count(repo["full_name"], token)
        protection = fetch_branch_protection(repo["full_name"], repo["default_branch"], token)

        rows.append(
            {
                "owner": owner,
                "repository": repo["name"],
                "visibility": "private" if repo["private"] else "public",
                "dependabot_open_alerts": dep_count,
                "branch_protected": protection.get("protected"),
                "required_reviews": protection.get("required_reviews"),
                "conversation_resolution": protection.get("conversation_resolution"),
                "allow_force_push": protection.get("allow_force_push"),
                "allow_deletions": protection.get("allow_deletions"),
            }
        )

    return rows


def render_markdown(owner: str, rows: list[dict[str, Any]]) -> str:
    generated_at = dt.datetime.now(dt.timezone.utc).isoformat()
    lines = [
        f"# GitHub Security Audit - {owner}",
        "",
        f"Gerado em: {generated_at}",
        "",
        "| Repository | Visibility | Dependabot Open | Protected | Reviews | Conversation | Force Push | Delete |",
        "|---|---|---:|---|---:|---|---|---|",
    ]

    for row in rows:
        dep = row["dependabot_open_alerts"]
        dep_text = str(dep) if dep is not None else "n/a"
        lines.append(
            "| {repository} | {visibility} | {dep} | {protected} | {reviews} | {conversation} | {force_push} | {deletions} |".format(
                repository=row["repository"],
                visibility=row["visibility"],
                dep=dep_text,
                protected=row["branch_protected"],
                reviews=row["required_reviews"],
                conversation=row["conversation_resolution"],
                force_push=row["allow_force_push"],
                deletions=row["allow_deletions"],
            )
        )

    return "\n".join(lines) + "\n"


def write_reports(prefix: str, owner: str, rows: list[dict[str, Any]]) -> tuple[str, str]:
    json_path = f"{prefix}.json"
    md_path = f"{prefix}.md"

    payload = {
        "owner": owner,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "rows": rows,
    }

    with open(json_path, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)

    with open(md_path, "w", encoding="utf-8") as fp:
        fp.write(render_markdown(owner, rows))

    return json_path, md_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit de seguranca de repositorios GitHub")
    parser.add_argument("--owner", default="Beckerr11", help="Conta/owner do GitHub")
    parser.add_argument("--token-env", default="GITHUB_TOKEN", help="Nome da variavel de ambiente com token da API")
    parser.add_argument("--output-prefix", default="security-report", help="Prefixo do arquivo de saida")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    token = os.getenv(args.token_env)

    repos = fetch_repos(args.owner, token)
    rows = build_rows(args.owner, repos, token)
    json_path, md_path = write_reports(args.output_prefix, args.owner, rows)

    print(f"Repos auditados: {len(rows)}")
    print(f"JSON: {json_path}")
    print(f"Markdown: {md_path}")


if __name__ == "__main__":
    main()