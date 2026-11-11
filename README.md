# PSDKP DevOps Infrastructure

Centralized DevOps infrastructure repository for frontend applications within PSDKP.

## Overview

This repository provides reusable CI/CD workflows, GitHub Actions, security scanning configurations, and deployment automation.

The goal is to standardize development workflows, improve security practices, and reduce duplicated CI/CD configurations across application repositories.

## Repository Structure

```text
devops/
├── .github/
│   └── workflows/
├── actions/
├── configs/
├── scripts/
└── README.md
```

## Components

| Component | Description |
|---|---|
| Reusable CI Workflows | Shared CI pipelines for Node.js and Python applications |
| Security Scanning | Centralized secret scanning, SAST, and SCA |
| Docker Workflow | Reusable Docker build and image publishing |
| Deployment Workflow | Deployment automation through Coolify |
| Shared Configurations | Generic Semgrep, ESLint, and Prettier configurations |

## Security

Security scanning is designed to be reusable across application repositories.

Planned integrations:
- Gitleaks / TruffleHog — Secret Detection
- Semgrep — Static Application Security Testing (SAST)
- Dependency Scanning — Software Composition Analysis (SCA)
- cve.now — Additional dependency vulnerability intelligence

## Repository Guidelines

- Keep reusable workflows generic.
- Keep application-specific configurations in their respective application repositories.
- Store credentials and environment variables in GitHub Actions Secrets.
- Never commit API keys, deployment tokens, passwords, or production credentials.
- Keep production deployment rules and sensitive configurations private.

## Usage

Application repositories can consume reusable workflows from this repository through GitHub Actions.

Detailed usage instructions will be added as each reusable workflow is implemented.

## Status

This repository is under development.
