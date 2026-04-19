# Bastet

Static security scanner for PHP projects.

`Bastet` is a dependency-light CLI tool for detecting common security vulnerabilities in PHP codebases. It is designed to work especially well with [`wayfinder-core`](https://github.com/trafficinc/wayfinder-core) projects, while remaining usable on generic PHP applications. It ships as a Composer package with a `vendor/bin/bastet` executable.

## Install

```bash
composer require --dev trafficinc/bastet
```

[Internal note]

[For local development from the Wayfinder workspace, use a Composer path repository that points at `../bastet`.]

## Usage

```bash
vendor/bin/bastet app
vendor/bin/bastet . --min-severity high
vendor/bin/bastet . --format json --output bastet-report.json
```

## Framework Support

Bastet scans generic PHP code, but some rules include framework-aware heuristics to improve signal for `wayfinder-core` style applications and similar PHP projects.

For example, XSS detection treats explicit HTML escaping such as `htmlspecialchars(...)` and `e(...)` as safe output patterns.

## Options

| Flag | Short | Description |
|---|---|---|
| `--target <path>` | `-t` | Directory or file to scan |
| `--format <fmt>` | `-f` | `console` or `json` |
| `--output <file>` | `-o` | Write report to file instead of stdout |
| `--min-severity <s>` | `-s` | Minimum severity: `critical` `high` `medium` `low` `info` |
| `--exclude <pattern>` | `-e` | Exclude paths matching pattern |
| `--no-color` | | Disable ANSI color output |
| `--list-rules` | | Print all rule IDs and exit |
| `--help` | `-h` | Print help and exit |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at High severity or above |
| `1` | One or more High or Critical findings |
| `2` | Invalid arguments or target not found |

## Development

Rules live under `src/Rules/`, shared scanner primitives live under `src/Core/`, and reporters live under `src/Reporting/`.

See [docs/ADDING_RULES.md](docs/ADDING_RULES.md) for the extension workflow.
