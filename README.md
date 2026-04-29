# Bastet

Static security scanner for PHP projects.

`Bastet` is a CLI tool for detecting common security vulnerabilities in PHP codebases. It remains usable on generic PHP applications. It ships as a Composer package with a `vendor/bin/bastet` executable.

The scanner now uses an AST-backed taint pipeline for core PHP code paths:

- Parses PHP into a raw AST
- Bastet normalizes that into a smaller security-focused AST
- a flow graph and taint engine track data from sources to sinks
- findings include source, sink, and propagation path metadata when available

## Install

```bash
composer require --dev trafficinc/bastet
```


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

The scanner is now hybrid:

- `src/Analysis/`, `src/Parsing/`, `src/SecurityAst/`, `src/Flow/`, and `src/Taint/` contain the AST and taint analysis engine
- `src/Checkers/` contains sink-specific analyzers for SQL injection, XSS, command injection, and file inclusion/path traversal
- `src/Rules/` still contains regex/config-style checks that are useful outside the AST-backed path
- `src/Core/` and `src/Reporting/` keep the CLI, finding model, orchestration, and output format stable
- `tests/run.php` executes fixture-based regression tests for the AST taint pipeline

Run local Bastet tests with:

```bash
php tests/run.php
```

See [docs/ADDING_RULES.md](docs/ADDING_RULES.md) for the extension workflow.
