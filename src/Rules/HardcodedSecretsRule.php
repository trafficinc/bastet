<?php

declare(strict_types=1);

namespace Bastet\Rules;

use Bastet\Core\Finding;
use Bastet\Core\Rule;
use Bastet\Core\Severity;

/**
 * SEC008 – Hardcoded Secrets
 *
 * Detects API keys, passwords, tokens, and other secrets assigned as
 * string literals in source code.
 */
final class HardcodedSecretsRule extends Rule
{
    public function id(): string   { return 'SEC008'; }
    public function name(): string { return 'Hardcoded Secrets'; }

    public function extensions(): array { return ['php', 'env', 'json', 'yaml', 'yml', 'xml', 'ini']; }

    // Keyword patterns that strongly suggest a secret assignment
    private const KEY_PATTERNS = [
        'password', 'passwd', 'secret', 'api_key', 'apikey', 'auth_token',
        'access_token', 'private_key', 'client_secret', 'stripe_key',
        'aws_secret', 'smtp_pass', 'db_password', 'database_password',
    ];

    // Value entropy heuristics – looks like a random token
    private const TOKEN_REGEX = '/[=:]\s*["\']([A-Za-z0-9+\/\-_]{20,})["\'](?!\s*\.\s*env)/';

    // Known placeholder values that are false positives
    private const PLACEHOLDERS = [
        'your-secret', 'changeme', 'xxxxxxxx', 'replace-me', 'todo',
        'example', 'secret', 'password', 'null', 'none', '', 'true', 'false',
    ];

    public function analyse(string $filePath, string $source, array $lines): array
    {
        $findings = [];

        // Skip .env.example and test fixtures
        $base = basename($filePath);
        if (str_contains($base, '.example') || str_contains($filePath, '/tests/')) {
            return [];
        }

        $keyPattern = implode('|', self::KEY_PATTERNS);

        // 1. Assignment to a secret-named variable/key with a non-empty literal
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/(?:' . $keyPattern . ')\s*[=:>]+\s*["\'][^"\']{6,}["\']/i',
            function (int $lineNo, string $line) use ($filePath): ?Finding {
                // Skip env() / config() lookups – they're fine
                if (preg_match('/env\s*\(|config\s*\(/', $line)) {
                    return null;
                }
                // Extract the value for placeholder check
                if (preg_match('/[=:>]+\s*["\']([^"\']+)["\']/', $line, $m)) {
                    $value = strtolower(trim($m[1]));
                    foreach (self::PLACEHOLDERS as $placeholder) {
                        if ($value === $placeholder || str_starts_with($value, 'your')) {
                            return null;
                        }
                    }
                }
                return $this->finding(
                    severity:    Severity::Critical,
                    title:       'Hardcoded secret / credential',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $this->redactSecret($line),
                    explanation: 'A variable or key whose name suggests a secret is assigned a string literal directly in source code. Committing secrets to VCS is a critical exposure risk.',
                    remediation: 'Move the value to a .env file and read it with env(\'KEY\'). Rotate the secret immediately if already committed.',
                    confidence:  0.80,
                );
            },
        ));

        // 2. High-entropy token-like strings in any file (catch generic tokens)
        if (!str_ends_with($filePath, '.env')) {
            $findings = array_merge($findings, $this->matchLines(
                $lines,
                self::TOKEN_REGEX,
                function (int $lineNo, string $line, array $m) use ($filePath): ?Finding {
                    $token = $m[1][0] ?? '';
                    if ($this->isLowEntropy($token) || strlen($token) < 24) {
                        return null;
                    }
                    return $this->finding(
                        severity:    Severity::High,
                        title:       'High-entropy string literal (possible secret)',
                        file:        $filePath,
                        line:        $lineNo,
                        snippet:     $this->redactSecret($line),
                        explanation: 'A string literal with characteristics of a secret token or key was found. Secrets should not be embedded in source files.',
                        remediation: 'Move to .env / secrets manager. Use env(\'KEY\') to retrieve at runtime.',
                        confidence:  0.60,
                    );
                },
            ));
        }

        return $findings;
    }

    private function isLowEntropy(string $s): bool
    {
        // Simple heuristic: if > 40% of chars are the same it's probably not a token
        $len = strlen($s);
        if ($len === 0) {
            return true;
        }
        $counts = array_count_values(str_split($s));
        return (max($counts) / $len) > 0.4;
    }

    private function redactSecret(string $line): string
    {
        // Replace the literal value with [REDACTED] in snippets to avoid leaking in reports
        return preg_replace(
            '/([=:>]+\s*["\'])([^"\']{4})([^"\']+)(["\'])/',
            '$1$2[REDACTED]$4',
            $line,
        ) ?? $line;
    }
}
