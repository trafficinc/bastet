<?php

declare(strict_types=1);

namespace Bastet\Rules;

use Bastet\Core\Finding;
use Bastet\Core\Rule;
use Bastet\Core\Severity;

/**
 * SEC012 – Insecure Configuration / Debug / Public Exposure
 *
 * Detects debug mode left on, error display enabled in production,
 * missing security headers, exposed .env files, and insecure defaults
 * in config files.
 */
final class InsecureConfigRule extends Rule
{
    public function id(): string   { return 'SEC012'; }
    public function name(): string { return 'Insecure Config / Debug / Public Exposure'; }

    public function extensions(): array
    {
        return ['php', 'env', 'ini', 'htaccess', 'xml', 'yaml', 'yml', 'json'];
    }

    public function analyse(string $filePath, string $source, array $lines): array
    {
        $findings = [];

        // ------------------------------------------------------------------ //
        // .env files
        // ------------------------------------------------------------------ //
        if (basename($filePath) === '.env') {
            // APP_DEBUG=true in production .env
            $findings = array_merge($findings, $this->matchLines(
                $lines,
                '/^APP_DEBUG\s*=\s*true\s*$/i',
                function (int $lineNo, string $line) use ($filePath): Finding {
                    return $this->finding(
                        severity:    Severity::High,
                        title:       'APP_DEBUG=true in .env',
                        file:        $filePath,
                        line:        $lineNo,
                        snippet:     $line,
                        explanation: 'Debug mode exposes stack traces, environment variables, and application internals to anyone who triggers an error.',
                        remediation: 'Set APP_DEBUG=false in production. Use APP_ENV=production.',
                        confidence:  0.95,
                    );
                },
            ));

            // APP_ENV=production with APP_DEBUG=true already caught above; also catch APP_ENV=local
            $findings = array_merge($findings, $this->matchLines(
                $lines,
                '/^APP_ENV\s*=\s*(local|development)\s*$/i',
                function (int $lineNo, string $line) use ($filePath): Finding {
                    return $this->finding(
                        severity:    Severity::Info,
                        title:       'Non-production APP_ENV in .env',
                        file:        $filePath,
                        line:        $lineNo,
                        snippet:     $line,
                        explanation: 'The application environment is set to a non-production value. If this file is deployed, certain security defaults (e.g., error pages) will not apply.',
                        remediation: 'Set APP_ENV=production for deployed environments.',
                        confidence:  0.70,
                    );
                },
            ));

            // Weak APP_KEY
            $findings = array_merge($findings, $this->matchLines(
                $lines,
                '/^APP_KEY\s*=\s*$/i',
                function (int $lineNo, string $line) use ($filePath): Finding {
                    return $this->finding(
                        severity:    Severity::Critical,
                        title:       'Empty APP_KEY',
                        file:        $filePath,
                        line:        $lineNo,
                        snippet:     $line,
                        explanation: 'An empty APP_KEY disables encryption of sessions, cookies, and encrypted model attributes, making them trivially forgeable.',
                        remediation: 'Run php artisan key:generate to generate a secure application key.',
                        confidence:  0.99,
                    );
                },
            ));
        }

        // ------------------------------------------------------------------ //
        // PHP config / ini_set calls
        // ------------------------------------------------------------------ //
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/ini_set\s*\(\s*["\']display_errors["\']\s*,\s*["\']?1["\']?\s*\)/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::High,
                    title:       'display_errors enabled via ini_set',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'display_errors=1 outputs PHP errors to the browser, leaking file paths, variable values, and stack traces in production.',
                    remediation: 'Use ini_set(\'display_errors\', \'0\') and ini_set(\'log_errors\', \'1\') in production. Output errors only to logs.',
                    confidence:  0.90,
                );
            },
        ));

        // ------------------------------------------------------------------ //
        // Laravel config/app.php
        // ------------------------------------------------------------------ //
        if (str_contains($filePath, 'config/app')) {
            $findings = array_merge($findings, $this->matchLines(
                $lines,
                "/'debug'\s*=>\s*(true|env\s*\(\s*'APP_DEBUG'\s*,\s*true\s*\))/",
                function (int $lineNo, string $line) use ($filePath): Finding {
                    return $this->finding(
                        severity:    Severity::High,
                        title:       'Debug mode defaulting to true in config/app.php',
                        file:        $filePath,
                        line:        $lineNo,
                        snippet:     $line,
                        explanation: "The debug default is true. If APP_DEBUG is not set in .env the application will run in debug mode.",
                        remediation: "Change to: 'debug' => env('APP_DEBUG', false).",
                        confidence:  0.85,
                    );
                },
            ));
        }

        // ------------------------------------------------------------------ //
        // Telescope / Debugbar in non-local environments
        // ------------------------------------------------------------------ //
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/TelescopeServiceProvider|DebugbarServiceProvider/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::Medium,
                    title:       'Debug service provider registered',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'Telescope and Debugbar expose request data, queries, logs, and jobs. They must be gated to local/dev environments only.',
                    remediation: "Wrap in: if (\$this->app->environment('local')) { ... } or use the 'enabled' config key driven by env().",
                    confidence:  0.65,
                );
            },
        ));

        // ------------------------------------------------------------------ //
        // Exposed .env checks in public-facing files
        // ------------------------------------------------------------------ //
        if (str_contains($filePath, '/public/')) {
            $findings = array_merge($findings, $this->matchLines(
                $lines,
                '/env\s*\(|getenv\s*\(/',
                function (int $lineNo, string $line) use ($filePath): Finding {
                    return $this->finding(
                        severity:    Severity::High,
                        title:       'env() called from a public-facing file',
                        file:        $filePath,
                        line:        $lineNo,
                        snippet:     $line,
                        explanation: 'Calling env() directly from a file in public/ may expose configuration values if the file is accessed directly or errors are shown.',
                        remediation: 'Move env() calls into config files. Access config values via config(\'app.key\') from application code.',
                        confidence:  0.70,
                    );
                },
            ));
        }

        // ------------------------------------------------------------------ //
        // Database config with hardcoded credentials
        // ------------------------------------------------------------------ //
        if (str_contains($filePath, 'config/database')) {
            $findings = array_merge($findings, $this->matchLines(
                $lines,
                "/'(username|password)'\s*=>\s*'[^']+'/",
                function (int $lineNo, string $line) use ($filePath): ?Finding {
                    if (str_contains($line, 'env(')) {
                        return null;
                    }
                    return $this->finding(
                        severity:    Severity::Critical,
                        title:       'Hardcoded database credential in config/database.php',
                        file:        $filePath,
                        line:        $lineNo,
                        snippet:     $line,
                        explanation: 'A database username or password is hardcoded as a string literal. Anyone with repository access has your database credentials.',
                        remediation: "Use env('DB_USERNAME') and env('DB_PASSWORD') and store values in .env (not committed to VCS).",
                        confidence:  0.90,
                    );
                },
            ));
        }

        return $findings;
    }
}
