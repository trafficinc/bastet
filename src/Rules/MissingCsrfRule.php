<?php

declare(strict_types=1);

namespace Bastet\Rules;

use Bastet\Core\Finding;
use Bastet\Core\Rule;
use Bastet\Core\Severity;

/**
 * SEC007 – Missing CSRF Protection
 *
 * Detects routes and form handling that bypass CSRF middleware,
 * and Blade forms missing @csrf.
 */
final class MissingCsrfRule extends Rule
{
    public function id(): string   { return 'SEC007'; }
    public function name(): string { return 'Missing CSRF Protection'; }

    public function extensions(): array { return ['php', 'blade.php']; }

    public function analyse(string $filePath, string $source, array $lines): array
    {
        $findings = [];

        // 1. Routes excluded from CSRF via VerifyCsrfToken $except array
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/\$except\s*=\s*\[/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::Medium,
                    title:       'CSRF exception list in VerifyCsrfToken',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'Routes listed in $except bypass CSRF verification. Wildcard exclusions or sensitive endpoints in this list are a CSRF vulnerability.',
                    remediation: 'Minimise the exclusion list. Webhook routes should validate signatures instead of bypassing CSRF entirely.',
                    confidence:  0.75,
                );
            },
        ));

        // 2. withoutMiddleware('csrf') or skipMiddleware containing csrf
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/withoutMiddleware\s*\([^)]*csrf/i',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::High,
                    title:       'CSRF middleware explicitly disabled on route',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'withoutMiddleware(\'csrf\') removes CSRF protection from this route, exposing state-changing operations to cross-site request forgery.',
                    remediation: 'Remove the CSRF exclusion unless this is a verified webhook. Webhooks should use signature-based authentication instead.',
                    confidence:  0.85,
                );
            },
        ));

        // 3. HTML <form method="post"> in Blade without @csrf on the next few lines
        if (str_ends_with($filePath, '.blade.php') || str_contains($filePath, '.blade.')) {
            foreach ($lines as $i => $line) {
                if (preg_match('/<form\b[^>]*method=["\']?post/i', $line)) {
                    // Check the next 5 lines for @csrf
                    $window = implode("\n", array_slice($lines, $i, 5));
                    if (!str_contains($window, '@csrf')) {
                        $findings[] = $this->finding(
                            severity:    Severity::High,
                            title:       'POST form missing @csrf directive',
                            file:        $filePath,
                            line:        $i + 1,
                            snippet:     $line,
                            explanation: 'A POST form does not include @csrf within the next 5 lines. Laravel\'s CSRF middleware will reject this form unless CSRF is disabled.',
                            remediation: 'Add @csrf as the first field inside the <form> tag.',
                            confidence:  0.80,
                        );
                    }
                }
            }
        }

        // 4. Route::post / Route::put / Route::patch / Route::delete defined without web middleware (in API routes)
        if (str_contains($filePath, 'routes/api')) {
            $findings = array_merge($findings, $this->matchLines(
                $lines,
                '/Route\s*::\s*(post|put|patch|delete)\s*\(/',
                function (int $lineNo, string $line) use ($filePath): Finding {
                    return $this->finding(
                        severity:    Severity::Info,
                        title:       'State-changing API route (no session-based CSRF)',
                        file:        $filePath,
                        line:        $lineNo,
                        snippet:     $line,
                        explanation: 'API routes don\'t use session-based CSRF. Ensure these endpoints are protected by token authentication (Sanctum, JWT, etc.).',
                        remediation: 'Apply auth:sanctum or equivalent middleware to all state-changing API routes.',
                        confidence:  0.60,
                    );
                },
            ));
        }

        return $findings;
    }
}
