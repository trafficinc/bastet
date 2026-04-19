<?php

declare(strict_types=1);

namespace Bastet\Rules;

use Bastet\Core\Finding;
use Bastet\Core\Rule;
use Bastet\Core\Severity;

/**
 * SEC011 – Authorization / Access-Control Smells
 *
 * Detects missing authorization checks, insecure direct object references,
 * role checks based on user-supplied data, and bypassed policies.
 */
final class AccessControlSmellsRule extends Rule
{
    public function id(): string   { return 'SEC011'; }
    public function name(): string { return 'Authorization / Access-Control Smells'; }

    public function analyse(string $filePath, string $source, array $lines): array
    {
        $findings = [];

        // 1. Controller methods that never call authorize(), $this->authorize(), Gate::, or can()
        if (str_contains($filePath, 'Controller')) {
            $this->scanControllerForMissingAuth($filePath, $source, $lines, $findings);
        }

        // 2. Direct model lookup by user-supplied ID without ownership check (IDOR smell)
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/::find(OrFail)?\s*\(\s*\$(?:request|_GET|_POST|_REQUEST|id)\b/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::High,
                    title:       'Potential IDOR: model lookup by user-supplied ID',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'A model is fetched directly using an ID from request data without a visible ownership constraint. An attacker can enumerate IDs to access other users\' records.',
                    remediation: 'Scope the query to the authenticated user: Auth::user()->records()->findOrFail($id). Use route model binding with policies.',
                    confidence:  0.70,
                );
            },
        ));

        // 3. Role checks comparing against a string from request input
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/hasRole\s*\([^)]*\$_(GET|POST|REQUEST)\[/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::Critical,
                    title:       'Role check using request-supplied role name',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'hasRole() is called with a value from a superglobal. An attacker submitting "admin" would pass this check.',
                    remediation: 'Hard-code role names in application logic. Never determine which role to check based on user-supplied data.',
                    confidence:  0.95,
                );
            },
        ));

        // 4. Disabled policy with ->withoutAuthorization() or Gate::before returning true for all
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/Gate\s*::\s*before\s*\([^)]*return\s+true/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::Critical,
                    title:       'Gate::before() grants all permissions unconditionally',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'A Gate::before() callback returning true unconditionally bypasses all authorization checks in the application.',
                    remediation: 'Limit the Gate::before() bypass to a specific super-admin role: return $user->isAdmin() ? true : null;',
                    confidence:  0.85,
                );
            },
        ));

        // 5. Auth::loginUsingId() with request data
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/Auth\s*::\s*loginUsingId\s*\([^)]*\$(?:request|_GET|_POST)/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::Critical,
                    title:       'Forced login with user-supplied ID',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'Auth::loginUsingId() is called with a value from request data, allowing an attacker to authenticate as any user by supplying their ID.',
                    remediation: 'Never allow users to choose which account to log in as. Authenticate via credentials only.',
                    confidence:  0.90,
                );
            },
        ));

        // 6. $user->is_admin or ->role checked from request, not from DB
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/\$_(GET|POST|REQUEST)\[[^\]]*(?:admin|role|permission)[^\]]*\]/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::High,
                    title:       'Authorization attribute read from request input',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'An authorization-related field (admin, role, permission) is being read from user-submitted input rather than from the database.',
                    remediation: 'Load role/permission data exclusively from the authenticated user\'s DB record: Auth::user()->role.',
                    confidence:  0.80,
                );
            },
        ));

        return $findings;
    }

    /** @param Finding[] $findings */
    private function scanControllerForMissingAuth(
        string $filePath,
        string $source,
        array  $lines,
        array  &$findings,
    ): void {
        // Split into public methods and check each for auth patterns
        $authSignals = [
            'authorize', 'Gate::', '->can(', 'abort_if', 'abort_unless',
            'middleware', 'policy', 'allowedTo', 'hasPermission',
        ];

        // Simple approach: find public function declarations
        $methodPattern = '/public\s+function\s+(\w+)\s*\(/';
        $skipNames     = ['__construct', '__invoke', 'middleware', 'callAction', 'getMiddleware'];

        preg_match_all($methodPattern, $source, $methodMatches, PREG_OFFSET_CAPTURE);

        foreach ($methodMatches[0] as $idx => $match) {
            [$matchText, $offset] = $match;
            $methodName = $methodMatches[1][$idx][0];

            if (in_array($methodName, $skipNames, true)) {
                continue;
            }

            // Find the method body (from the match to the next public function or EOF)
            $nextOffset = $methodMatches[0][$idx + 1][1] ?? strlen($source);
            $body       = substr($source, $offset, $nextOffset - $offset);

            // Skip if any auth signal is found in the body
            foreach ($authSignals as $signal) {
                if (str_contains($body, $signal)) {
                    continue 2;
                }
            }

            // Skip if method doesn't touch the DB (low signal)
            if (!preg_match('/\b(find|where|first|get|all|create|update|delete|save)\b/', $body)) {
                continue;
            }

            $lineNo = substr_count(substr($source, 0, $offset), "\n") + 1;
            $findings[] = $this->finding(
                severity:    Severity::Medium,
                title:       "Controller method '{$methodName}' may lack authorization",
                file:        $filePath,
                line:        $lineNo,
                snippet:     trim($matchText),
                explanation: "The method '{$methodName}' performs database operations but no authorization check (authorize(), Gate::, ->can(), abort_if) was detected.",
                remediation: "Add \$this->authorize('action', Model::class) or a Gate check at the start of the method, or apply a policy via middleware.",
                confidence:  0.55,
            );
        }
    }
}
