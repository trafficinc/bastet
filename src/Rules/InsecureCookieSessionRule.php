<?php

declare(strict_types=1);

namespace Bastet\Rules;

use Bastet\Core\Finding;
use Bastet\Core\Rule;
use Bastet\Core\Severity;

/**
 * SEC010 – Insecure Cookie / Session Settings
 *
 * Detects misconfigured session and cookie options that weaken transport
 * security, enable JavaScript access to session cookies, or allow
 * cross-site cookie leakage.
 */
final class InsecureCookieSessionRule extends Rule
{
    public function id(): string   { return 'SEC010'; }
    public function name(): string { return 'Insecure Cookie / Session Settings'; }

    public function analyse(string $filePath, string $source, array $lines): array
    {
        $findings = [];

        // 1. setcookie() without HttpOnly or Secure flags
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/\bsetcookie\s*\(/',
            function (int $lineNo, string $line) use ($filePath, $lines): array {
                $inner = [];
                // Collect up to 3 lines for multi-line calls
                $call = implode(' ', array_slice($lines, $lineNo - 1, 3));

                if (!preg_match('/true\s*,\s*true/', $call) && !str_contains($call, 'httponly') && !str_contains(strtolower($call), 'options')) {
                    $inner[] = $this->finding(
                        severity:    Severity::High,
                        title:       'setcookie() without HttpOnly flag',
                        file:        $filePath,
                        line:        $lineNo,
                        snippet:     $line,
                        explanation: 'Cookies without the HttpOnly flag are accessible via JavaScript, enabling session hijacking through XSS.',
                        remediation: 'Pass an options array: setcookie($name, $value, [\'httponly\' => true, \'secure\' => true, \'samesite\' => \'Lax\']).',
                        confidence:  0.65,
                    );
                }
                return $inner;
            },
        ));

        // 2. session.cookie_secure = 0 / false in ini_set
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/ini_set\s*\(\s*["\']session\.cookie_(secure|httponly|samesite)["\']/',
            function (int $lineNo, string $line) use ($filePath): ?Finding {
                if (preg_match('/["\']0["\']\s*\)|false\s*\)/', $line)) {
                    return $this->finding(
                        severity:    Severity::High,
                        title:       'Session cookie security flag disabled via ini_set',
                        file:        $filePath,
                        line:        $lineNo,
                        snippet:     $line,
                        explanation: 'Explicitly setting session.cookie_secure or session.cookie_httponly to 0/false disables important session protection.',
                        remediation: 'Set session.cookie_secure=1, session.cookie_httponly=1, session.cookie_samesite=Lax in php.ini or via ini_set with true.',
                        confidence:  0.90,
                    );
                }
                return null;
            },
        ));

        // 3. Laravel config: session.php with secure => false or http_only => false
        if (str_contains($filePath, 'config/session')) {
            $findings = array_merge($findings, $this->matchLines(
                $lines,
                "/'(secure|http_only)'\s*=>\s*(false|0)/",
                function (int $lineNo, string $line) use ($filePath): Finding {
                    return $this->finding(
                        severity:    Severity::High,
                        title:       'Laravel session config: secure/http_only disabled',
                        file:        $filePath,
                        line:        $lineNo,
                        snippet:     $line,
                        explanation: 'The session cookie is not marked secure or HttpOnly, allowing interception over HTTP or access via JavaScript.',
                        remediation: "Set 'secure' => env('SESSION_SECURE_COOKIE', true) and 'http_only' => true in config/session.php.",
                        confidence:  0.85,
                    );
                },
            ));

            // SameSite = None without Secure
            $findings = array_merge($findings, $this->matchLines(
                $lines,
                "/'same_site'\s*=>\s*'[Nn]one'/",
                function (int $lineNo, string $line) use ($filePath): Finding {
                    return $this->finding(
                        severity:    Severity::Medium,
                        title:       'Session SameSite=None without Secure requirement',
                        file:        $filePath,
                        line:        $lineNo,
                        snippet:     $line,
                        explanation: "SameSite=None allows cross-site cookies. Browsers require the Secure flag to be set when SameSite=None is used.",
                        remediation: "Pair 'same_site' => 'None' with 'secure' => true, or use 'Lax' which is safer for most applications.",
                        confidence:  0.75,
                    );
                },
            ));
        }

        // 4. session_start() called without security options
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/\bsession_start\s*\(\s*\)/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::Low,
                    title:       'session_start() called without explicit security options',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'session_start() with no options uses php.ini defaults. If defaults are insecure (no secure/httponly flags), session cookies are exposed.',
                    remediation: "Call session_start(['cookie_secure' => 1, 'cookie_httponly' => 1, 'cookie_samesite' => 'Lax']) or set these in php.ini.",
                    confidence:  0.50,
                );
            },
        ));

        return $findings;
    }
}
