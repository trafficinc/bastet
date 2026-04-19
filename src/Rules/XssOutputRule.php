<?php

declare(strict_types=1);

namespace Bastet\Rules;

use Bastet\Core\Finding;
use Bastet\Core\Rule;
use Bastet\Core\Severity;

/**
 * SEC002 – Cross-Site Scripting (XSS)
 *
 * Detects unescaped output of user-controlled data in PHP files and
 * Blade templates that use {!! !!} (unescaped) instead of {{ }}.
 */
final class XssOutputRule extends Rule
{
    public function id(): string   { return 'SEC002'; }
    public function name(): string { return 'Cross-Site Scripting (XSS)'; }

    public function extensions(): array { return ['php', 'blade.php']; }

    public function analyse(string $filePath, string $source, array $lines): array
    {
        $findings = [];

        // 1. Blade unescaped output {!! $var !!} – always flag
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/\{!!\s*\$/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                if ($this->hasExplicitHtmlEscape($line)) {
                    return null;
                }

                return $this->finding(
                    severity:    Severity::High,
                    title:       'Unescaped Blade output',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: '{!! !!} renders raw HTML without escaping. If the value contains user input this is an XSS vector.',
                    remediation: 'Use {{ $var }} which auto-escapes via htmlspecialchars(), or explicitly escape with e($var) before using {!! !!}.',
                    confidence:  0.80,
                );
            },
        ));

        // 2. echo/print of $_GET/$_POST/$_REQUEST/$_COOKIE without escaping
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/\b(echo|print)\b[^;]*\$_(GET|POST|REQUEST|COOKIE)\[/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                if ($this->hasExplicitHtmlEscape($line)) {
                    return null;
                }

                return $this->finding(
                    severity:    Severity::Critical,
                    title:       'Superglobal echoed without escaping',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'User-supplied data from a superglobal is echoed directly to the browser without HTML-encoding.',
                    remediation: 'Wrap the value: echo htmlspecialchars($val, ENT_QUOTES, \'UTF-8\');',
                    confidence:  0.95,
                );
            },
        ));

        // 3. echo/print of $request->input() / $request->get() without escaping
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/\b(echo|print)\b[^;]*\$request\s*->\s*(input|get|query|post|all)\s*\(/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                if ($this->hasExplicitHtmlEscape($line)) {
                    return null;
                }

                return $this->finding(
                    severity:    Severity::High,
                    title:       'Request input echoed without escaping',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'Data from $request is echoed without HTML-encoding, which may cause XSS if the value originates from user input.',
                    remediation: 'Use e($request->input(\'key\')) or pass the data through a Blade template with {{ }}.',
                    confidence:  0.75,
                );
            },
        ));

        // 4. header("Location: " . $var) – open redirect / header injection
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/header\s*\(\s*["\']Location:\s*["\']\.?\s*\$/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::Medium,
                    title:       'Header injection / open redirect via variable',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'A variable is concatenated into a Location header. Attacker-controlled newlines can inject arbitrary HTTP headers; unchecked URLs enable open redirect.',
                    remediation: 'Validate redirect URLs against an allowlist. Strip newlines: $url = str_replace(["\\r","\\n"], \'\', $url);',
                    confidence:  0.70,
                );
            },
        ));

        return $findings;
    }

    private function hasExplicitHtmlEscape(string $line): bool
    {
        return preg_match('/\b(?:e|htmlspecialchars)\s*\(/', $line) === 1;
    }
}
