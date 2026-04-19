<?php

declare(strict_types=1);

namespace Bastet\Rules;

use Bastet\Core\Finding;
use Bastet\Core\Rule;
use Bastet\Core\Severity;

/**
 * SEC009 – Dangerous PHP Functions
 *
 * Flags use of PHP functions that are inherently risky or frequently
 * abused: eval, unserialize, assert, extract, create_function, etc.
 */
final class DangerousFunctionsRule extends Rule
{
    public function id(): string   { return 'SEC009'; }
    public function name(): string { return 'Dangerous PHP Functions'; }

    private const FUNCTIONS = [
        'eval' => [
            'severity'    => Severity::Critical,
            'explanation' => 'eval() executes arbitrary PHP code. If user-controlled data reaches eval(), remote code execution is trivial.',
            'remediation' => 'Remove eval(). If dynamic behaviour is needed, use a whitelist of known operations or a proper expression evaluator library.',
            'confidence'  => 0.90,
        ],
        'unserialize' => [
            'severity'    => Severity::Critical,
            'explanation' => 'unserialize() on untrusted data enables PHP object injection and can lead to RCE via magic method chains (gadget chains).',
            'remediation' => 'Use JSON (json_decode) instead. If unserialize is necessary, pass an $allowed_classes whitelist and validate the source.',
            'confidence'  => 0.85,
        ],
        'assert' => [
            'severity'    => Severity::High,
            'explanation' => 'assert() with a string argument evaluates PHP code. Deprecated and dangerous – equivalent to eval() in older PHP versions.',
            'remediation' => 'Remove string-form assert() calls. Use proper exceptions for runtime checks.',
            'confidence'  => 0.75,
        ],
        'extract' => [
            'severity'    => Severity::High,
            'explanation' => 'extract() on user-supplied data (e.g., $_GET, $_POST) injects keys as local variables, overwriting existing ones and enabling variable confusion attacks.',
            'remediation' => 'Extract only known keys explicitly. Never call extract() on superglobals.',
            'confidence'  => 0.70,
        ],
        'create_function' => [
            'severity'    => Severity::Critical,
            'explanation' => 'create_function() is removed in PHP 8 and was essentially a wrapper for eval(). Any remaining usage is a code execution risk.',
            'remediation' => 'Replace with anonymous functions (closures).',
            'confidence'  => 0.95,
        ],
        // preg_replace is only dangerous with the /e modifier; handled below via custom pattern

        'base64_decode' => [
            'severity'    => Severity::Low,
            'explanation' => 'base64_decode() is frequently used to obfuscate malicious payloads. Its presence combined with eval/exec warrants review.',
            'remediation' => 'Audit the context. Ensure decoded content is not passed to eval(), exec(), or file operations.',
            'confidence'  => 0.35,
        ],
        'phpinfo' => [
            'severity'    => Severity::Medium,
            'explanation' => 'phpinfo() reveals detailed server configuration. If reachable in production it provides attackers with information for targeted attacks.',
            'remediation' => 'Remove phpinfo() calls from production code. Protect with authentication if needed during debugging.',
            'confidence'  => 0.95,
        ],
        'var_dump' => [
            'severity'    => Severity::Low,
            'explanation' => 'var_dump() left in production code can leak internal data structures, object graphs, and sensitive values to end users.',
            'remediation' => 'Remove var_dump() from production paths. Use structured logging.',
            'confidence'  => 0.85,
        ],
    ];

    public function analyse(string $filePath, string $source, array $lines): array
    {
        $findings = [];

        foreach (self::FUNCTIONS as $fn => $cfg) {
            $pattern = '/\b' . preg_quote($fn, '/') . '\s*\(/';
            $findings = array_merge($findings, $this->matchLines(
                $lines,
                $pattern,
                function (int $lineNo, string $line) use ($filePath, $fn, $cfg): Finding {
                    return $this->finding(
                        severity:    $cfg['severity'],
                        title:       "Use of {$fn}()",
                        file:        $filePath,
                        line:        $lineNo,
                        snippet:     $line,
                        explanation: $cfg['explanation'],
                        remediation: $cfg['remediation'],
                        confidence:  $cfg['confidence'],
                    );
                },
            ));
        }

        // preg_replace with /e modifier only (dangerous; modifier removed in PHP 7 but code may still contain it)
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/\bpreg_replace\s*\(\s*["\'][^"\']*\/e[a-z]*["\']/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::Critical,
                    title:       'preg_replace() with /e modifier',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'The /e modifier caused the replacement string to be evaluated as PHP code. Even if removed in PHP 7+, this pattern indicates historically unsafe code that may have been ported.',
                    remediation: 'Replace with preg_replace_callback() and an explicit callback function.',
                    confidence:  0.95,
                );
            },
        ));

        return $findings;
    }
}
