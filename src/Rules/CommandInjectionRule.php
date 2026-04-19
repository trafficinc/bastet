<?php

declare(strict_types=1);

namespace Bastet\Rules;

use Bastet\Core\Finding;
use Bastet\Core\Rule;
use Bastet\Core\Severity;

/**
 * SEC003 – Command Injection
 *
 * Detects PHP functions that execute shell commands when called with
 * user-controlled or unescaped arguments.
 */
final class CommandInjectionRule extends Rule
{
    public function id(): string   { return 'SEC003'; }
    public function name(): string { return 'Command Injection'; }

    public function analyse(string $filePath, string $source, array $lines): array
    {
        $findings = [];

        // 1. shell_exec / exec / passthru / system / popen with variable args
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/\b(shell_exec|exec|passthru|system|popen|proc_open)\s*\([^)]*\$/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::Critical,
                    title:       'Command execution with variable argument',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'A shell-execution function receives a variable in its argument. If that variable contains user-controlled data the OS command can be manipulated.',
                    remediation: 'Escape all arguments with escapeshellarg(). Prefer Symfony Process or avoid shell calls entirely.',
                    confidence:  0.80,
                );
            },
        ));

        // 2. Backtick operator with variable – must be a standalone PHP expression, not inside a string/array
        //    Require the backtick to appear at the start of an expression context (=, return, echo, (, ,)
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/(?:=|return|echo|print|\(|,)\s*`[^`]*\$[^`]*`/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::Critical,
                    title:       'Backtick shell execution with variable',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'PHP backticks execute the contents as a shell command. Including unescaped variables allows command injection.',
                    remediation: 'Remove backtick usage. Use escapeshellarg() on any inputs, or replace with Symfony Process.',
                    confidence:  0.85,
                );
            },
        ));

        // 3. Artisan::call or Process with user-provided string
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/Artisan\s*::\s*call\s*\([^)]*\$(?!this)/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::Medium,
                    title:       'Dynamic Artisan::call with variable command',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'Artisan::call receives a dynamic command string. An attacker who controls this value can run arbitrary Artisan commands.',
                    remediation: 'Use a whitelist of allowed commands and compare before calling.',
                    confidence:  0.65,
                );
            },
        ));

        return $findings;
    }
}
