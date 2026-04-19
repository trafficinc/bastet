<?php

declare(strict_types=1);

namespace Bastet\Rules;

use Bastet\Core\Finding;
use Bastet\Core\Rule;
use Bastet\Core\Severity;

/**
 * SEC004 – File Inclusion / Path Traversal
 *
 * Flags dynamic include/require calls and file read/write operations
 * that use variables, which may allow directory traversal or remote
 * file inclusion.
 */
final class FileInclusionRule extends Rule
{
    public function id(): string   { return 'SEC004'; }
    public function name(): string { return 'File Inclusion / Path Traversal'; }

    public function analyse(string $filePath, string $source, array $lines): array
    {
        $findings = [];

        // 1. include/require with variable path
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/\b(include|require|include_once|require_once)\s*[(\s][^;]*\$/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::Critical,
                    title:       'Dynamic file inclusion',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'include/require with a variable path allows attackers to load arbitrary files (LFI) or remote URLs (RFI) if allow_url_include is on.',
                    remediation: 'Use a fixed allowlist of includable files. Never build paths from user input. Disable allow_url_include in php.ini.',
                    confidence:  0.80,
                );
            },
        ));

        // 2. file_get_contents / readfile / file with variable containing request data
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/\b(file_get_contents|readfile|file|fopen|file_put_contents)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE|FILES)/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::Critical,
                    title:       'File read/write with superglobal path',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'A file function receives a path that originates directly from a superglobal. This enables path traversal (../../etc/passwd) or arbitrary file disclosure.',
                    remediation: 'Validate and canonicalise paths with realpath(). Ensure the resolved path starts with an allowed base directory.',
                    confidence:  0.90,
                );
            },
        ));

        // 3. "../" or ".." traversal patterns in variables assigned from request
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/\$\w+\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\[/',
            function (int $lineNo, string $line) use ($filePath): ?Finding {
                // Only flag if the same variable feeds a file function (heuristic: narrow context)
                if (!preg_match('/\b(file|fopen|include|require|readfile|Storage)\b/', $line)) {
                    return null;
                }
                return $this->finding(
                    severity:    Severity::High,
                    title:       'User-controlled value used in file operation',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'A superglobal value is assigned and immediately used in a file-related operation, which may allow path traversal.',
                    remediation: 'Sanitise with basename() for filename-only cases or realpath() with base-prefix check for full paths.',
                    confidence:  0.65,
                );
            },
        ));

        // 4. Storage::get / Storage::path with request input
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/Storage\s*::\s*(get|path|url|download|exists)\s*\([^)]*\$request/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::High,
                    title:       'Laravel Storage call with request-derived path',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'Storage:: receives a path value that may originate from request input. Path traversal sequences could escape the storage root.',
                    remediation: 'Validate file references against known identifiers (e.g., a database record). Never allow free-form path strings from users.',
                    confidence:  0.70,
                );
            },
        ));

        return $findings;
    }
}
