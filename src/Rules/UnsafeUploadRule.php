<?php

declare(strict_types=1);

namespace Bastet\Rules;

use Bastet\Core\Finding;
use Bastet\Core\Rule;
use Bastet\Core\Severity;

/**
 * SEC005 – Unsafe File Upload Handling
 *
 * Flags file uploads that rely on client-provided MIME type or extension,
 * or that store uploads in a web-accessible directory without validation.
 */
final class UnsafeUploadRule extends Rule
{
    public function id(): string   { return 'SEC005'; }
    public function name(): string { return 'Unsafe File Upload Handling'; }

    public function analyse(string $filePath, string $source, array $lines): array
    {
        $findings = [];

        // 1. Trust client-provided MIME type from $_FILES
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/\$_FILES\s*\[[^\]]*\]\s*\[\s*[\'"]type[\'"]\s*\]/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::High,
                    title:       'Trusting client-supplied MIME type',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: '$_FILES[…][\'type\'] is set by the browser and trivially spoofed. Using it to decide whether a file is safe leads to unrestricted file upload.',
                    remediation: 'Use finfo_open(FILEINFO_MIME_TYPE) on the actual file bytes, or $uploadedFile->getMimeType() in Laravel (which uses server-side detection).',
                    confidence:  0.85,
                );
            },
        ));

        // 2. Moving upload to a path derived from original filename
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/move_uploaded_file\s*\([^,]+,\s*[^)]*\$_(FILES|GET|POST|REQUEST)/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::High,
                    title:       'Upload destination derived from user-controlled data',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'The destination path for move_uploaded_file() contains user-supplied data, allowing path traversal or overwriting sensitive files.',
                    remediation: 'Generate the destination filename server-side (e.g., using uuid). Never use the original filename directly.',
                    confidence:  0.80,
                );
            },
        ));

        // 3. Storing uploads under public/ without extension validation
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/storeAs?\s*\([^)]*[\'"]public[\'"]/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::Medium,
                    title:       'File uploaded to public disk without explicit validation',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'Files stored on the \'public\' disk are web-accessible. Without extension and MIME validation an attacker may upload executable code (e.g., PHP).',
                    remediation: 'Validate extension and server-side MIME type before storing. Consider storing uploads outside the webroot and serving via a controller.',
                    confidence:  0.65,
                );
            },
        ));

        // 4. getClientOriginalName / getClientOriginalExtension used for storage path
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/getClientOriginal(Name|Extension)\s*\(\s*\)/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::Medium,
                    title:       'Client-supplied filename/extension used in storage path',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'getClientOriginalName() and getClientOriginalExtension() return whatever the user\'s browser sent, which can be manipulated.',
                    remediation: 'Use $file->extension() (server-side MIME detection) or generate a random UUID-based filename.',
                    confidence:  0.75,
                );
            },
        ));

        return $findings;
    }
}
