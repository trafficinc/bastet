<?php

declare(strict_types=1);

namespace Bastet\Rules;

use Bastet\Core\Finding;
use Bastet\Core\Rule;
use Bastet\Core\Severity;

/**
 * SEC006 – Weak Password / Hash Handling
 *
 * Detects use of broken or weak cryptographic hash functions for passwords,
 * plaintext password comparisons, and insecure random token generation.
 */
final class WeakHashingRule extends Rule
{
    public function id(): string   { return 'SEC006'; }
    public function name(): string { return 'Weak Password / Hash Handling'; }

    public function analyse(string $filePath, string $source, array $lines): array
    {
        $findings = [];

        // 1. md5() or sha1() used on anything that looks like a password
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/\b(md5|sha1)\s*\([^)]*(?:password|passwd|pass|secret|token|key)\b/i',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::Critical,
                    title:       'Weak hash function used on password/secret',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'MD5 and SHA-1 are broken for cryptographic use and trivially reversed via rainbow tables. Using them for passwords is a critical vulnerability.',
                    remediation: 'Use password_hash($password, PASSWORD_BCRYPT) or PASSWORD_ARGON2ID. Verify with password_verify().',
                    confidence:  0.90,
                );
            },
        ));

        // 2. Any bare md5() / sha1() call (lower confidence – may be used for checksums)
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/\b(md5|sha1)\s*\(/',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::Low,
                    title:       'Use of MD5/SHA1',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'MD5 and SHA-1 should not be used for security-sensitive operations. Even if used for non-password purposes, consider whether integrity guarantees are required.',
                    remediation: 'For checksums: hash(\'sha256\', …). For passwords: password_hash(). For tokens: random_bytes() / bin2hex(random_bytes(32)).',
                    confidence:  0.45,
                );
            },
        ));

        // 3. Direct password comparison with == instead of password_verify
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/\b(?:password|passwd|pass)\b[^=]*={1,2}[^=]/',
            function (int $lineNo, string $line) use ($filePath): ?Finding {
                // Narrow to lines that look like comparisons, skip assignments
                if (!preg_match('/[!=]=/', $line)) {
                    return null;
                }
                return $this->finding(
                    severity:    Severity::High,
                    title:       'Possible plaintext password comparison',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'Comparing password variables with == or === may indicate plaintext storage or comparison, which is insecure. Timing attacks are also possible with direct comparison.',
                    remediation: 'Store passwords as bcrypt/argon2 hashes and use password_verify($input, $hash) for comparison.',
                    confidence:  0.55,
                );
            },
        ));

        // 4. rand() / mt_rand() used for token/secret generation
        $findings = array_merge($findings, $this->matchLines(
            $lines,
            '/\b(rand|mt_rand|uniqid)\s*\([^)]*\)[^;]*(?:token|secret|key|nonce|csrf|salt)\b/i',
            function (int $lineNo, string $line) use ($filePath): Finding {
                return $this->finding(
                    severity:    Severity::High,
                    title:       'Cryptographically weak random number generator for security token',
                    file:        $filePath,
                    line:        $lineNo,
                    snippet:     $line,
                    explanation: 'rand(), mt_rand(), and uniqid() are not cryptographically secure and their output can be predicted.',
                    remediation: 'Use random_bytes(32) and encode with bin2hex() or base64_encode(). Laravel: Str::random() uses CSPRNG.',
                    confidence:  0.80,
                );
            },
        ));

        return $findings;
    }
}
