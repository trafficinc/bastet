<?php

declare(strict_types=1);

namespace Bastet\Rules;

use Bastet\Core\Finding;
use Bastet\Core\Rule;
use Bastet\Core\Severity;

/**
 * SEC001 – SQL Injection
 *
 * Detects string concatenation or interpolation directly into SQL queries,
 * raw query execution without parameterised bindings, and $request/$_GET/$_POST
 * values used in DB calls.
 */
final class SqlInjectionRule extends Rule
{
    public function id(): string   { return 'SEC001'; }
    public function name(): string { return 'SQL Injection'; }

    private const PATTERNS = [
        // DB::statement / DB::select with concatenation or interpolation
        [
            'pattern'     => '/DB::(statement|select|insert|update|delete|raw)\s*\(\s*["\'].*?[\$\.\s]/',
            'title'       => 'Possible SQL injection via raw DB call',
            'explanation' => 'User-controlled data appears to be concatenated directly into a raw database query string.',
            'remediation' => 'Use parameterised bindings: DB::select(\'SELECT … WHERE id = ?\', [$id]) or Eloquent query builder methods.',
            'severity'    => Severity::Critical,
            'confidence'  => 0.75,
        ],
        // ->where("col = " . $var) or ->where("col = $var") – raw expression as first arg only
        // The safe three-argument form ->where('col', 'op', $val) is NOT flagged here.
        [
            'pattern'     => '/->where\s*\(\s*["\'][^"\']*\$[^"\']*["\']/',
            'title'       => 'Variable interpolated into WHERE clause string',
            'explanation' => 'A string with an embedded $ variable is passed as the WHERE expression, bypassing parameterisation.',
            'remediation' => 'Use the three-argument form: ->where(\'column\', \'=\', $value) which automatically parameterises.',
            'severity'    => Severity::High,
            'confidence'  => 0.80,
        ],
        // $pdo->query($sql) or $pdo->exec($sql) where $sql is built outside
        [
            'pattern'     => '/\$\w+\s*->\s*(query|exec|prepare)\s*\(\s*\$/',
            'title'       => 'PDO query with variable argument',
            'explanation' => 'A PDO query/exec call receives a variable directly. If that variable contains user input the query is injectable.',
            'remediation' => 'Always use $pdo->prepare($sql) with $stmt->execute([$param]) for user-supplied values.',
            'severity'    => Severity::High,
            'confidence'  => 0.65,
        ],
        // $_GET/$_POST/$_REQUEST used directly inside a query string
        [
            'pattern'     => '/["\'][^"\']*\$_(GET|POST|REQUEST|COOKIE)\[/',
            'title'       => 'Superglobal interpolated into SQL string',
            'explanation' => '$_GET/$_POST/$_REQUEST/$_COOKIE is interpolated directly into a string that is likely used as SQL.',
            'remediation' => 'Sanitise or validate input and use parameterised queries.',
            'severity'    => Severity::Critical,
            'confidence'  => 0.90,
        ],
    ];

    public function analyse(string $filePath, string $source, array $lines): array
    {
        $findings = [];
        foreach (self::PATTERNS as $cfg) {
            $findings = array_merge(
                $findings,
                $this->matchLines($lines, $cfg['pattern'], function (int $lineNo, string $lineText) use ($filePath, $cfg): Finding {
                    return $this->finding(
                        severity:    $cfg['severity'],
                        title:       $cfg['title'],
                        file:        $filePath,
                        line:        $lineNo,
                        snippet:     $lineText,
                        explanation: $cfg['explanation'],
                        remediation: $cfg['remediation'],
                        confidence:  $cfg['confidence'],
                    );
                }),
            );
        }
        return $findings;
    }
}
