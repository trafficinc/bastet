<?php

declare(strict_types=1);

namespace Bastet\Core;

abstract class Rule
{
    /**
     * Unique rule identifier, e.g. "SEC001".
     */
    abstract public function id(): string;

    /**
     * Human-readable rule name shown in reports.
     */
    abstract public function name(): string;

    /**
     * File extensions this rule applies to.
     * Return empty array to match all files.
     *
     * @return string[]
     */
    public function extensions(): array
    {
        return ['php'];
    }

    /**
     * Analyse a single file and return any findings.
     *
     * @param  string   $filePath  Absolute path to the file.
     * @param  string   $source    Raw file contents.
     * @param  string[] $lines     Source split into lines (1-indexed via array_values + offset).
     * @return Finding[]
     */
    abstract public function analyse(string $filePath, string $source, array $lines): array;

    // -------------------------------------------------------------------------
    // Helpers available to every rule
    // -------------------------------------------------------------------------

    /**
     * Build a Finding with sensible defaults from the rule's own metadata.
     */
    protected function finding(
        Severity $severity,
        string   $title,
        string   $file,
        int      $line,
        string   $snippet,
        string   $explanation,
        string   $remediation,
        float    $confidence = 0.8,
    ): Finding {
        return new Finding(
            severity:    $severity,
            title:       $title,
            file:        $file,
            line:        $line,
            snippet:     trim($snippet),
            explanation: $explanation,
            remediation: $remediation,
            confidence:  $confidence,
            ruleId:      $this->id(),
        );
    }

    /**
     * Scan every line of $lines against a regex and call $callback for each match.
     * $callback receives (lineNumber, lineText, matchData).
     *
     * @param  string[]  $lines
     * @param  string    $pattern
     * @param  callable  $callback
     * @return Finding[]
     */
    protected function matchLines(array $lines, string $pattern, callable $callback): array
    {
        $findings = [];
        foreach ($lines as $i => $line) {
            if (preg_match($pattern, $line, $m)) {
                $result = $callback($i + 1, $line, $m);
                if ($result instanceof Finding) {
                    $findings[] = $result;
                } elseif (is_array($result)) {
                    array_push($findings, ...$result);
                }
            }
        }
        return $findings;
    }

    /**
     * Scan $source with a multiline/global regex and call $callback for each match.
     * $callback receives (lineNumber, matchedText, matchData).
     *
     * @param  callable  $callback
     * @return Finding[]
     */
    protected function matchSource(string $source, string $pattern, callable $callback): array
    {
        $findings = [];
        if (preg_match_all($pattern, $source, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $match) {
                [$text, $offset] = $match;
                $lineNumber = substr_count(substr($source, 0, $offset), "\n") + 1;
                $result = $callback($lineNumber, $text, $matches);
                if ($result instanceof Finding) {
                    $findings[] = $result;
                } elseif (is_array($result)) {
                    array_push($findings, ...$result);
                }
            }
        }
        return $findings;
    }
}
