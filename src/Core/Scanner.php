<?php

declare(strict_types=1);

namespace Bastet\Core;

use Bastet\Analysis\ProjectAnalyzer;
use Bastet\Checkers\CommandInjectionChecker;
use Bastet\Checkers\FileInclusionChecker;
use Bastet\Checkers\SqlInjectionChecker;
use Bastet\Checkers\XssChecker;

final class Scanner
{
    /** @var Rule[] */
    private array $rules = [];

    /** @var string[] */
    private array $exclusions = [];

    private Severity $minimumSeverity;

    private ProjectAnalyzer $projectAnalyzer;

    public function __construct(Severity $minimumSeverity = Severity::Info)
    {
        $this->minimumSeverity = $minimumSeverity;
        $this->projectAnalyzer = new ProjectAnalyzer();
    }

    public function addRule(Rule $rule): void
    {
        $this->rules[] = $rule;
    }

    /** @param string[] $patterns Glob-style path patterns to exclude */
    public function setExclusions(array $patterns): void
    {
        $this->exclusions = $patterns;
    }

    /**
     * Scan a target path (file or directory) and return all findings.
     *
     * @return Finding[]
     */
    public function scan(string $targetPath): array
    {
        return $this->scanTargets([$targetPath]);
    }

    /**
     * Scan multiple target paths and return all findings.
     *
     * @param list<string> $targetPaths
     * @return Finding[]
     */
    public function scanTargets(array $targetPaths): array
    {
        $files = [];

        foreach ($targetPaths as $targetPath) {
            $files = array_merge($files, $this->collectFiles($targetPath));
        }

        $files = array_values(array_unique($files));
        $findings = [];

        foreach ($files as $file) {
            $source = file_get_contents($file);
            if ($source === false) {
                continue;
            }
            $lines = explode("\n", $source);
            $fileFindings = [];
            $isPhpFile = strtolower(pathinfo($file, PATHINFO_EXTENSION)) === 'php';
            $isBladeTemplate = str_ends_with($file, '.blade.php');
            $astBacked = $isPhpFile && ! $isBladeTemplate && $this->projectAnalyzer->isAvailable();

            if ($astBacked) {
                $fileFindings = array_merge($fileFindings, $this->runAstAnalysis($file, $source));
            }

            foreach ($this->rules as $rule) {
                $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
                $allowed = $rule->extensions();
                if (!empty($allowed) && !in_array($ext, $allowed, true)) {
                    continue;
                }

                if ($astBacked && in_array($rule->id(), ['SEC001', 'SEC002', 'SEC003', 'SEC004'], true)) {
                    continue;
                }

                $ruleFindings = $rule->analyse($file, $source, $lines);

                foreach ($ruleFindings as $finding) {
                    if ($finding->severity->weight() >= $this->minimumSeverity->weight()) {
                        $fileFindings[] = $finding;
                    }
                }
            }

            $findings = array_merge($findings, $this->withoutSuppressedFindings($fileFindings, $lines));
        }

        // Sort: most severe first, then by file + line.
        usort($findings, static function (Finding $a, Finding $b): int {
            $cmp = $b->severity->weight() <=> $a->severity->weight();
            if ($cmp !== 0) {
                return $cmp;
            }
            $cmp = strcmp($a->file, $b->file);
            if ($cmp !== 0) {
                return $cmp;
            }
            return $a->line <=> $b->line;
        });

        return $findings;
    }

    /**
     * @param Finding[] $findings
     * @param string[] $lines
     * @return Finding[]
     */
    private function withoutSuppressedFindings(array $findings, array $lines): array
    {
        if ($findings === []) {
            return [];
        }

        return array_values(array_filter(
            $findings,
            fn (Finding $finding): bool => ! $this->isSuppressed($finding, $lines),
        ));
    }

    /**
     * Supports:
     * - bastet-ignore-file SEC009
     * - bastet-ignore-next-line SEC009
     * - bastet-ignore-line SEC009
     *
     * Use "all" instead of a rule id only for intentional broad suppressions.
     *
     * @param string[] $lines
     */
    private function isSuppressed(Finding $finding, array $lines): bool
    {
        foreach ($lines as $line) {
            if ($this->lineSuppressesRule($line, 'file', $finding->ruleId)) {
                return true;
            }
        }

        $lineIndex = $finding->line - 1;

        if (isset($lines[$lineIndex]) && $this->lineSuppressesRule($lines[$lineIndex], 'line', $finding->ruleId)) {
            return true;
        }

        $previousLineIndex = $lineIndex - 1;

        return isset($lines[$previousLineIndex])
            && $this->lineSuppressesRule($lines[$previousLineIndex], 'next-line', $finding->ruleId);
    }

    private function lineSuppressesRule(string $line, string $scope, string $ruleId): bool
    {
        if (! preg_match('/\bbastet-ignore-' . preg_quote($scope, '/') . '\b(?P<rest>[^\r\n]*)/i', $line, $match)) {
            return false;
        }

        $ruleList = trim(explode('--', (string) $match['rest'], 2)[0]);

        if ($ruleList === '') {
            return false;
        }

        $rules = preg_split('/[\s,]+/', $ruleList, -1, PREG_SPLIT_NO_EMPTY);

        if ($rules === false || $rules === []) {
            return false;
        }

        foreach ($rules as $rule) {
            if (strcasecmp($rule, 'all') === 0 || strcasecmp($rule, $ruleId) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return Finding[]
     */
    private function runAstAnalysis(string $file, string $source): array
    {
        if (! $this->projectAnalyzer->isAvailable()) {
            return [];
        }

        $analysis = $this->projectAnalyzer->analyzeFile($file, $source);

        if ($analysis === null) {
            return [];
        }

        $checkers = [
            new SqlInjectionChecker(),
            new XssChecker(),
            new CommandInjectionChecker(),
            new FileInclusionChecker(),
        ];

        $findings = [];
        foreach ($checkers as $checker) {
            $findings = array_merge($findings, $checker->check($analysis));
        }

        return $findings;
    }

    // -------------------------------------------------------------------------

    /** @return string[] */
    private function collectFiles(string $path): array
    {
        if (is_file($path)) {
            return $this->isExcluded($path) ? [] : [$path];
        }

        if (!is_dir($path)) {
            return [];
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY,
        );

        $files = [];
        foreach ($iterator as $file) {
            /** @var \SplFileInfo $file */
            if (!$file->isFile()) {
                continue;
            }
            $realPath = $file->getRealPath();
            if ($realPath === false) {
                continue;
            }
            if ($this->isExcluded($realPath)) {
                continue;
            }
            $files[] = $realPath;
        }

        return $files;
    }

    private function isExcluded(string $path): bool
    {
        foreach ($this->exclusions as $pattern) {
            // Support both substring and fnmatch-style patterns.
            if (str_contains($path, $pattern) || fnmatch($pattern, $path)) {
                return true;
            }
        }
        return false;
    }
}
