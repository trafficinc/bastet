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
            $isPhpFile = strtolower(pathinfo($file, PATHINFO_EXTENSION)) === 'php';
            $isBladeTemplate = str_ends_with($file, '.blade.php');
            $astBacked = $isPhpFile && ! $isBladeTemplate && $this->projectAnalyzer->isAvailable();

            if ($astBacked) {
                $findings = array_merge($findings, $this->runAstAnalysis($file, $source));
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
                        $findings[] = $finding;
                    }
                }
            }
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
