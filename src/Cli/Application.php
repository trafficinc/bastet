<?php

declare(strict_types=1);

namespace Bastet\Cli;

use Bastet\Core\RuleRegistry;
use Bastet\Core\Scanner;
use Bastet\Core\Severity;
use Bastet\Reporting\ConsoleReporter;
use Bastet\Reporting\JsonReporter;

final class Application
{
    /**
     * @param list<string> $argv
     */
    public function run(array $argv): int
    {
        error_reporting(E_ERROR | E_PARSE);

        $opts = getopt('ht:f:o:s:e:', [
            'help',
            'target:',
            'format:',
            'output:',
            'min-severity:',
            'exclude:',
            'no-color',
            'list-rules',
        ], $restIndex);

        $positional = array_slice($argv, $restIndex);

        if (isset($opts['h']) || isset($opts['help'])) {
            fwrite(STDOUT, $this->help());

            return 0;
        }

        if (isset($opts['list-rules'])) {
            foreach (RuleRegistry::all() as $rule) {
                fprintf(STDOUT, "  %s  %s  [%s]\n", $rule->id(), $rule->name(), implode(', ', $rule->extensions()));
            }

            return 0;
        }

        $target = $opts['t'] ?? $opts['target'] ?? $positional[0] ?? null;

        if ($target === null) {
            fwrite(STDERR, "Error: no target path specified. Use --target <path> or pass a path as the last argument.\n");
            fwrite(STDERR, "Run with --help for usage.\n");

            return 2;
        }

        $target = rtrim(realpath($target) ?: $target, '/');

        if (! file_exists($target)) {
            fwrite(STDERR, "Error: target path does not exist: {$target}\n");

            return 2;
        }

        $format = strtolower((string) ($opts['f'] ?? $opts['format'] ?? 'console'));
        $outFile = $opts['o'] ?? $opts['output'] ?? null;

        if (! in_array($format, ['console', 'json'], true)) {
            fwrite(STDERR, "Error: unknown format '{$format}'. Use 'console' or 'json'.\n");

            return 2;
        }

        $minSeverityStr = strtolower((string) ($opts['s'] ?? $opts['min-severity'] ?? 'info'));

        try {
            $minSeverity = Severity::fromString($minSeverityStr);
        } catch (\ValueError) {
            fwrite(STDERR, "Error: invalid severity '{$minSeverityStr}'. Use: critical, high, medium, low, info.\n");

            return 2;
        }

        $exclusions = $this->normalizeExclusions($opts);
        $noColor = isset($opts['no-color']);

        $scanner = new Scanner($minSeverity);
        $scanner->setExclusions($exclusions);

        foreach (RuleRegistry::all() as $rule) {
            $scanner->addRule($rule);
        }

        $start = microtime(true);
        $findings = $scanner->scan($target);
        $elapsed = microtime(true) - $start;

        $meta = [
            'target' => $target,
            'scannedFiles' => $this->countScannedFiles($target, $exclusions),
            'elapsed' => $elapsed,
        ];

        $reporter = match ($format) {
            'json' => new JsonReporter(),
            default => new ConsoleReporter(noColor: $noColor),
        };

        $output = $reporter->report($findings, $meta);

        if (is_string($outFile) && $outFile !== '') {
            file_put_contents($outFile, $output);
            fwrite(STDOUT, "Report written to: {$outFile}\n");
        } else {
            fwrite(STDOUT, $output);
        }

        $serious = array_filter(
            $findings,
            static fn ($finding): bool => $finding->severity->weight() >= Severity::High->weight(),
        );

        return count($serious) > 0 ? 1 : 0;
    }

    /**
     * @param array<string, mixed> $opts
     * @return list<string>
     */
    private function normalizeExclusions(array $opts): array
    {
        $rawExclusions = [];

        if (isset($opts['e'])) {
            $rawExclusions = is_array($opts['e']) ? $opts['e'] : [$opts['e']];
        }

        if (isset($opts['exclude'])) {
            $extra = is_array($opts['exclude']) ? $opts['exclude'] : [$opts['exclude']];
            $rawExclusions = array_merge($rawExclusions, $extra);
        }

        $exclusions = [];

        foreach ($rawExclusions as $exclusion) {
            if (! is_string($exclusion)) {
                continue;
            }

            foreach (explode(',', $exclusion) as $part) {
                $part = trim($part);

                if ($part !== '') {
                    $exclusions[] = $part;
                }
            }
        }

        return array_merge($exclusions, [
            '/vendor/',
            '/node_modules/',
        ]);
    }

    /**
     * @param list<string> $exclusions
     */
    private function countScannedFiles(string $target, array $exclusions): int
    {
        if (is_file($target)) {
            return 1;
        }

        $count = 0;
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($target, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY,
        );

        foreach ($iterator as $file) {
            $path = $file->getRealPath();

            if ($path === false) {
                continue;
            }

            $excluded = false;

            foreach ($exclusions as $exclusion) {
                if (str_contains($path, $exclusion) || fnmatch($exclusion, $path)) {
                    $excluded = true;
                    break;
                }
            }

            if (! $excluded) {
                $count++;
            }
        }

        return $count;
    }

    private function help(): string
    {
        return <<<'HELP'

  BASTET
  ══════
  A static analysis tool for detecting common security vulnerabilities in PHP projects.

  USAGE
    bastet [options] [path]

  ARGUMENTS
    path                    Target directory or file to scan

  OPTIONS
    -t, --target <path>     Target path (alternative to positional argument)
    -f, --format <fmt>      Output format: console (default) or json
    -o, --output <file>     Write report to file instead of stdout
    -s, --min-severity <s>  Minimum severity to report: critical|high|medium|low|info
    -e, --exclude <pattern> Exclude paths matching this pattern (can repeat; comma-separate multiple)
        --no-color          Disable ANSI colour output
        --list-rules        List all available rules and exit
    -h, --help              Show this help and exit

  EXIT CODES
    0   No findings at High severity or above
    1   One or more High/Critical findings detected
    2   Invalid arguments or target not found

HELP;
    }
}
