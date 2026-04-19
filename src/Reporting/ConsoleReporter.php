<?php

declare(strict_types=1);

namespace Bastet\Reporting;

use Bastet\Core\Finding;
use Bastet\Core\Severity;

final class ConsoleReporter implements ReporterInterface
{
    private const RESET  = "\033[0m";
    private const BOLD   = "\033[1m";
    private const DIM    = "\033[2m";
    private const GREEN  = "\033[0;32m";
    private const WHITE  = "\033[1;37m";

    private bool $noColor;

    public function __construct(bool $noColor = false)
    {
        $this->noColor = $noColor || !stream_isatty(STDOUT);
    }

    public function report(array $findings, array $meta): string
    {
        $out = [];

        $out[] = $this->header($meta);

        if (empty($findings)) {
            $out[] = $this->color(self::GREEN, "\n  No findings above the minimum severity threshold.\n");
            $out[] = $this->summary($findings, $meta);
            return implode('', $out);
        }

        $currentFile = null;
        foreach ($findings as $finding) {
            if ($finding->file !== $currentFile) {
                $currentFile = $finding->file;
                $out[] = "\n" . $this->color(self::BOLD . self::WHITE, '  FILE: ') .
                         $this->color(self::WHITE, $this->relativePath($finding->file)) . "\n";
            }
            $out[] = $this->formatFinding($finding);
        }

        $out[] = $this->summary($findings, $meta);

        return implode('', $out);
    }

    // -------------------------------------------------------------------------

    private function header(array $meta): string
    {
        $line  = str_repeat('─', 72);
        $title = '  BASTET SECURITY SCAN';
        $sub   = sprintf(
            '  Target: %s  |  Files: %d  |  Time: %.2fs',
            $meta['target'],
            $meta['scannedFiles'],
            $meta['elapsed'],
        );
        return "\n" .
               $this->color(self::BOLD, $line . "\n") .
               $this->color(self::BOLD . self::WHITE, $title . "\n") .
               $this->color(self::DIM, $sub . "\n") .
               $this->color(self::BOLD, $line) . "\n";
    }

    private function formatFinding(Finding $f): string
    {
        $sColor  = $f->severity->color();
        $badge   = sprintf('[%s]', strtoupper($f->severity->value));
        $conf    = sprintf('%.0f%%', $f->confidence * 100);
        $snippet = $this->truncate(trim($f->snippet), 100);

        $lines = [];
        $lines[] = sprintf(
            '    %s %s %s %s',
            $this->color($sColor . self::BOLD, $badge),
            $this->color(self::BOLD, $f->title),
            $this->color(self::DIM, "({$f->ruleId})"),
            $this->color(self::DIM, "conf:{$conf}"),
        );
        $lines[] = sprintf(
            '    %s Line %d',
            $this->color(self::DIM, '↳'),
            $f->line,
        );
        if ($snippet !== '') {
            $lines[] = $this->color(self::DIM, "      » {$snippet}");
        }
        $lines[] = "      {$f->explanation}";
        $lines[] = $this->color(self::GREEN, "      Fix: ") . $f->remediation;
        $lines[] = '';

        return implode("\n", $lines);
    }

    private function summary(array $findings, array $meta): string
    {
        $counts = [];
        foreach (Severity::cases() as $s) {
            $counts[$s->value] = 0;
        }
        foreach ($findings as $f) {
            $counts[$f->severity->value]++;
        }

        $line    = str_repeat('─', 72);
        $total   = count($findings);
        $out     = [];
        $out[]   = "\n" . $this->color(self::BOLD, $line) . "\n";
        $out[]   = $this->color(self::BOLD, "  SUMMARY\n");

        foreach (Severity::cases() as $s) {
            $n = $counts[$s->value];
            if ($n === 0) {
                continue;
            }
            $out[] = sprintf(
                "  %s %s\n",
                $this->color($s->color() . self::BOLD, str_pad(strtoupper($s->value), 10)),
                $n,
            );
        }

        $out[] = sprintf(
            "\n  %s %d finding%s across %d file%s\n",
            $this->color(self::BOLD, 'TOTAL:'),
            $total,
            $total === 1 ? '' : 's',
            $meta['scannedFiles'],
            $meta['scannedFiles'] === 1 ? '' : 's',
        );
        $out[] = $this->color(self::BOLD, $line) . "\n";

        return implode('', $out);
    }

    private function color(string $codes, string $text): string
    {
        if ($this->noColor) {
            return $text;
        }
        return $codes . $text . self::RESET;
    }

    private function relativePath(string $path): string
    {
        $cwd = getcwd() ?: '';
        return str_starts_with($path, $cwd)
            ? ltrim(substr($path, strlen($cwd)), '/')
            : $path;
    }

    private function truncate(string $s, int $max): string
    {
        $s = preg_replace('/\s+/', ' ', $s) ?? $s;
        return mb_strlen($s) > $max ? mb_substr($s, 0, $max - 1) . '…' : $s;
    }
}
