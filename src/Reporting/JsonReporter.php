<?php

declare(strict_types=1);

namespace Bastet\Reporting;

use Bastet\Core\Finding;
use Bastet\Core\Severity;

final class JsonReporter implements ReporterInterface
{
    public function report(array $findings, array $meta): string
    {
        $counts = [];
        foreach (Severity::cases() as $s) {
            $counts[$s->value] = 0;
        }
        foreach ($findings as $f) {
            $counts[$f->severity->value]++;
        }

        $output = [
            'meta' => [
                'target'        => $meta['target'],
                'scanned_files' => $meta['scannedFiles'],
                'elapsed_sec'   => round($meta['elapsed'], 3),
                'total_findings'=> count($findings),
                'counts'        => $counts,
                'generated_at'  => date('c'),
            ],
            'findings' => array_map(
                static fn(Finding $f) => $f->toArray(),
                $findings,
            ),
        ];

        return json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
