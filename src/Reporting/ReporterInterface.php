<?php

declare(strict_types=1);

namespace Bastet\Reporting;

use Bastet\Core\Finding;

interface ReporterInterface
{
    /**
     * @param Finding[] $findings
     * @param array{target: string, scannedFiles: int, elapsed: float} $meta
     */
    public function report(array $findings, array $meta): string;
}
