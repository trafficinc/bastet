<?php

declare(strict_types=1);

namespace Bastet\Checkers;

use Bastet\Analysis\AnalysisResult;
use Bastet\Core\Finding;
use Bastet\Core\Severity;
use Bastet\Flow\FlowNode;
use Bastet\Taint\SecurityContext;

abstract class AbstractTaintChecker
{
    /**
     * @return Finding[]
     */
    abstract public function check(AnalysisResult $result): array;

    protected function taintedArgumentFinding(
        AnalysisResult $result,
        FlowNode $sink,
        SecurityContext $context,
        Severity $severity,
        string $title,
        string $explanation,
        string $remediation,
        string $ruleId,
        float $confidence,
    ): ?Finding {
        foreach ($sink->inputs as $inputId) {
            $record = $result->taint->record($inputId);

            if ($record->state->value < 1 || $record->isSafeFor($context)) {
                continue;
            }

            $path = $result->taint->trace($inputId);

            return new Finding(
                severity: $severity,
                title: $title,
                file: $sink->file,
                line: $sink->line,
                snippet: $sink->label,
                explanation: $explanation,
                remediation: $remediation,
                confidence: $confidence,
                ruleId: $ruleId,
                details: [
                    'source' => $record->sourceLabel,
                    'sink' => $sink->label,
                    'context' => $context->value,
                    'path' => $path,
                ],
            );
        }

        return null;
    }
}
