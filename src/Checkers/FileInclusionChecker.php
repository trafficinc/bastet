<?php

declare(strict_types=1);

namespace Bastet\Checkers;

use Bastet\Analysis\AnalysisResult;
use Bastet\Core\Severity;
use Bastet\Flow\FlowNode;
use Bastet\Taint\SecurityContext;

final class FileInclusionChecker extends AbstractTaintChecker
{
    public function check(AnalysisResult $result): array
    {
        $findings = [];

        foreach ($result->graph->nodes() as $node) {
            if (! $node instanceof FlowNode) {
                continue;
            }

            $context = $node->attributes['sinkContext'] ?? null;
            if ($context !== SecurityContext::File) {
                continue;
            }

            $finding = $this->taintedArgumentFinding(
                $result,
                $node,
                SecurityContext::File,
                Severity::Critical,
                'Tainted data reaches file system sink',
                'User-controlled data flows into a file include or file path sink without a recognized path safety check.',
                'Validate against an allowlist and constrain paths with basename() or realpath() plus a base-directory check.',
                'SEC004',
                0.88,
            );

            if ($finding !== null) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }
}
