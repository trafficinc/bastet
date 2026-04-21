<?php

declare(strict_types=1);

namespace Bastet\Checkers;

use Bastet\Analysis\AnalysisResult;
use Bastet\Core\Severity;
use Bastet\Flow\FlowNode;
use Bastet\Taint\SecurityContext;

final class CommandInjectionChecker extends AbstractTaintChecker
{
    public function check(AnalysisResult $result): array
    {
        $findings = [];

        foreach ($result->graph->nodes() as $node) {
            if (! $node instanceof FlowNode) {
                continue;
            }

            $context = $node->attributes['sinkContext'] ?? null;
            if ($context !== SecurityContext::Shell) {
                continue;
            }

            $finding = $this->taintedArgumentFinding(
                $result,
                $node,
                SecurityContext::Shell,
                Severity::Critical,
                'Tainted data reaches command execution',
                'User-controlled data flows into a shell execution sink without a recognized shell escaping step.',
                'Use escapeshellarg()/escapeshellcmd() or avoid shelling out with user-supplied input.',
                'SEC003',
                0.93,
            );

            if ($finding !== null) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }
}
