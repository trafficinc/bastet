<?php

declare(strict_types=1);

namespace Bastet\Checkers;

use Bastet\Analysis\AnalysisResult;
use Bastet\Core\Severity;
use Bastet\Flow\FlowNode;
use Bastet\Taint\SecurityContext;

final class SqlInjectionChecker extends AbstractTaintChecker
{
    public function check(AnalysisResult $result): array
    {
        $findings = [];

        foreach ($result->graph->nodes() as $node) {
            if (! $node instanceof FlowNode) {
                continue;
            }

            $context = $node->attributes['sinkContext'] ?? null;
            if ($context !== SecurityContext::Sql) {
                continue;
            }

            $finding = $this->taintedArgumentFinding(
                $result,
                $node,
                SecurityContext::Sql,
                Severity::Critical,
                'Tainted data reaches SQL execution',
                'User-controlled data flows into a SQL execution sink without a recognized SQL-safe transformation.',
                'Use parameterized queries or query builder bindings. Avoid building SQL with concatenation or interpolation.',
                'SEC001',
                0.92,
            );

            if ($finding !== null) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }
}
