<?php

declare(strict_types=1);

namespace Bastet\Checkers;

use Bastet\Analysis\AnalysisResult;
use Bastet\Core\Severity;
use Bastet\Flow\FlowNode;
use Bastet\Taint\SecurityContext;

final class XssChecker extends AbstractTaintChecker
{
    public function check(AnalysisResult $result): array
    {
        $findings = [];

        foreach ($result->graph->nodes() as $node) {
            if (! $node instanceof FlowNode) {
                continue;
            }

            $context = $node->attributes['sinkContext'] ?? null;
            if ($context !== SecurityContext::Html) {
                continue;
            }

            $finding = $this->taintedArgumentFinding(
                $result,
                $node,
                SecurityContext::Html,
                Severity::Critical,
                'Tainted data reaches HTML output',
                'User-controlled data is emitted into an HTML sink without a recognized HTML escaping step.',
                'Escape output with htmlspecialchars() or a framework helper such as e().',
                'SEC002',
                0.90,
            );

            if ($finding !== null) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }
}
