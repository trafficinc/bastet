<?php

declare(strict_types=1);

namespace Bastet\Taint;

use Bastet\Flow\FlowGraph;
use Bastet\Flow\FlowNode;

final readonly class TaintAnalysisResult
{
    /**
     * @param array<string, TaintRecord> $records
     */
    public function __construct(
        public FlowGraph $graph,
        public array $records,
    ) {}

    public function record(string $nodeId): TaintRecord
    {
        return $this->records[$nodeId] ?? new TaintRecord(TaintState::Clean);
    }

    public function trace(string $nodeId): array
    {
        $path = [];
        $visited = [];
        $current = $nodeId;

        while ($current !== null && ! isset($visited[$current])) {
            $visited[$current] = true;
            $node = $this->graph->nodes()[$current] ?? null;

            if ($node instanceof FlowNode) {
                $path[] = $node->label;
            }

            $current = $this->records[$current]->predecessor ?? null;
        }

        return array_reverse($path);
    }
}
