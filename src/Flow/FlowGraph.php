<?php

declare(strict_types=1);

namespace Bastet\Flow;

final class FlowGraph
{
    /** @var array<string, FlowNode> */
    private array $nodes = [];

    /** @var list<FlowEdge> */
    private array $edges = [];

    public function addNode(FlowNode $node): void
    {
        $this->nodes[$node->id] = $node;
    }

    public function addEdge(FlowEdge $edge): void
    {
        $this->edges[] = $edge;
    }

    /**
     * @return array<string, FlowNode>
     */
    public function nodes(): array
    {
        return $this->nodes;
    }

    /**
     * @return list<FlowEdge>
     */
    public function edges(): array
    {
        return $this->edges;
    }
}
