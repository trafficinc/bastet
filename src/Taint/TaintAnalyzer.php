<?php

declare(strict_types=1);

namespace Bastet\Taint;

use Bastet\Flow\FlowGraph;
use Bastet\Flow\FlowNode;

final class TaintAnalyzer
{
    public function __construct(
        private readonly FunctionRegistry $registry = new FunctionRegistry(),
    ) {}

    public function analyze(FlowGraph $graph): TaintAnalysisResult
    {
        $records = [];
        $queue = array_keys($graph->nodes());

        foreach ($graph->nodes() as $nodeId => $node) {
            $records[$nodeId] = $this->initialRecord($node);
        }

        while ($queue !== []) {
            $nodeId = array_shift($queue);
            $node = $graph->nodes()[$nodeId] ?? null;

            if (! $node instanceof FlowNode) {
                continue;
            }

            $updated = $this->evaluateNode($node, $records);

            if ($this->isMoreSpecific($updated, $records[$nodeId])) {
                $records[$nodeId] = $updated;

                foreach ($graph->edges() as $edge) {
                    if ($edge->from === $nodeId) {
                        $queue[] = $edge->to;
                    }
                }
            }
        }

        return new TaintAnalysisResult($graph, $records);
    }

    /**
     * @param array<string, TaintRecord> $records
     */
    private function evaluateNode(FlowNode $node, array $records): TaintRecord
    {
        if ($node->kind === 'source') {
            return new TaintRecord(
                TaintState::Tainted,
                sourceLabel: $node->label,
            );
        }

        if ($node->inputs === []) {
            return $records[$node->id] ?? new TaintRecord(TaintState::Clean);
        }

        $inputRecords = [];
        foreach ($node->inputs as $inputId) {
            $inputRecords[$inputId] = $records[$inputId] ?? new TaintRecord(TaintState::Clean);
        }

        if (isset($node->attributes['sanitizes'])) {
            $contexts = $node->attributes['sanitizes'];
            $predecessor = array_key_first($inputRecords);
            $sourceLabel = $predecessor !== null ? $inputRecords[$predecessor]->sourceLabel : null;

            return new TaintRecord(
                TaintState::Sanitized,
                predecessor: $predecessor,
                sourceLabel: $sourceLabel,
                sanitizedFor: $contexts,
            );
        }

        if (isset($node->attributes['summary']) && $node->attributes['summary'] instanceof FunctionSummary) {
            $candidateStates = [];
            $predecessor = null;
            $sourceLabel = $node->attributes['summary']->sourceLabel;
            $sanitizedFor = [];

            foreach ($node->attributes['summary']->taintOutFromArgs as $index) {
                if (! isset($node->inputs[$index])) {
                    continue;
                }

                $inputId = $node->inputs[$index];
                $candidateStates[] = $inputRecords[$inputId]->state;

                if ($inputRecords[$inputId]->state === TaintState::Tainted) {
                    $predecessor = $inputId;
                    $sourceLabel = $inputRecords[$inputId]->sourceLabel;
                }

                if ($inputRecords[$inputId]->state === TaintState::Sanitized) {
                    if ($predecessor === null) {
                        $predecessor = $inputId;
                        $sourceLabel = $inputRecords[$inputId]->sourceLabel;
                    }

                    $sanitizedFor = array_values(array_unique(array_merge(
                        $sanitizedFor,
                        $inputRecords[$inputId]->sanitizedFor,
                    )));
                }
            }

            if ($node->attributes['summary']->taintedWithoutArgs) {
                $candidateStates[] = TaintState::Tainted;
            }

            if ($candidateStates !== []) {
                $state = TaintState::merge(...$candidateStates);

                if ($node->attributes['summary']->sanitizes !== [] && $state !== TaintState::Clean) {
                    return new TaintRecord(
                        TaintState::Sanitized,
                        predecessor: $predecessor,
                        sourceLabel: $sourceLabel,
                        sanitizedFor: $node->attributes['summary']->sanitizes,
                    );
                }

                return new TaintRecord(
                    $state,
                    predecessor: $predecessor,
                    sourceLabel: $sourceLabel,
                    sanitizedFor: $sanitizedFor,
                );
            }
        }

        $state = TaintState::Clean;
        $predecessor = null;
        $sourceLabel = null;
        $sanitizedFor = [];

        foreach ($inputRecords as $inputId => $record) {
            $state = TaintState::merge($state, $record->state);

            if ($record->state === TaintState::Tainted) {
                $predecessor = $inputId;
                $sourceLabel = $record->sourceLabel;
            }

            if ($record->state === TaintState::Sanitized) {
                $sanitizedFor = array_values(array_unique(array_merge($sanitizedFor, $record->sanitizedFor)));
                if ($predecessor === null) {
                    $predecessor = $inputId;
                    $sourceLabel = $record->sourceLabel;
                }
            }
        }

        return new TaintRecord($state, $predecessor, $sourceLabel, $sanitizedFor);
    }

    private function initialRecord(FlowNode $node): TaintRecord
    {
        if ($node->kind === 'source') {
            return new TaintRecord(TaintState::Tainted, sourceLabel: $node->label);
        }

        if ($node->kind === 'literal') {
            return new TaintRecord(TaintState::Clean);
        }

        return new TaintRecord(TaintState::Clean);
    }

    private function isMoreSpecific(TaintRecord $candidate, TaintRecord $current): bool
    {
        if ($candidate->state->value !== $current->state->value) {
            return $candidate->state->value > $current->state->value;
        }

        return count($candidate->sanitizedFor) > count($current->sanitizedFor);
    }
}
