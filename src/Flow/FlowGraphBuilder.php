<?php

declare(strict_types=1);

namespace Bastet\Flow;

use Bastet\SecurityAst\Expression;
use Bastet\SecurityAst\Expression\BinaryOperation;
use Bastet\SecurityAst\Expression\FunctionCall;
use Bastet\SecurityAst\Expression\LiteralValue;
use Bastet\SecurityAst\Expression\MethodCall;
use Bastet\SecurityAst\Expression\UnknownExpression;
use Bastet\SecurityAst\Expression\Variable;
use Bastet\SecurityAst\Program;
use Bastet\SecurityAst\Statement;
use Bastet\SecurityAst\Statement\Assignment;
use Bastet\SecurityAst\Statement\ExpressionStatement;
use Bastet\SecurityAst\Statement\FunctionDefinition;
use Bastet\SecurityAst\Statement\IfStatement;
use Bastet\SecurityAst\Statement\ReturnStatement;
use Bastet\Taint\FunctionRegistry;
use Bastet\Taint\FunctionSummaryBuilder;
use Bastet\Taint\FunctionSummary;

final class FlowGraphBuilder
{
    private FlowGraph $graph;

    /** @var array<string, string> */
    private array $variableDefs = [];

    private int $idCounter = 0;

    public function __construct(
        private readonly FunctionRegistry $functionRegistry = new FunctionRegistry(),
    ) {}

    public function build(Program $program): FlowGraph
    {
        $this->graph = new FlowGraph();
        $this->variableDefs = [];
        $this->idCounter = 0;

        $this->buildFunctionSummaries($program);

        foreach ($program->statements as $statement) {
            if (! $statement instanceof FunctionDefinition) {
                $this->buildStatement($statement);
            }
        }

        return $this->graph;
    }

    private function buildStatement(Statement $statement): void
    {
        if ($statement instanceof Assignment) {
            $valueId = $this->buildExpression($statement->value);
            $targetId = $this->newNodeId('var');
            $label = '$' . $statement->target->name;

            $this->graph->addNode(new FlowNode(
                id: $targetId,
                kind: 'variable',
                label: $statement->target->propertyPath ?? $label,
                file: $statement->meta->file,
                line: $statement->meta->line,
                inputs: [$valueId],
                attributes: ['name' => $statement->target->name],
            ));
            $this->graph->addEdge(new FlowEdge($valueId, $targetId, 'ASSIGNMENT'));
            $this->variableDefs[$label] = $targetId;

            return;
        }

        if ($statement instanceof ExpressionStatement) {
            $this->buildExpression($statement->expression);
            return;
        }

        if ($statement instanceof IfStatement) {
            $this->buildExpression($statement->condition);
            foreach ($statement->thenBlock as $nested) {
                $this->buildStatement($nested);
            }
            foreach ($statement->elseBlock as $nested) {
                $this->buildStatement($nested);
            }
            return;
        }
    }

    private function buildExpression(Expression $expression): string
    {
        if ($expression instanceof Variable) {
            $existing = $this->variableDefs['$' . $expression->name] ?? null;
            if ($existing !== null && ! $expression->isSuperglobal) {
                return $existing;
            }

            $id = $this->newNodeId('var');
            $this->graph->addNode(new FlowNode(
                id: $id,
                kind: $expression->isSuperglobal ? 'source' : 'variable',
                label: $expression->propertyPath ?? ('$' . $expression->name),
                file: $expression->meta->file,
                line: $expression->meta->line,
                attributes: [
                    'name' => $expression->name,
                    'isSource' => $expression->isSuperglobal,
                ],
            ));

            if (! $expression->isSuperglobal) {
                $this->variableDefs['$' . $expression->name] = $id;
            }

            return $id;
        }

        if ($expression instanceof LiteralValue) {
            $id = $this->newNodeId('literal');
            $this->graph->addNode(new FlowNode(
                id: $id,
                kind: 'literal',
                label: (string) $expression->value,
                file: $expression->meta->file,
                line: $expression->meta->line,
            ));
            return $id;
        }

        if ($expression instanceof BinaryOperation) {
            $left = $this->buildExpression($expression->left);
            $right = $this->buildExpression($expression->right);
            $id = $this->newNodeId('binop');
            $this->graph->addNode(new FlowNode(
                id: $id,
                kind: 'binary_operation',
                label: 'binary(' . $expression->operator . ')',
                file: $expression->meta->file,
                line: $expression->meta->line,
                inputs: [$left, $right],
                attributes: ['operator' => $expression->operator],
            ));
            $this->graph->addEdge(new FlowEdge($left, $id, 'CONCAT'));
            $this->graph->addEdge(new FlowEdge($right, $id, 'CONCAT'));
            return $id;
        }

        if ($expression instanceof FunctionCall) {
            return $this->buildCallNode(
                kind: 'function_call',
                label: $expression->name . '()',
                callableName: $expression->name,
                args: $expression->args,
                file: $expression->meta->file,
                line: $expression->meta->line,
            );
        }

        if ($expression instanceof MethodCall) {
            $callableName = strtolower($expression->method);
            $fullCallableName = $callableName;

            if ($expression->object instanceof Variable) {
                $fullCallableName = strtolower($expression->object->name) . '::' . strtolower($expression->method);

                if (
                    $this->functionRegistry->isSourceCall($fullCallableName)
                    || $this->functionRegistry->isSanitizer($fullCallableName)
                    || $this->functionRegistry->sinkContext($fullCallableName) !== null
                    || $this->functionRegistry->summary($fullCallableName) !== null
                ) {
                    $callableName = $fullCallableName;
                }
            }

            $args = $expression->args;
            array_unshift($args, $expression->object);

            return $this->buildCallNode(
                kind: 'method_call',
                label: $callableName . '()',
                callableName: $callableName,
                args: $args,
                file: $expression->meta->file,
                line: $expression->meta->line,
            );
        }

        if ($expression instanceof UnknownExpression) {
            $id = $this->newNodeId('unknown');
            $this->graph->addNode(new FlowNode(
                id: $id,
                kind: 'unknown',
                label: $expression->label,
                file: $expression->meta->file,
                line: $expression->meta->line,
            ));
            return $id;
        }

        $id = $this->newNodeId('unknown');
        $this->graph->addNode(new FlowNode(
            id: $id,
            kind: 'unknown',
            label: 'unknown',
            file: $expression->meta->file,
            line: $expression->meta->line,
        ));

        return $id;
    }

    /**
     * @param list<Expression> $args
     */
    private function buildCallNode(string $kind, string $label, string $callableName, array $args, string $file, int $line): string
    {
        $argIds = [];

        foreach ($args as $arg) {
            $argIds[] = $this->buildExpression($arg);
        }

        $id = $this->newNodeId('call');
        $attributes = ['callable' => strtolower($callableName)];

        if ($this->functionRegistry->isSourceCall(strtolower($callableName))) {
            $attributes['isSource'] = true;
        }

        if ($this->functionRegistry->isSanitizer(strtolower($callableName))) {
            $attributes['sanitizes'] = $this->functionRegistry->sanitizerContexts(strtolower($callableName));
        }

        if (($context = $this->functionRegistry->sinkContext(strtolower($callableName))) !== null) {
            $attributes['sinkContext'] = $context;
        }

        if (($summary = $this->functionRegistry->summary(strtolower($callableName))) !== null) {
            $attributes['summary'] = $summary;
        }

        $this->graph->addNode(new FlowNode(
            id: $id,
            kind: ($attributes['isSource'] ?? false) === true ? 'source' : $kind,
            label: $label,
            file: $file,
            line: $line,
            inputs: $argIds,
            attributes: $attributes,
        ));

        foreach ($argIds as $argId) {
            $this->graph->addEdge(new FlowEdge($argId, $id, 'ARGUMENT'));
        }

        return $id;
    }

    private function buildFunctionSummaries(Program $program): void
    {
        $functions = [];

        foreach ($program->statements as $statement) {
            if (! $statement instanceof FunctionDefinition) {
                continue;
            }

            $functions[] = $statement;
        }

        if ($functions === []) {
            return;
        }

        $summaryBuilder = new FunctionSummaryBuilder($this->functionRegistry);
        $maxIterations = max(2, count($functions) * 2);

        for ($i = 0; $i < $maxIterations; $i++) {
            $changed = false;

            foreach ($functions as $function) {
                $existing = $this->functionRegistry->summary($function->name);
                $summary = $summaryBuilder->build($function);

                if (! $existing instanceof FunctionSummary || ! $existing->equals($summary)) {
                    $this->functionRegistry->addSummary($function->name, $summary);
                    $changed = true;
                }
            }

            if (! $changed) {
                break;
            }
        }
    }

    private function newNodeId(string $prefix): string
    {
        $this->idCounter++;

        return $prefix . '_' . $this->idCounter;
    }
}
