<?php

declare(strict_types=1);

namespace Bastet\Flow;

use Bastet\SecurityAst\Expression;
use Bastet\SecurityAst\Expression\BinaryOperation;
use Bastet\SecurityAst\Expression\ConditionalExpression;
use Bastet\SecurityAst\Expression\FunctionCall;
use Bastet\SecurityAst\Expression\LiteralValue;
use Bastet\SecurityAst\Expression\MethodCall;
use Bastet\SecurityAst\Expression\UnknownExpression;
use Bastet\SecurityAst\Expression\Variable;
use Bastet\SecurityAst\Program;
use Bastet\SecurityAst\Statement;
use Bastet\SecurityAst\Statement\Assignment;
use Bastet\SecurityAst\Statement\ExpressionStatement;
use Bastet\SecurityAst\Statement\ForeachStatement;
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
            $this->buildStatement($statement);
        }

        return $this->graph;
    }

    private function buildStatement(Statement $statement): void
    {
        if ($statement instanceof Assignment) {
            $valueId = $this->buildExpression($statement->value);
            $targetId = $this->newNodeId('var');
            $key = $this->variableKey($statement->target);

            $this->graph->addNode(new FlowNode(
                id: $targetId,
                kind: 'variable',
                label: $key,
                file: $statement->meta->file,
                line: $statement->meta->line,
                inputs: [$valueId],
                attributes: ['name' => $statement->target->name],
            ));
            $this->graph->addEdge(new FlowEdge($valueId, $targetId, 'ASSIGNMENT'));
            $this->variableDefs[$key] = $targetId;

            return;
        }

        if ($statement instanceof ExpressionStatement) {
            $this->buildExpression($statement->expression);
            return;
        }

        if ($statement instanceof IfStatement) {
            $this->buildExpression($statement->condition);
            $baselineDefs = $this->variableDefs;
            $thenDefs = $this->buildScopedStatements($statement->thenBlock, $baselineDefs);
            $elseDefs = $this->buildScopedStatements($statement->elseBlock, $baselineDefs);
            $this->variableDefs = $this->mergeVariableDefinitions($baselineDefs, $thenDefs, $elseDefs, $statement->meta->file, $statement->meta->line);
            return;
        }

        if ($statement instanceof FunctionDefinition) {
            $this->buildFunctionBody($statement);
            return;
        }

        if ($statement instanceof ForeachStatement) {
            $baselineDefs = $this->variableDefs;
            $iterableId = $this->buildExpression($statement->iterable);

            $loopDefs = $baselineDefs;
            $loopDefs[$this->variableKey($statement->valueVariable)] = $this->createAssignedVariableNode(
                $statement->valueVariable,
                $iterableId,
                $statement->meta->file,
                $statement->meta->line,
            );

            if ($statement->keyVariable !== null) {
                $keySourceId = $this->newNodeId('literal');
                $this->graph->addNode(new FlowNode(
                    id: $keySourceId,
                    kind: 'literal',
                    label: 'foreach-key',
                    file: $statement->meta->file,
                    line: $statement->meta->line,
                ));
                $loopDefs[$this->variableKey($statement->keyVariable)] = $this->createAssignedVariableNode(
                    $statement->keyVariable,
                    $keySourceId,
                    $statement->meta->file,
                    $statement->meta->line,
                );
            }

            $loopDefs = $this->buildScopedStatements($statement->body, $loopDefs);
            $this->variableDefs = $this->mergeVariableDefinitions($baselineDefs, $loopDefs, $baselineDefs, $statement->meta->file, $statement->meta->line);
        }
    }

    private function buildExpression(Expression $expression): string
    {
        if ($expression instanceof Variable) {
            $key = $this->variableKey($expression);
            $existing = $this->variableDefs[$key] ?? null;
            if ($existing !== null && ! $expression->isSuperglobal) {
                return $existing;
            }

            $id = $this->newNodeId('var');
            $this->graph->addNode(new FlowNode(
                id: $id,
                kind: $expression->isSuperglobal ? 'source' : 'variable',
                label: $key,
                file: $expression->meta->file,
                line: $expression->meta->line,
                attributes: [
                    'name' => $expression->name,
                    'isSource' => $expression->isSuperglobal,
                ],
            ));

            if (! $expression->isSuperglobal) {
                $this->variableDefs[$key] = $id;
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

        if ($expression instanceof ConditionalExpression) {
            $condition = $this->buildExpression($expression->condition);
            $ifTrue = $expression->ifTrue !== null
                ? $this->buildExpression($expression->ifTrue)
                : $condition;
            $ifFalse = $this->buildExpression($expression->ifFalse);
            $id = $this->newNodeId('conditional');
            $this->graph->addNode(new FlowNode(
                id: $id,
                kind: 'conditional_expression',
                label: 'conditional',
                file: $expression->meta->file,
                line: $expression->meta->line,
                inputs: [$condition, $ifTrue, $ifFalse],
            ));
            $this->graph->addEdge(new FlowEdge($condition, $id, 'CONDITION'));
            $this->graph->addEdge(new FlowEdge($ifTrue, $id, 'BRANCH'));
            $this->graph->addEdge(new FlowEdge($ifFalse, $id, 'BRANCH'));
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
            $callableName = $expression->resolvedName ?? strtolower($expression->method);
            $fullCallableName = $callableName;

            if ($expression->resolvedName === null && $expression->object instanceof Variable) {
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
                $existing = $this->functionRegistry->summary($function->canonicalName);
                $summary = $summaryBuilder->build($function);

                if (! $existing instanceof FunctionSummary || ! $existing->equals($summary)) {
                    $this->functionRegistry->addSummary($function->canonicalName, $summary);
                    $changed = true;
                }
            }

            if (! $changed) {
                break;
            }
        }
    }

    private function buildFunctionBody(FunctionDefinition $function): void
    {
        $previousDefs = $this->variableDefs;
        $this->variableDefs = [];

        if ($function->ownerClass !== null) {
            $thisNodeId = $this->newNodeId('var');
            $this->graph->addNode(new FlowNode(
                id: $thisNodeId,
                kind: 'variable',
                label: '$this',
                file: $function->meta->file,
                line: $function->meta->line,
                attributes: ['name' => 'this'],
            ));
            $this->variableDefs['$this'] = $thisNodeId;
        }

        foreach ($function->parameters as $parameter) {
            $paramNodeId = $this->newNodeId('var');
            $label = '$' . $parameter;
            $this->graph->addNode(new FlowNode(
                id: $paramNodeId,
                kind: 'variable',
                label: $label,
                file: $function->meta->file,
                line: $function->meta->line,
                attributes: ['name' => $parameter, 'parameter' => true],
            ));
            $this->variableDefs[$label] = $paramNodeId;
        }

        foreach ($function->body as $nested) {
            $this->buildStatement($nested);
        }

        $this->variableDefs = $previousDefs;
    }

    private function newNodeId(string $prefix): string
    {
        $this->idCounter++;

        return $prefix . '_' . $this->idCounter;
    }

    /**
     * @param list<Statement> $statements
     * @param array<string, string> $startingDefs
     * @return array<string, string>
     */
    private function buildScopedStatements(array $statements, array $startingDefs): array
    {
        $previousDefs = $this->variableDefs;
        $this->variableDefs = $startingDefs;

        foreach ($statements as $statement) {
            $this->buildStatement($statement);
        }

        $scopedDefs = $this->variableDefs;
        $this->variableDefs = $previousDefs;

        return $scopedDefs;
    }

    /**
     * @param array<string, string> $baselineDefs
     * @param array<string, string> $leftDefs
     * @param array<string, string> $rightDefs
     * @return array<string, string>
     */
    private function mergeVariableDefinitions(array $baselineDefs, array $leftDefs, array $rightDefs, string $file, int $line): array
    {
        $merged = $baselineDefs;
        $keys = array_values(array_unique(array_merge(
            array_keys($baselineDefs),
            array_keys($leftDefs),
            array_keys($rightDefs),
        )));

        foreach ($keys as $key) {
            $left = $leftDefs[$key] ?? $baselineDefs[$key] ?? null;
            $right = $rightDefs[$key] ?? $baselineDefs[$key] ?? null;

            if ($left === null && $right === null) {
                continue;
            }

            if ($left === $right) {
                $merged[$key] = $left;
                continue;
            }

            $mergeId = $this->newNodeId('merge');
            $inputs = array_values(array_unique(array_filter([$left, $right])));
            $this->graph->addNode(new FlowNode(
                id: $mergeId,
                kind: 'merge',
                label: 'merge(' . $key . ')',
                file: $file,
                line: $line,
                inputs: $inputs,
            ));

            foreach ($inputs as $inputId) {
                $this->graph->addEdge(new FlowEdge($inputId, $mergeId, 'MERGE'));
            }

            $merged[$key] = $mergeId;
        }

        return $merged;
    }

    private function createAssignedVariableNode(Variable $variable, string $valueId, string $file, int $line): string
    {
        $targetId = $this->newNodeId('var');
        $key = $this->variableKey($variable);

        $this->graph->addNode(new FlowNode(
            id: $targetId,
            kind: 'variable',
            label: $key,
            file: $file,
            line: $line,
            inputs: [$valueId],
            attributes: ['name' => $variable->name],
        ));
        $this->graph->addEdge(new FlowEdge($valueId, $targetId, 'ASSIGNMENT'));

        return $targetId;
    }

    private function variableKey(Variable $variable): string
    {
        return $variable->propertyPath ?? ('$' . $variable->name);
    }
}
