<?php

declare(strict_types=1);

namespace Bastet\Taint;

use Bastet\SecurityAst\Expression;
use Bastet\SecurityAst\Expression\BinaryOperation;
use Bastet\SecurityAst\Expression\ConditionalExpression;
use Bastet\SecurityAst\Expression\FunctionCall;
use Bastet\SecurityAst\Expression\LiteralValue;
use Bastet\SecurityAst\Expression\MethodCall;
use Bastet\SecurityAst\Expression\UnknownExpression;
use Bastet\SecurityAst\Expression\Variable;
use Bastet\SecurityAst\Statement;
use Bastet\SecurityAst\Statement\Assignment;
use Bastet\SecurityAst\Statement\ExpressionStatement;
use Bastet\SecurityAst\Statement\ForeachStatement;
use Bastet\SecurityAst\Statement\FunctionDefinition;
use Bastet\SecurityAst\Statement\IfStatement;
use Bastet\SecurityAst\Statement\ReturnStatement;

final class FunctionSummaryBuilder
{
    public function __construct(
        private readonly FunctionRegistry $registry,
    ) {}

    public function build(FunctionDefinition $function): FunctionSummary
    {
        $environment = [];

        if ($function->ownerClass !== null) {
            $environment['$this'] = new SummaryValue(argIndexes: [0]);
        }

        foreach ($function->parameters as $index => $parameter) {
            $argIndex = $function->ownerClass !== null ? $index + 1 : $index;
            $environment['$' . $parameter] = new SummaryValue(argIndexes: [$argIndex]);
        }

        $returns = $this->summarizeStatements($function->body, $environment);

        if ($returns === []) {
            return new FunctionSummary();
        }

        $argIndexes = [];
        $taintedWithoutArgs = false;
        $sourceLabel = null;
        $sanitizedFor = null;

        foreach ($returns as $returnValue) {
            $argIndexes = array_values(array_unique(array_merge($argIndexes, $returnValue->argIndexes)));
            $taintedWithoutArgs = $taintedWithoutArgs || $returnValue->taintedWithoutArgs;
            $sourceLabel ??= $returnValue->sourceLabel;

            if (! $returnValue->dependsOnInput()) {
                $sanitizedFor = [];
                continue;
            }

            if ($returnValue->sanitizedFor === []) {
                $sanitizedFor = [];
                continue;
            }

            $sanitizedFor = $sanitizedFor === null
                ? $returnValue->sanitizedFor
                : $this->intersectContexts($sanitizedFor, $returnValue->sanitizedFor);
        }

        return new FunctionSummary(
            taintOutFromArgs: $argIndexes,
            sanitizes: $sanitizedFor ?? [],
            taintedWithoutArgs: $taintedWithoutArgs,
            sourceLabel: $sourceLabel,
        );
    }

    /**
     * @param list<Statement> $statements
     * @param array<string, SummaryValue> $environment
     * @return list<SummaryValue>
     */
    private function summarizeStatements(array $statements, array &$environment): array
    {
        $returns = [];

        foreach ($statements as $statement) {
            if ($statement instanceof Assignment) {
                $environment[$this->variableKey($statement->target)] = $this->evaluateExpression($statement->value, $environment);
                continue;
            }

            if ($statement instanceof ReturnStatement) {
                if ($statement->value !== null) {
                    $returns[] = $this->evaluateExpression($statement->value, $environment);
                }
                continue;
            }

            if ($statement instanceof IfStatement) {
                $thenEnvironment = $environment;
                $elseEnvironment = $environment;
                $thenReturns = $this->summarizeStatements($statement->thenBlock, $thenEnvironment);
                $elseReturns = $this->summarizeStatements($statement->elseBlock, $elseEnvironment);

                $environment = $this->mergeEnvironments($environment, $thenEnvironment, $elseEnvironment);
                $returns = array_merge($returns, $thenReturns, $elseReturns);
                continue;
            }

            if ($statement instanceof ForeachStatement) {
                $loopEnvironment = $environment;
                $iterableValue = $this->evaluateExpression($statement->iterable, $environment);
                $loopEnvironment[$this->variableKey($statement->valueVariable)] = $iterableValue;

                if ($statement->keyVariable !== null) {
                    $loopEnvironment[$this->variableKey($statement->keyVariable)] = SummaryValue::clean();
                }

                $loopReturns = $this->summarizeStatements($statement->body, $loopEnvironment);
                $environment = $this->mergeEnvironments($environment, $loopEnvironment, $environment);
                $returns = array_merge($returns, $loopReturns);
                continue;
            }

            if ($statement instanceof ExpressionStatement) {
                $this->evaluateExpression($statement->expression, $environment);
            }
        }

        return $returns;
    }

    /**
     * @param array<string, SummaryValue> $baseline
     * @param array<string, SummaryValue> $thenEnvironment
     * @param array<string, SummaryValue> $elseEnvironment
     * @return array<string, SummaryValue>
     */
    private function mergeEnvironments(array $baseline, array $thenEnvironment, array $elseEnvironment): array
    {
        $merged = $baseline;
        $names = array_values(array_unique(array_merge(
            array_keys($baseline),
            array_keys($thenEnvironment),
            array_keys($elseEnvironment),
        )));

        foreach ($names as $name) {
            $left = $thenEnvironment[$name] ?? $baseline[$name] ?? SummaryValue::clean();
            $right = $elseEnvironment[$name] ?? $baseline[$name] ?? SummaryValue::clean();

            $sanitizedFor = [];
            if ($left->sanitizedFor !== [] && $right->sanitizedFor !== []) {
                $sanitizedFor = $this->intersectContexts($left->sanitizedFor, $right->sanitizedFor);
            }

            $merged[$name] = new SummaryValue(
                argIndexes: array_values(array_unique(array_merge($left->argIndexes, $right->argIndexes))),
                sanitizedFor: $sanitizedFor,
                taintedWithoutArgs: $left->taintedWithoutArgs || $right->taintedWithoutArgs,
                sourceLabel: $left->sourceLabel ?? $right->sourceLabel,
            );
        }

        return $merged;
    }

    /**
     * @param array<string, SummaryValue> $environment
     */
    private function evaluateExpression(Expression $expression, array $environment): SummaryValue
    {
        if ($expression instanceof Variable) {
            $key = $this->variableKey($expression);

            return $environment[$key]
                ?? ($expression->isSuperglobal
                    ? new SummaryValue(taintedWithoutArgs: true, sourceLabel: $expression->propertyPath ?? '$' . $expression->name)
                    : SummaryValue::clean());
        }

        if ($expression instanceof LiteralValue || $expression instanceof UnknownExpression) {
            return SummaryValue::clean();
        }

        if ($expression instanceof BinaryOperation) {
            return $this->evaluateExpression($expression->left, $environment)
                ->merge($this->evaluateExpression($expression->right, $environment))
                ->withoutSanitization();
        }

        if ($expression instanceof ConditionalExpression) {
            $ifTrue = $expression->ifTrue !== null
                ? $this->evaluateExpression($expression->ifTrue, $environment)
                : $this->evaluateExpression($expression->condition, $environment);
            $ifFalse = $this->evaluateExpression($expression->ifFalse, $environment);

            return $this->mergeAlternativeValues($ifTrue, $ifFalse);
        }

        if ($expression instanceof FunctionCall) {
            return $this->evaluateCall($expression->name, $expression->args, $environment);
        }

        if ($expression instanceof MethodCall) {
            $name = $expression->resolvedName ?? strtolower($expression->method);
            if ($expression->resolvedName === null && $expression->object instanceof Variable) {
                $fullName = strtolower($expression->object->name) . '::' . strtolower($expression->method);
                if (
                    $this->registry->isSourceCall($fullName)
                    || $this->registry->isSanitizer($fullName)
                    || $this->registry->summary($fullName) !== null
                ) {
                    $name = $fullName;
                }
            }

            $args = $expression->args;
            array_unshift($args, $expression->object);

            return $this->evaluateCall($name, $args, $environment);
        }

        return SummaryValue::clean();
    }

    /**
     * @param list<Expression> $args
     * @param array<string, SummaryValue> $environment
     */
    private function evaluateCall(string $name, array $args, array $environment): SummaryValue
    {
        $name = strtolower($name);
        $argValues = array_map(
            fn (Expression $arg): SummaryValue => $this->evaluateExpression($arg, $environment),
            $args,
        );

        if ($this->registry->isSourceCall($name)) {
            return new SummaryValue(taintedWithoutArgs: true, sourceLabel: $name . '()');
        }

        if ($this->registry->isSanitizer($name)) {
            $input = $argValues[0] ?? SummaryValue::clean();
            return $input->withSanitization($this->registry->sanitizerContexts($name));
        }

        $summary = $this->registry->summary($name);
        if ($summary instanceof FunctionSummary) {
            return $this->applySummary($summary, $argValues);
        }

        $value = SummaryValue::clean();
        foreach ($argValues as $argValue) {
            $value = $value->merge($argValue);
        }

        return $value->withoutSanitization();
    }

    /**
     * @param list<SummaryValue> $argValues
     */
    private function applySummary(FunctionSummary $summary, array $argValues): SummaryValue
    {
        $value = SummaryValue::clean();

        foreach ($summary->taintOutFromArgs as $index) {
            if (isset($argValues[$index])) {
                $value = $value->merge($argValues[$index]);
            }
        }

        if ($summary->taintedWithoutArgs) {
            $value = $value->merge(new SummaryValue(
                taintedWithoutArgs: true,
                sourceLabel: $summary->sourceLabel,
            ));
        }

        if ($summary->sanitizes !== [] && $value->dependsOnInput()) {
            return $value->withSanitization($summary->sanitizes);
        }

        return $value;
    }

    private function variableKey(Variable $variable): string
    {
        return $variable->propertyPath ?? ('$' . $variable->name);
    }

    private function mergeAlternativeValues(SummaryValue $left, SummaryValue $right): SummaryValue
    {
        $sanitizedFor = [];

        if ($left->sanitizedFor !== [] && $right->sanitizedFor !== []) {
            $sanitizedFor = $this->intersectContexts($left->sanitizedFor, $right->sanitizedFor);
        }

        return new SummaryValue(
            argIndexes: array_values(array_unique(array_merge($left->argIndexes, $right->argIndexes))),
            sanitizedFor: $sanitizedFor,
            taintedWithoutArgs: $left->taintedWithoutArgs || $right->taintedWithoutArgs,
            sourceLabel: $left->sourceLabel ?? $right->sourceLabel,
        );
    }

    /**
     * @param list<SecurityContext> $left
     * @param list<SecurityContext> $right
     * @return list<SecurityContext>
     */
    private function intersectContexts(array $left, array $right): array
    {
        $rightByValue = [];
        foreach ($right as $context) {
            $rightByValue[$context->value] = $context;
        }

        $intersection = [];
        foreach ($left as $context) {
            if (isset($rightByValue[$context->value])) {
                $intersection[$context->value] = $context;
            }
        }

        return array_values($intersection);
    }
}
