<?php

declare(strict_types=1);

namespace Bastet\SecurityAst;

use Bastet\Parsing\ParsedFile;
use Bastet\SecurityAst\Expression\BinaryOperation;
use Bastet\SecurityAst\Expression\FunctionCall;
use Bastet\SecurityAst\Expression\LiteralValue;
use Bastet\SecurityAst\Expression\MethodCall;
use Bastet\SecurityAst\Expression\UnknownExpression;
use Bastet\SecurityAst\Expression\Variable;
use Bastet\SecurityAst\Statement\Assignment;
use Bastet\SecurityAst\Statement\ExpressionStatement;
use Bastet\SecurityAst\Statement\FunctionDefinition;
use Bastet\SecurityAst\Statement\IfStatement;
use Bastet\SecurityAst\Statement\ReturnStatement;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar;
use PhpParser\Node\Stmt;

final class AstNormalizer
{
    private int $idCounter = 0;

    public function normalize(ParsedFile $file): Program
    {
        $this->idCounter = 0;

        $statements = [];

        foreach ($file->statements as $statement) {
            $normalized = $this->normalizeStatement($statement, $file->filePath);

            if ($normalized !== null) {
                $statements[] = $normalized;
            }
        }

        return new Program(
            id: $this->nextId('program'),
            meta: new NodeMeta($file->filePath, 1),
            statements: $statements,
        );
    }

    private function normalizeStatement(Stmt $statement, string $filePath): ?Statement
    {
        $meta = $this->meta($statement, $filePath);

        if ($statement instanceof Stmt\Expression) {
            if ($statement->expr instanceof Expr\Assign) {
                $target = $this->normalizeVariableLike($statement->expr->var, $filePath);
                $value = $this->normalizeExpression($statement->expr->expr, $filePath);

                if ($target !== null && $value !== null) {
                    return new Assignment($this->nextId('assign'), $meta, $target, $value);
                }
            }

            $expression = $this->normalizeExpression($statement->expr, $filePath);

            return $expression === null
                ? null
                : new ExpressionStatement($this->nextId('expr_stmt'), $meta, $expression);
        }

        if ($statement instanceof Stmt\If_) {
            $condition = $this->normalizeExpression($statement->cond, $filePath);

            if ($condition === null) {
                return null;
            }

            $thenBlock = $this->normalizeStatementList($statement->stmts, $filePath);
            $elseBlock = [];

            if ($statement->else !== null) {
                $elseBlock = $this->normalizeStatementList($statement->else->stmts, $filePath);
            } elseif (! empty($statement->elseifs)) {
                foreach ($statement->elseifs as $elseif) {
                    $elseifNode = new IfStatement(
                        $this->nextId('if'),
                        $this->meta($elseif, $filePath),
                        $this->normalizeExpression($elseif->cond, $filePath) ?? new UnknownExpression(
                            $this->nextId('unknown'),
                            $this->meta($elseif, $filePath),
                            'elseif-condition',
                        ),
                        $this->normalizeStatementList($elseif->stmts, $filePath),
                        [],
                    );
                    $elseBlock[] = $elseifNode;
                }
            }

            return new IfStatement($this->nextId('if'), $meta, $condition, $thenBlock, $elseBlock);
        }

        if ($statement instanceof Stmt\Return_) {
            return new ReturnStatement(
                $this->nextId('return'),
                $meta,
                $statement->expr !== null ? $this->normalizeExpression($statement->expr, $filePath) : null,
            );
        }

        if ($statement instanceof Stmt\Function_) {
            $parameters = [];

            foreach ($statement->params as $param) {
                if ($param->var instanceof Expr\Variable && is_string($param->var->name)) {
                    $parameters[] = $param->var->name;
                }
            }

            return new FunctionDefinition(
                $this->nextId('function'),
                $meta,
                $statement->name->toString(),
                $parameters,
                $this->normalizeStatementList($statement->stmts, $filePath),
            );
        }

        if ($statement instanceof Stmt\Echo_) {
            $args = [];
            foreach ($statement->exprs as $expr) {
                $normalized = $this->normalizeExpression($expr, $filePath);
                if ($normalized !== null) {
                    $args[] = $normalized;
                }
            }

            return new ExpressionStatement(
                $this->nextId('expr_stmt'),
                $meta,
                new FunctionCall($this->nextId('call'), $meta, 'echo', $args),
            );
        }

        return null;
    }

    /**
     * @param list<Stmt> $statements
     * @return list<Statement>
     */
    private function normalizeStatementList(array $statements, string $filePath): array
    {
        $normalized = [];

        foreach ($statements as $statement) {
            $item = $this->normalizeStatement($statement, $filePath);
            if ($item !== null) {
                $normalized[] = $item;
            }
        }

        return $normalized;
    }

    private function normalizeExpression(Expr $expression, string $filePath): ?Expression
    {
        $meta = $this->meta($expression, $filePath);

        if ($expression instanceof Expr\Variable || $expression instanceof Expr\ArrayDimFetch) {
            return $this->normalizeVariableLike($expression, $filePath);
        }

        if ($expression instanceof Scalar\String_
            || $expression instanceof Scalar\LNumber
            || $expression instanceof Scalar\DNumber
        ) {
            $type = match (true) {
                $expression instanceof Scalar\String_ => 'string',
                $expression instanceof Scalar\LNumber => 'int',
                default => 'float',
            };

            return new LiteralValue($this->nextId('literal'), $meta, $expression->value, $type);
        }

        if ($expression instanceof Expr\ConstFetch) {
            $name = strtolower($expression->name->toString());
            return new LiteralValue(
                $this->nextId('literal'),
                $meta,
                match ($name) {
                    'true' => true,
                    'false' => false,
                    default => null,
                },
                match ($name) {
                    'true', 'false' => 'bool',
                    default => 'null',
                },
            );
        }

        if ($expression instanceof Expr\FuncCall) {
            $name = $expression->name instanceof Name
                ? strtolower($expression->name->toString())
                : 'unknown';

            return new FunctionCall(
                $this->nextId('call'),
                $meta,
                $name,
                $this->normalizeArgs($expression->args, $filePath),
            );
        }

        if ($expression instanceof Expr\MethodCall) {
            $object = $this->normalizeExpression($expression->var, $filePath);
            if ($object === null) {
                return null;
            }

            $method = $expression->name instanceof Node\Identifier
                ? strtolower($expression->name->toString())
                : 'unknown';

            return new MethodCall(
                $this->nextId('method_call'),
                $meta,
                $object,
                $method,
                $this->normalizeArgs($expression->args, $filePath),
            );
        }

        if ($expression instanceof Expr\StaticCall) {
            $class = $expression->class instanceof Name
                ? strtolower($expression->class->toString())
                : 'unknown';
            $method = $expression->name instanceof Node\Identifier
                ? strtolower($expression->name->toString())
                : 'unknown';

            return new FunctionCall(
                $this->nextId('call'),
                $meta,
                $class . '::' . $method,
                $this->normalizeArgs($expression->args, $filePath),
            );
        }

        if ($expression instanceof Expr\BinaryOp) {
            $left = $this->normalizeExpression($expression->left, $filePath);
            $right = $this->normalizeExpression($expression->right, $filePath);

            if ($left === null || $right === null) {
                return null;
            }

            return new BinaryOperation(
                $this->nextId('binop'),
                $meta,
                $left,
                $this->operatorName($expression),
                $right,
            );
        }

        if ($expression instanceof Expr\Include_) {
            $arg = $this->normalizeExpression($expression->expr, $filePath);

            if ($arg === null) {
                return null;
            }

            return new FunctionCall(
                $this->nextId('call'),
                $meta,
                match ($expression->type) {
                    Expr\Include_::TYPE_INCLUDE => 'include',
                    Expr\Include_::TYPE_INCLUDE_ONCE => 'include_once',
                    Expr\Include_::TYPE_REQUIRE => 'require',
                    Expr\Include_::TYPE_REQUIRE_ONCE => 'require_once',
                    default => 'include',
                },
                [$arg],
            );
        }

        if ($expression instanceof Expr\Print_) {
            $arg = $this->normalizeExpression($expression->expr, $filePath);
            if ($arg === null) {
                return null;
            }

            return new FunctionCall($this->nextId('call'), $meta, 'print', [$arg]);
        }

        if ($expression instanceof Expr\Cast\Int_) {
            $arg = $this->normalizeExpression($expression->expr, $filePath);
            if ($arg === null) {
                return null;
            }

            return new FunctionCall($this->nextId('call'), $meta, '(int)', [$arg]);
        }

        if ($expression instanceof Expr\Ternary) {
            if ($expression->if !== null) {
                return $this->normalizeExpression($expression->if, $filePath);
            }

            return $this->normalizeExpression($expression->else, $filePath);
        }

        return new UnknownExpression($this->nextId('unknown'), $meta, $expression::class);
    }

    /**
     * @param list<Arg> $args
     * @return list<Expression>
     */
    private function normalizeArgs(array $args, string $filePath): array
    {
        $normalized = [];

        foreach ($args as $arg) {
            $expression = $this->normalizeExpression($arg->value, $filePath);

            if ($expression !== null) {
                $normalized[] = $expression;
            }
        }

        return $normalized;
    }

    private function normalizeVariableLike(Expr $expr, string $filePath): ?Variable
    {
        $meta = $this->meta($expr, $filePath);

        if ($expr instanceof Expr\Variable && is_string($expr->name)) {
            $name = $expr->name;
            $isSuperglobal = in_array($name, ['_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES', '_SERVER'], true);

            return new Variable(
                $this->nextId('var'),
                $meta,
                $name,
                $isSuperglobal,
                $isSuperglobal ? '$' . $name : null,
            );
        }

        if ($expr instanceof Expr\ArrayDimFetch) {
            $root = $expr->var instanceof Expr ? $this->normalizeVariableLike($expr->var, $filePath) : null;

            if ($root === null) {
                return null;
            }

            $segment = $this->arrayDimToString($expr->dim);
            $path = $root->propertyPath ?? ('$' . $root->name);
            $path .= '[' . $segment . ']';

            return new Variable(
                $this->nextId('var'),
                $meta,
                $root->name,
                $root->isSuperglobal,
                $path,
            );
        }

        return null;
    }

    private function arrayDimToString(Node|null $dim): string
    {
        if ($dim instanceof Scalar\String_ || $dim instanceof Scalar\LNumber) {
            return (string) $dim->value;
        }

        if ($dim instanceof Expr\Variable && is_string($dim->name)) {
            return '$' . $dim->name;
        }

        return '?';
    }

    private function operatorName(Expr\BinaryOp $expr): string
    {
        return match (true) {
            $expr instanceof Expr\BinaryOp\Concat => '.',
            $expr instanceof Expr\BinaryOp\Plus => '+',
            $expr instanceof Expr\BinaryOp\Minus => '-',
            $expr instanceof Expr\BinaryOp\Mul => '*',
            $expr instanceof Expr\BinaryOp\Div => '/',
            $expr instanceof Expr\BinaryOp\BooleanAnd => '&&',
            $expr instanceof Expr\BinaryOp\BooleanOr => '||',
            $expr instanceof Expr\BinaryOp\Coalesce => '??',
            default => $expr::class,
        };
    }

    private function meta(Node $node, string $filePath): NodeMeta
    {
        return new NodeMeta($filePath, (int) $node->getStartLine());
    }

    private function nextId(string $prefix): string
    {
        $this->idCounter++;

        return $prefix . '_' . $this->idCounter;
    }
}
