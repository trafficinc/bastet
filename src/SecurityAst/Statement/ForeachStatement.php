<?php

declare(strict_types=1);

namespace Bastet\SecurityAst\Statement;

use Bastet\SecurityAst\Expression;
use Bastet\SecurityAst\NodeMeta;
use Bastet\SecurityAst\Statement;
use Bastet\SecurityAst\Expression\Variable;

final readonly class ForeachStatement extends Statement
{
    /**
     * @param list<Statement> $body
     */
    public function __construct(
        string $id,
        NodeMeta $meta,
        public Expression $iterable,
        public Variable $valueVariable,
        public ?Variable $keyVariable,
        public array $body,
    ) {
        parent::__construct($id, $meta);
    }
}
