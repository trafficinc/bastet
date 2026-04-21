<?php

declare(strict_types=1);

namespace Bastet\SecurityAst\Expression;

use Bastet\SecurityAst\Expression;
use Bastet\SecurityAst\NodeMeta;

final readonly class BinaryOperation extends Expression
{
    public function __construct(
        string $id,
        NodeMeta $meta,
        public Expression $left,
        public string $operator,
        public Expression $right,
    ) {
        parent::__construct($id, $meta);
    }
}
