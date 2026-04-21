<?php

declare(strict_types=1);

namespace Bastet\SecurityAst\Expression;

use Bastet\SecurityAst\Expression;
use Bastet\SecurityAst\NodeMeta;

final readonly class ConditionalExpression extends Expression
{
    public function __construct(
        string $id,
        NodeMeta $meta,
        public Expression $condition,
        public ?Expression $ifTrue,
        public Expression $ifFalse,
    ) {
        parent::__construct($id, $meta);
    }
}
