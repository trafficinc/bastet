<?php

declare(strict_types=1);

namespace Bastet\SecurityAst\Statement;

use Bastet\SecurityAst\Expression;
use Bastet\SecurityAst\NodeMeta;
use Bastet\SecurityAst\Statement;

final readonly class ExpressionStatement extends Statement
{
    public function __construct(
        string $id,
        NodeMeta $meta,
        public Expression $expression,
    ) {
        parent::__construct($id, $meta);
    }
}
