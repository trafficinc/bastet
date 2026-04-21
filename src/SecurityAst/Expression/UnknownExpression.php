<?php

declare(strict_types=1);

namespace Bastet\SecurityAst\Expression;

use Bastet\SecurityAst\Expression;
use Bastet\SecurityAst\NodeMeta;

final readonly class UnknownExpression extends Expression
{
    public function __construct(
        string $id,
        NodeMeta $meta,
        public string $label,
    ) {
        parent::__construct($id, $meta);
    }
}
