<?php

declare(strict_types=1);

namespace Bastet\SecurityAst\Expression;

use Bastet\SecurityAst\Expression;
use Bastet\SecurityAst\NodeMeta;

final readonly class FunctionCall extends Expression
{
    /**
     * @param list<Expression> $args
     */
    public function __construct(
        string $id,
        NodeMeta $meta,
        public string $name,
        public array $args,
    ) {
        parent::__construct($id, $meta);
    }
}
