<?php

declare(strict_types=1);

namespace Bastet\SecurityAst\Expression;

use Bastet\SecurityAst\Expression;
use Bastet\SecurityAst\NodeMeta;

final readonly class MethodCall extends Expression
{
    /**
     * @param list<Expression> $args
     */
    public function __construct(
        string $id,
        NodeMeta $meta,
        public Expression $object,
        public string $method,
        public array $args,
    ) {
        parent::__construct($id, $meta);
    }
}
