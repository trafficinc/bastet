<?php

declare(strict_types=1);

namespace Bastet\SecurityAst\Expression;

use Bastet\SecurityAst\Expression;
use Bastet\SecurityAst\NodeMeta;

final readonly class Variable extends Expression
{
    public function __construct(
        string $id,
        NodeMeta $meta,
        public string $name,
        public bool $isSuperglobal = false,
        public ?string $propertyPath = null,
    ) {
        parent::__construct($id, $meta);
    }
}
