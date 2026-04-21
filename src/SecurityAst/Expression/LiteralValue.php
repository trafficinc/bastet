<?php

declare(strict_types=1);

namespace Bastet\SecurityAst\Expression;

use Bastet\SecurityAst\Expression;
use Bastet\SecurityAst\NodeMeta;

final readonly class LiteralValue extends Expression
{
    public function __construct(
        string $id,
        NodeMeta $meta,
        public string|int|float|bool|null $value,
        public string $type,
    ) {
        parent::__construct($id, $meta);
    }
}
