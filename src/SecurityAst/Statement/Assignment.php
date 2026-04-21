<?php

declare(strict_types=1);

namespace Bastet\SecurityAst\Statement;

use Bastet\SecurityAst\Expression;
use Bastet\SecurityAst\NodeMeta;
use Bastet\SecurityAst\Statement;
use Bastet\SecurityAst\Expression\Variable;

final readonly class Assignment extends Statement
{
    public function __construct(
        string $id,
        NodeMeta $meta,
        public Variable $target,
        public Expression $value,
    ) {
        parent::__construct($id, $meta);
    }
}
