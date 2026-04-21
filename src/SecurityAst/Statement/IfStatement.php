<?php

declare(strict_types=1);

namespace Bastet\SecurityAst\Statement;

use Bastet\SecurityAst\Expression;
use Bastet\SecurityAst\NodeMeta;
use Bastet\SecurityAst\Statement;

final readonly class IfStatement extends Statement
{
    /**
     * @param list<Statement> $thenBlock
     * @param list<Statement> $elseBlock
     */
    public function __construct(
        string $id,
        NodeMeta $meta,
        public Expression $condition,
        public array $thenBlock,
        public array $elseBlock,
    ) {
        parent::__construct($id, $meta);
    }
}
