<?php

declare(strict_types=1);

namespace Bastet\SecurityAst;

final readonly class Program extends Node
{
    /**
     * @param list<Statement> $statements
     */
    public function __construct(
        string $id,
        NodeMeta $meta,
        public array $statements,
    ) {
        parent::__construct($id, $meta);
    }
}
