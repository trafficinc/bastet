<?php

declare(strict_types=1);

namespace Bastet\SecurityAst;

abstract readonly class Node
{
    public function __construct(
        public string $id,
        public NodeMeta $meta,
    ) {}
}
