<?php

declare(strict_types=1);

namespace Bastet\SecurityAst;

final readonly class NodeMeta
{
    public function __construct(
        public string $file,
        public int $line,
    ) {}
}
