<?php

declare(strict_types=1);

namespace Bastet\Parsing;

final readonly class ParsedFile
{
    /**
     * @param list<\PhpParser\Node\Stmt> $statements
     */
    public function __construct(
        public string $filePath,
        public string $source,
        public array $statements,
    ) {}
}
