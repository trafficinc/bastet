<?php

declare(strict_types=1);

namespace Bastet\SecurityAst\Statement;

use Bastet\SecurityAst\NodeMeta;
use Bastet\SecurityAst\Statement;

final readonly class FunctionDefinition extends Statement
{
    /**
     * @param list<string> $parameters
     * @param list<Statement> $body
     */
    public function __construct(
        string $id,
        NodeMeta $meta,
        public string $name,
        public array $parameters,
        public array $body,
    ) {
        parent::__construct($id, $meta);
    }
}
