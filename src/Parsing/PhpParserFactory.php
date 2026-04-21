<?php

declare(strict_types=1);

namespace Bastet\Parsing;

use PhpParser\ErrorHandler\Collecting;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\ParentConnectingVisitor;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\Parser;
use PhpParser\ParserFactory;

final class PhpParserFactory
{
    public function createParser(): Parser
    {
        return (new ParserFactory())->createForNewestSupportedVersion();
    }

    public function createErrorHandler(): Collecting
    {
        return new Collecting();
    }

    public function createTraverser(): NodeTraverser
    {
        $traverser = new NodeTraverser();
        $traverser->addVisitor(new ParentConnectingVisitor());
        $traverser->addVisitor(new NameResolver());

        return $traverser;
    }
}
