<?php

declare(strict_types=1);

namespace Bastet\Parsing;

final class PhpFileParser
{
    public function __construct(
        private readonly PhpParserFactory $factory = new PhpParserFactory(),
    ) {}

    public function canParse(): bool
    {
        return class_exists(\PhpParser\ParserFactory::class);
    }

    public function parseFile(string $filePath, string $source): ?ParsedFile
    {
        if (! $this->canParse()) {
            return null;
        }

        $parser = $this->factory->createParser();
        $errors = $this->factory->createErrorHandler();
        $ast = $parser->parse($source, $errors);

        if ($ast === null || $errors->hasErrors()) {
            return null;
        }

        $ast = $this->factory->createTraverser()->traverse($ast);

        return new ParsedFile(
            filePath: $filePath,
            source: $source,
            statements: $ast,
        );
    }
}
