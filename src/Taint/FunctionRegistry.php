<?php

declare(strict_types=1);

namespace Bastet\Taint;

final class FunctionRegistry
{
    /** @var array<string, bool> */
    private array $sourceCalls = [
        'request::input' => true,
        'request::get' => true,
        'request::query' => true,
        'request::post' => true,
        'request::all' => true,
        'request::cookie' => true,
        'request::header' => true,
    ];

    /** @var array<string, list<SecurityContext>> */
    private array $sanitizers = [
        'htmlspecialchars' => [SecurityContext::Html],
        'e' => [SecurityContext::Html],
        'intval' => [SecurityContext::Sql, SecurityContext::Shell, SecurityContext::File],
        '(int)' => [SecurityContext::Sql, SecurityContext::Shell, SecurityContext::File],
        'basename' => [SecurityContext::File],
        'realpath' => [SecurityContext::File],
        'escapeshellarg' => [SecurityContext::Shell],
        'escapeshellcmd' => [SecurityContext::Shell],
    ];

    /** @var array<string, SecurityContext> */
    private array $sinkContexts = [
        'echo' => SecurityContext::Html,
        'print' => SecurityContext::Html,
        'exec' => SecurityContext::Shell,
        'shell_exec' => SecurityContext::Shell,
        'system' => SecurityContext::Shell,
        'passthru' => SecurityContext::Shell,
        'popen' => SecurityContext::Shell,
        'proc_open' => SecurityContext::Shell,
        'include' => SecurityContext::File,
        'include_once' => SecurityContext::File,
        'require' => SecurityContext::File,
        'require_once' => SecurityContext::File,
        'db::select' => SecurityContext::Sql,
        'db::statement' => SecurityContext::Sql,
        'db::insert' => SecurityContext::Sql,
        'db::update' => SecurityContext::Sql,
        'db::delete' => SecurityContext::Sql,
        'db::raw' => SecurityContext::Sql,
        'query' => SecurityContext::Sql,
        'exec_sql' => SecurityContext::Sql,
        'pdo::query' => SecurityContext::Sql,
        'pdo::exec' => SecurityContext::Sql,
        'mysqli::query' => SecurityContext::Sql,
        'mysqli::multi_query' => SecurityContext::Sql,
        'file_get_contents' => SecurityContext::File,
        'readfile' => SecurityContext::File,
        'fopen' => SecurityContext::File,
        'file_put_contents' => SecurityContext::File,
    ];

    /** @var array<string, FunctionSummary> */
    private array $summaries = [];

    public function isSanitizer(string $name): bool
    {
        return isset($this->sanitizers[$name]);
    }

    public function isSourceCall(string $name): bool
    {
        return isset($this->sourceCalls[$name]);
    }

    /**
     * @return list<SecurityContext>
     */
    public function sanitizerContexts(string $name): array
    {
        return $this->sanitizers[$name] ?? [];
    }

    public function sinkContext(string $name): ?SecurityContext
    {
        return $this->sinkContexts[$name] ?? null;
    }

    public function addSummary(string $name, FunctionSummary $summary): void
    {
        $this->summaries[strtolower($name)] = $summary;
    }

    public function summary(string $name): ?FunctionSummary
    {
        return $this->summaries[strtolower($name)] ?? null;
    }
}
