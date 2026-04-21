<?php

declare(strict_types=1);

namespace Bastet\Core;

final readonly class Finding
{
    public function __construct(
        public Severity $severity,
        public string   $title,
        public string   $file,
        public int      $line,
        public string   $snippet,
        public string   $explanation,
        public string   $remediation,
        public float    $confidence,
        public string   $ruleId,
        public array    $details = [],
    ) {}

    public function toArray(): array
    {
        return [
            'severity'    => $this->severity->value,
            'title'       => $this->title,
            'file'        => $this->file,
            'line'        => $this->line,
            'snippet'     => $this->snippet,
            'explanation' => $this->explanation,
            'remediation' => $this->remediation,
            'confidence'  => $this->confidence,
            'rule_id'     => $this->ruleId,
            'details'     => $this->details,
        ];
    }
}
