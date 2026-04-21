<?php

declare(strict_types=1);

namespace Bastet\Taint;

enum SecurityContext: string
{
    case Generic = 'generic';
    case Html = 'html';
    case Sql = 'sql';
    case Shell = 'shell';
    case File = 'file';
}
