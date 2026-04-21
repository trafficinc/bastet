<?php

function safe_shell_arg($value)
{
    return escapeshellarg($value);
}

$command = safe_shell_arg($_GET['cmd']);
exec($command);
