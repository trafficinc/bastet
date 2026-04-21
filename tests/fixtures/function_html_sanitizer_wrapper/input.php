<?php

function escape_html($value)
{
    $escaped = htmlspecialchars($value);

    return $escaped;
}

$name = escape_html($_GET['name']);
echo $name;
