<?php

function passthrough($value)
{
    $local = $value;

    return $local;
}

$name = passthrough($_GET['name']);
echo $name;
