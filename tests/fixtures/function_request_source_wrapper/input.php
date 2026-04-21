<?php

function load_name($request)
{
    $value = $request->input('name');

    return $value;
}

$name = load_name($request);
echo $name;
