<?php

if (rand(0, 1)) {
    $name = $_GET['name'];
} else {
    $name = 'guest';
}

echo $name;
