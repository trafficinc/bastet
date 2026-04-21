<?php

$items = htmlspecialchars($_GET['names']);

foreach ($items as $name) {
    echo $name;
}
