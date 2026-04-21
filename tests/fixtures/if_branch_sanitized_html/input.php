<?php

if (rand(0, 1)) {
    $name = htmlspecialchars($_GET['name']);
} else {
    $name = htmlspecialchars($_POST['name']);
}

echo $name;
