<?php

$name = isset($_GET['name'])
    ? htmlspecialchars($_GET['name'])
    : htmlspecialchars($_POST['name']);
echo $name;
