<?php

class UserController
{
    public function escape($value)
    {
        return htmlspecialchars($value);
    }

    public function show()
    {
        $name = $this->escape($_GET['name']);
        echo $name;
    }
}
