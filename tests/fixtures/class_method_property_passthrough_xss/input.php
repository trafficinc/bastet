<?php

class UserController
{
    public function stash($value)
    {
        $this->name = $value;

        return $this->name;
    }

    public function show()
    {
        $name = $this->stash($_GET['name']);
        echo $name;
    }
}
