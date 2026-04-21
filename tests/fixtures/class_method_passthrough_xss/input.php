<?php

class UserController
{
    public function passthrough($value)
    {
        return $value;
    }

    public function show()
    {
        $name = $this->passthrough($_GET['name']);
        echo $name;
    }
}
