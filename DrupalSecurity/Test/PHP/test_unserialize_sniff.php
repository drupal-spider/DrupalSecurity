<?php
// test_unserialize_sniff.php

class FileWriter
{
    public $file;
    public $data;

    public function __destruct()
    {
        // When the object is garbage-collected (end of request),
        // it will write $this->data to $this->file.
        file_put_contents($this->file, $this->data);
    }
}

$user_data = unserialize($_POST['data']);

$user_data = unserialize($_POST['data'], ['allowed_classes' => FALSE]);
