<?php

use ZipArchive;
use ZipArchive as CustomZipArchive;
use Drupal\Core\Archiver\Zip as DrupalZip;

ZipArchive::extractTo('/tmp/harmful');

CustomZipArchive::extractTo('/tmp/harmful');

\ZipArchive::extractTo('/tmp/harmful');

ZipArchive::open('test.zip');

CustomZipArchive::open('test.zip');

\ZipArchive::open('test.zip');

$zip = new ZipArchive();
$zip->extractTo('/tmp/harmful');
$zip->open('test.zip');

$customZipObject = new CustomZipArchive();
$customZipObject->open('test.zip');

class ZipHolder {
    private $zip;

    public function run(): void {
        $this->zip = new ZipArchive();
        $this->zip->extractTo('/tmp/harmful');
        $this->zip->open('test.zip');
    }
}

class AliasZipHolder {
    private $zip;

    public function run(): void {
        $this->zip = new CustomZipArchive();
        $this->zip->open('test.zip');
    }
}

$drupalZip = new \Drupal\Core\Archiver\Zip('archive.zip');
$drupalZip->extract('/tmp/harmful');

$aliasDrupalZip = new DrupalZip('archive.zip');
$aliasDrupalZip->extract('/tmp/harmful');

class DrupalZipHolder {
    private $zip;

    public function run(): void {
        $this->zip = new DrupalZip('archive.zip');
        $this->zip->extract('/tmp/harmful');
    }
}

DrupalZip::extract('/tmp/harmful');

\Drupal\Core\Archiver\Zip::extract('/tmp/harmful');
