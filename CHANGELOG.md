# Change Log for drupal-spider/drupalsecurity

All notable changes to this project will be documented in this file.

This projects adheres to [Keep a CHANGELOG](https://keepachangelog.com/) and uses [Semantic Versioning](https://semver.org/).

## [1.2.3]

### Add

- #### Added `ZipExtractSniff` to warn about risky uses of `ZipArchive::extractTo()`, `ZipArchive::open()`, and `Drupal\\Core\\Archiver\\Zip::extract()`.

## [1.2.2]

### Add

- #### A new sniff for auditing PHP unserialize() vulnerability.

- #### A new sniff for auditing FieldType plugin.

## [1.2.1]

### Add

#### A new sniff for auditing cache poisoning vulnerability.

## [1.2.0]

### Change

#### Now, you can install this tool via a single composer command.

## [1.1.1]

### Update

#### Fix the dependency name in composer.json file.

## [1.1.0]

### Add

#### A new sniff for checking the access to a Drupal view.
