# DrupalSecurity

DrupalSecurity is a library for automated Drupal code security reviews. It
defines rules for [PHP_CodeSniffer](https://github.com/squizlabs/PHP_CodeSniffer)

Note that Javascript has not been supported yet. To check and fix Javascript files
please use [ESLint](http://eslint.org/) and see the
[Drupal ESLint](https://www.drupal.org/node/1955232) documentation.

## Global installation

First, install phpcs:

[PHP_CodeSniffe install](https://github.com/PHPCSStandards/PHP_CodeSniffer/?tab=readme-ov-file#installation)

To make the `phpcs` command available globally, add the Composer
bin path to your `$PATH` variable in `~/.profile`, `~/.bashrc` or `~/.zshrc`:

    export PATH="$PATH:$HOME/.config/composer/vendor/bin"

Second, install PHPCS plugins:
[Drupal coder](https://github.com/drupalprojects/coder#installation)
[PHPCSUtils](https://github.com/PHPCSStandards/PHPCSUtils)

Last, download the DrupalSecurity folder to your local

## Usage

Check Drupal Security standards

    phpcs --standard=/path/to/DrupalSecurity --extensions=php,module,inc,install,theme,yml,twig /file/to/drupal/module
