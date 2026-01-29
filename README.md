# DrupalSecurity

DrupalSecurity is a library for automated Drupal code security reviews. It
defines rules for [PHP_CodeSniffer](https://github.com/squizlabs/PHP_CodeSniffer)

Note that Javascript has not been supported yet. To check and fix Javascript files
please use [ESLint](http://eslint.org/) and see the
[Drupal ESLint](https://www.drupal.org/node/1955232) documentation.

## Global installation
    composer global require "squizlabs/php_codesniffer=*"
    composer global require drupal-spider/drupalsecurity

  Make sure you have the composer bin dir in your PATH. The default value is ~/.composer/vendor/bin/, but you can check the value that you need to use by running 

    composer global config bin-dir --absolute

## Usage

Check Drupal Security standards

    phpcs --standard=DrupalSecurity  --ignore='*/tests/*' --extensions=php,module,inc,install,theme,yml,twig [/file/to/drupal/module]

List all sniffers

    phpcs --standard=DrupalSecurity -e


