<?php

/**
 * \DrupalSecurity\Sniffs\Theme\TwigTemplateSniff.
 *
 * @category PHP
 * @package PHP_CodeSniffer
 * @link http://pear.php.net/package/PHP_CodeSniffer
 */
namespace DrupalSecurity\Sniffs\Theme;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Checks if there are potential security issue with twig
 * files.
 *
 *
 * @category Twig
 * @package PHP_CodeSniffer
 * @link http://pear.php.net/package/PHP_CodeSniffer
 */
class TwigTemplateSniff implements Sniff {

  /**
   * Returns an array of tokens this test wants to listen for.
   *
   * @return array<int|string>
   */
  public function register() {
    return [
      T_INLINE_HTML
    ];
  }

  // end register()

  /**
   * Processes this test, when one of its tokens is encountered.
   *
   * @param \PHP_CodeSniffer\Files\File $phpcsFile
   *        The current file being processed.
   * @param int $stackPtr
   *        The position of the current token
   *        in the stack passed in $tokens.
   *
   * @return void|int
   */
  public function process(File $phpcsFile, $stackPtr) {
    $fileExtension = strtolower(substr($phpcsFile->getFilename(), -5));
    if ($fileExtension !== '.twig') {
      return ($phpcsFile->numTokens + 1);
    }

    $content = $phpcsFile->getTokensAsString($stackPtr, 1);
    // Remove white space and make content lowercase.
    $content = str_replace(' ', '', strtolower($content));
    // Search for the raw filter.
    // The raw filter does not escape output,
    // which should be avoided whenever possible,
    // particularly from using for outputting data that could be user-entered.
    // @See https://www.drupal.org/node/2357633#raw
    if (strpos($content, '|raw') !== false) {
      $error = 'The raw filter should be avoided whenever possible.';
      $phpcsFile->addError($error, $stackPtr, 'UnsafeFilterFound');
    }

    // Search for unsafe attributes in a Twig template file.
    // @see https://www.drupal.org/docs/security-in-drupal/writing-secure-code-for-drupal#s-use-twig-templates
    if (strpos($content, '={{') !== false) {
      $error = 'rendering attributes in Twig should be wrapped with double or single quotes. @see https://www.drupal.org/docs/security-in-drupal/writing-secure-code-for-drupal#s-use-twig-templates';
      $phpcsFile->addError($error, $stackPtr, 'UnsafeTwigTemplate');
    }
  }

  // end process()
}//end class
