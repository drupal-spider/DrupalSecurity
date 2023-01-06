<?php

/**
 * \DrupalSecurity\Sniffs\Database\SqlSniff
 *
 * @category PHP
 * @package PHP_CodeSniffer
 * @link http://pear.php.net/package/PHP_CodeSniffer
 */
namespace DrupalSecurity\Sniffs\Render;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Util\Tokens;

/**
 * Checks if there are potential vulnerability with Drupal render array.
 *
 *
 * @category PHP
 * @package PHP_CodeSniffer
 * @link http://pear.php.net/package/PHP_CodeSniffer
 */
class RenderSniff implements Sniff {

  /**
   * Returns an array of tokens this test wants to listen for.
   *
   * @return array<int|string>
   */
  public function register() {
    return [
      T_DOUBLE_ARROW
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
    $tokens = $phpcsFile->getTokens();
    $key_position = $phpcsFile->findPrevious(T_CONSTANT_ENCAPSED_STRING, $stackPtr - 1);
    // The key of a render array item.
    $key = \strtolower($tokens[$key_position]['content']);
    // Check if there is any inline template used.
    // There is a possibility of SSTI (Server Side Template Injection)
    // with inline template for a render array.
    // For example https://www.drupal.org/project/drupal/issues/3331205
    if ($key === "'#type'") {
      $value_position = $phpcsFile->findNext(T_CONSTANT_ENCAPSED_STRING, $key_position + 1);
      $value = \strtolower($tokens[$value_position]['content']);
      if ($value === "'inline_template'") {
        $message = 'Inline template found. Check for SSTI. For example https://www.drupal.org/project/drupal/issues/3331205';
        $phpcsFile->addWarning($message, $stackPtr, 'Render');
      }
    }
  }

}