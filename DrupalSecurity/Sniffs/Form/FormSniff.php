<?php

/**
 * \DrupalSecurity\Sniffs\Form\FormSniff.
 *
 * @category PHP
 * @package PHP_CodeSniffer
 * @link http://pear.php.net/package/PHP_CodeSniffer
 */
namespace DrupalSecurity\Sniffs\Form;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Checks if there are potential security issue with Drupal form.
 *
 *
 * @category PHP
 * @package PHP_CodeSniffer
 * @link http://pear.php.net/package/PHP_CodeSniffer
 */
class FormSniff implements Sniff {

  /**
   * Returns an array of tokens this test wants to listen for.
   *
   * @return array<int|string>
   */
  public function register() {
    return [
      T_VARIABLE
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
    $content = $phpcsFile->getTokensAsString($stackPtr, 5);
    // Search FormState::getUserInput(), which returns
    // raw and unvalidated data entered by user.
    // This is a potential security risk of injection attack.
    // @see https://api.drupal.org/api/drupal/core%21lib%21Drupal%21Core%21Form%21FormState.php/function/FormState%3A%3AgetUserInput/10.0.x
    if (strpos($content, 'getUserInput(') !== false) {
      $warning = 'FormState::getUserInput() Detected.';
      $phpcsFile->addWarning($warning, $stackPtr, 'Form');
    }
  }

  // end process()
}//end class
