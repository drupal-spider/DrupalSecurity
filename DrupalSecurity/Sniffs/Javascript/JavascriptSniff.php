<?php

/**
 * \DrupalSecurity\Sniffs\Javascript\JavascriptSniff.
 *
 * @category PHP
 * @package PHP_CodeSniffer
 * @link http://pear.php.net/package/PHP_CodeSniffer
 */
namespace DrupalSecurity\Sniffs\Javascript;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Checks if there are potential security issue with twig
 * files.
 *
 *
 * @category PHP
 * @package PHP_CodeSniffer
 * @link http://pear.php.net/package/PHP_CodeSniffer
 */
class JavascriptSniff implements Sniff {

  /**
   * Returns an array of tokens this test wants to listen for.
   *
   * @return array<int|string>
   */
  public function register() {
    return [
      T_NOWDOC,
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
    $fileExtension = strtolower(substr($phpcsFile->getFilename(), -3));
    if ($fileExtension !== '.js') {
      return ($phpcsFile->numTokens + 1);
    }

    $content = $phpcsFile->getTokensAsString($stackPtr, 1);
    // Search for innerHTML.
    // The XSS attack via innerHTML property is quite common,
    // particularly from using for outputting data that could be user-entered.
    // @See https://dev.to/caffiendkitten/innerhtml-cross-site-scripting-agc
    if (strpos(str_replace(' ', '', $content), '.innerHTML=') !== false) {
      $warning = 'Setting the value of innerHTML detected.';
      $phpcsFile->addWarning($warning, $stackPtr, 'XssAttack');
    }

    // Search for script injection.
    if (strpos(str_replace(' ', '', strtolower($content)), 'script') !== false) {
      $warning = 'Potential script injection detected.';
      $phpcsFile->addWarning($warning, $stackPtr, 'CodeInjection');
    }
  }

  // end process()
}//end class
