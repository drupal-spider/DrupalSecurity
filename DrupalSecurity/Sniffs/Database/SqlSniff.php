<?php

/**
 * \DrupalSecurity\Sniffs\Database\SqlSniff
 *
 * @category PHP
 * @package PHP_CodeSniffer
 * @link http://pear.php.net/package/PHP_CodeSniffer
 */
namespace DrupalSecurity\Sniffs\Database;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Util\Tokens;
use PHPCSUtils\Utils\PassedParameters;

/**
 * Checks if there are potential SQL injections with Drupal database query.
 *
 *
 * @category PHP
 * @package PHP_CodeSniffer
 * @link http://pear.php.net/package/PHP_CodeSniffer
 */
class SqlSniff implements Sniff {

  /**
   * The target functions for this sniff.
   *
   * @var array
   */
  protected $targetFunctions = [
    'query' => true,
    'condition' => true,
  ];

  /**
   * Returns an array of tokens this test wants to listen for.
   *
   * @return array<int|string>
   */
  public function register() {
    return [\T_STRING];
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
    $tokens     = $phpcsFile->getTokens();
    $functionLc = \strtolower($tokens[$stackPtr]['content']);
    if (isset($this->targetFunctions[$functionLc]) === false) {
      return;
    }

    // Next non-empty token should be the open parenthesis.
    $nextNonEmpty = $phpcsFile->findNext(Tokens::$emptyTokens, ($stackPtr + 1), null, true, null, true);
    if ($nextNonEmpty === false || $tokens[$nextNonEmpty]['code'] !== \T_OPEN_PARENTHESIS) {
      return;
    }

    $parameters = PassedParameters::getParameters($phpcsFile, $stackPtr);

    switch ($functionLc) {
      case 'query':
        if (!isset($parameters[2])) {
          $warning = 'Concatenate data directly into SQL queries. @see https://www.drupal.org/docs/security-in-drupal/writing-secure-code-for-drupal#s-use-the-database-abstraction-layer-to-avoid-sql-injection-attacks';
          $phpcsFile->addError($warning, $stackPtr, 'SQL');
        }
        break;
      case 'condition':
        if (isset($parameters[3])) {
          if (\strtolower($parameters[3]['clean']) === "'like'") {
            if (\strpos($parameters[2]['clean'], '$') !== false) {
              $warning = 'A LIKE query contains dynamic variable. @see https://www.drupal.org/docs/security-in-drupal/writing-secure-code-for-drupal#s-use-the-database-abstraction-layer-to-avoid-sql-injection-attacks';
              $phpcsFile->addError($warning, $stackPtr, 'SQL');
            }
          }
          elseif (\strpos($parameters[3]['clean'], '$') !== false) {
            $warning = "Dynamic variable as a operator to a query's condition. @see https://www.drupal.org/docs/security-in-drupal/writing-secure-code-for-drupal#s-use-the-database-abstraction-layer-to-avoid-sql-injection-attacks";
            $phpcsFile->addError($warning, $stackPtr, 'SQL');
          }
        }
        break;
    }
  }// end process()
}//end class
