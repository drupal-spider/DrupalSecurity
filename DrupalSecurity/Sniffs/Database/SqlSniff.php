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
    'accessCheck' => true,
    'loadMultiple' => true,
    'loadByProperties' => true,
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
    $functionLc = $tokens[$stackPtr]['content'];
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
          $clean_content = \strtolower($parameters[3]['clean']);
          $clean_content = str_replace(["'", '"'], '', $clean_content);
          if ( $clean_content === "like") {
            if (\strpos($parameters[2]['clean'], '$') !== false) {
              $warning = 'A LIKE query contains dynamic variable. @see https://www.drupal.org/docs/security-in-drupal/writing-secure-code-for-drupal#s-use-the-database-abstraction-layer-to-avoid-sql-injection-attacks';
              $phpcsFile->addWarning($warning, $stackPtr, 'SQL');
            }
          }
          elseif (\strpos($clean_content, '$') !== false) {
            $warning = "Dynamic variable as a operator to a query's condition. @see https://www.drupal.org/docs/security-in-drupal/writing-secure-code-for-drupal#s-use-the-database-abstraction-layer-to-avoid-sql-injection-attacks";
            $phpcsFile->addError($warning, $stackPtr, 'SQL');
          }
        }
        break;
      case 'accessCheck':
        if (isset($parameters[1]) && \strtolower($parameters[1]['clean']) == 'false') {
          $warning = "Query without having access check. @see https://www.drupal.org/node/3201242";
          $phpcsFile->addWarning($warning, $stackPtr, 'Access check');
        }
        break;
      case 'loadMultiple':
        $warning = "loadMultiple() function detected. This function won't check access during loading. @see https://www.drupal.org/docs/drupal-apis/entity-api/working-with-the-entity-api#s-checking-if-a-user-account-has-access-to-an-entity-object";
        $phpcsFile->addWarning($warning, $stackPtr, 'Access check');
        break;
      case 'loadByProperties':
        $warning = "loadByProperties() function detected. This function won't check access during loading. @see https://www.drupal.org/docs/drupal-apis/entity-api/working-with-the-entity-api#s-checking-if-a-user-account-has-access-to-an-entity-object";
        $phpcsFile->addWarning($warning, $stackPtr, 'Access check');
        break;
    }
  }// end process()
}//end class
