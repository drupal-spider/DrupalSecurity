<?php

/**
 * \DrupalSecurity\Sniffs\Yaml\RoutingAccessSniff.
 *
 * @category PHP
 * @package PHP_CodeSniffer
 * @link http://pear.php.net/package/PHP_CodeSniffer
 */
namespace DrupalSecurity\Sniffs\Yaml;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;
use Symfony\Component\Yaml\Yaml;
use Symfony\Component\Yaml\Exception\ParseException;

/**
 * Checks if there are potential security issue in *.routing.yml
 * files.
 *
 *
 * @category Yaml
 * @package PHP_CodeSniffer
 * @link http://pear.php.net/package/PHP_CodeSniffer
 */
class RoutingAccessSniff implements Sniff {

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
    $tokens = $phpcsFile->getTokens();

    $fileExtension = strtolower(substr($phpcsFile->getFilename(), -12));
    if ($fileExtension !== '.routing.yml') {
      return ($phpcsFile->numTokens + 1);
    }

    $contents = file_get_contents($phpcsFile->getFilename());
    try {
      $info = Yaml::parse($contents);
    }
    catch (ParseException $e) {
      // If the YAML is invalid we ignore this file.
      return ($phpcsFile->numTokens + 1);
    }

    foreach ($tokens as $line_num => $token) {
      $key = explode(':', $token['content']);
      $rout_key = $key[0] ?? '';
      if ($rout = $info[$rout_key] ?? false) {
        // Audit requirements.
        if ($requirements = $rout['requirements'] ?? false) {
          if ($accesss = $requirements['_access'] ?? false) {
            // Search for _access: 'TRUE'
            if (is_string($accesss) && strtolower($accesss) === 'true') {
              $warning = "Open access to $rout_key found";
              $phpcsFile->addWarning($warning, $line_num, 'OpenAccess');
            }
          }
          elseif ($permission = $requirements['_permission'] ?? false) {
            // Search for 'administer site configuration' permission.
            // The "administer site configuration" permission is a very wide
            // permission,
            // which allows a user role to change configurations system-wide.
            // A route open to a content author or other non-admin role
            // should not require this permission to access.
            if (strtolower($permission) === 'administer site configuration') {
              $warning = "Wide permission required by $rout_key found";
              $phpcsFile->addWarning($warning, $line_num, 'WidePermissionFound');
            }

            // Search for 'access conten' permission.
            // 'access conten' is nomrally granted to anonymouse user.
            // This permission should not be used for a route
            // that performs actions or operations
            if (strtolower($permission) === 'access conten') {
              $warning = "Open access to $rout_key found";
              $phpcsFile->addWarning($warning, $line_num, 'OpenAccess');
            }
          }
          if (!isset($rout['defaults']['_form'])) {
            // Search for _csrf_token.
            if ($csrf_token = $requirements['_csrf_token'] ?? false) {
              if (!$csrf_token) {
                $warning = "_csrf_token is set to FALSE for $rout_key. @see https://www.drupal.org/node/3048359";
                $phpcsFile->addWarning($warning, $line_num, 'CsrfTokenDisable');
              }
            }
            else {
              $warning = "_csrf_token for $rout_key is missing. @see https://www.drupal.org/node/3048359";
              $phpcsFile->addWarning($warning, $line_num, 'CsrfTokenDisable');
            }
          }
        }
      }
    }

    return ($phpcsFile->numTokens + 1);
  }

  // end process()
}//end class
