<?php

/**
 * \DrupalSecurity\Sniffs\Yaml\ViewAccessSniff.
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
 * Checks if there are potential security issue in views.view.*.yml
 * files.
 *
 *
 * @category Yaml
 * @package PHP_CodeSniffer
 * @link http://pear.php.net/package/PHP_CodeSniffer
 */
class ViewAccessSniff implements Sniff {

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
    $lines = $phpcsFile->getTokens();

    $fileExtension = strtolower(substr($phpcsFile->getFilename(), -3));
    $fileNameStartWith = strtolower(substr(basename($phpcsFile->getFilename()), 0, 11));
    if ($fileExtension !== 'yml' || $fileNameStartWith !== 'views.view.') {
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

    if (!isset($info['display'])) {
      return ($phpcsFile->numTokens + 1);
    }
    // Start checking open access to a view.
    foreach ($info['display'] as $display_name => $display_properties) {
      if (isset($display_properties['display_options']['access']['type'])) {
        $access_setting = $display_properties['display_options']['access'];
        // Check unrestricted access.
        if (strtolower(trim($access_setting['type'])) === 'none') {
          $warning = "Open access to $display_name display found";
          $line_num = $this->getTheLineNumber($display_name, $lines);
          $phpcsFile->addWarning($warning, $line_num ?: 0, 'OpenAccess');
        }
        // Check 'View published content' permission.
        elseif (strtolower(trim($access_setting['type'])) === 'perm') {
          if (isset($access_setting['options']['perm']) && strtolower(trim($access_setting['options']['perm'])) === 'access content')
          {
            $warning = "Open access to $display_name display found";
            $line_num = $this->getTheLineNumber($display_name, $lines);
            $phpcsFile->addWarning($warning, $line_num, 'OpenAccess');
          }
        }
        // Check anonymous role access.
        elseif (strtolower(trim($access_setting['type'])) === 'role') {
          if (isset($access_setting['options']['role']))
          {
            if (is_array($access_setting['options']['role']) && array_key_exists('anonymous', $access_setting['options']['role'])) {
              $warning = "Open access to $display_name display found";
              $line_num = $this->getTheLineNumber($display_name, $lines);
              $phpcsFile->addWarning($warning, $line_num, 'OpenAccess');
            }
          }
        }
      }
    }

    return ($phpcsFile->numTokens + 1);
  }

  /**
   * Get the line number of the display options.
   *
   * @param string $displayName
   * @param array $lines
   * @return int|boolean
   *   Return the line number if the display option line found,
   *   otherwise return false.
   */
  private function getTheLineNumber(string $displayName, array $lines) {
    $found_display = false;
    $found_display_section = false;
    $display_options_start = 0;
    foreach ($lines as $line_num => $line) {
      if ($found_display) {
        if ($display_options_start) {
          $key = explode(':', $line['content']);
          $property_name = $key[0] ?? '';
          if (strtolower(trim($property_name)) === 'access') {
            return $line_num;
          }
        }
        else {
          $key = explode(':', $line['content']);
          $property_name = $key[0] ?? '';
          if (strtolower(trim($property_name)) === 'display_options') {
            $display_options_start = $line_num;
          }
        }
      }
      elseif ($found_display_section) {
        $key = explode(':', $line['content']);
        $property_name = $key[0] ?? '';
        if (strtolower(trim($property_name)) === $displayName) {
          $found_display = $line_num;
        }
      }
      else {
        $key = explode(':', $line['content']);
        $property_name = $key[0] ?? '';
        if ($property_name === 'display') {
          $found_display_section = $line_num;
        }
      }
    }

    return false;
  }
}