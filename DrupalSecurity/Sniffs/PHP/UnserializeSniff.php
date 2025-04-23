<?php

namespace DrupalSecurity\Sniffs\PHP;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Prohibits any direct call to PHP's unserialize() function.
 */
class UnserializeSniff implements Sniff
{
    /**
     * The function names this sniff forbids.
     *
     * @var string[]
     */
    public $forbidden = [
        'unserialize' => true,
    ];

    /**
     * {@inheritdoc}
     */
    public function register()
    {
        return [T_STRING];
    }

    /**
     * {@inheritdoc}
     */
    public function process(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        $name   = strtolower($tokens[$stackPtr]['content']);

        if (isset($this->forbidden[$name])) {
            // Locate the opening parenthesis of the function call.
            $openParen = $phpcsFile->findNext(T_OPEN_PARENTHESIS, $stackPtr);
            if ($openParen !== false && isset($tokens[$openParen]['parenthesis_closer'])) {
                $closeParen = $tokens[$openParen]['parenthesis_closer'];
                // Extract all tokens inside the parentheses.
                $callContent = '';
                for ($i = $openParen + 1; $i < $closeParen; $i++) {
                    $callContent .= $tokens[$i]['content'];
                }
                // If the allowed_classes => FALSE option is present, allow the call.
                if (preg_match("/['\"]allowed_classes['\"]\s*=>\s*FALSE/i", $callContent)) {
                    return;
                }
            }
            // Otherwise, emit an error.
            $phpcsFile->addError(
                sprintf('Calling %s() without forbidding class objects may lead to PHP Object Injection.', $name),
                $stackPtr,
                'ForbiddenUnserialize'
            );
        }
    }
}