<?php

namespace DrupalSecurity\Sniffs\Field;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Warns when a FieldType plugin schema() definition uses 'serialize' => TRUE.
 */
class FieldTypeSerializeSniff implements Sniff
{
    /**
     * {@inheritdoc}
     */
    public function register()
    {
        return [T_CLASS];
    }

    /**
     * {@inheritdoc}
     */
    public function process(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();

        // Ensure this class extends FieldItemBase.
        $extendsPtr = $phpcsFile->findNext(T_EXTENDS, $stackPtr);
        if ($extendsPtr === false) {
            return;
        }
        $parentNamePtr = $phpcsFile->findNext(T_STRING, $extendsPtr + 1);
        if (strtolower($tokens[$parentNamePtr]['content']) !== 'fielditembase') {
            return;
        }

        // Locate the schema() method within this class.
        $classCloser = $tokens[$stackPtr]['scope_closer'];
        for ($i = $stackPtr; $i < $classCloser; $i++) {
            if ($tokens[$i]['code'] === T_FUNCTION) {
                $namePtr = $phpcsFile->findNext(T_STRING, $i + 1);
                if ($tokens[$namePtr]['content'] === 'schema') {
                    // Grab the body of schema() by using the function's scope pointers.
                    if (isset($tokens[$i]['scope_opener'], $tokens[$i]['scope_closer'])) {
                        $bodyStart = $tokens[$i]['scope_opener'];
                        $bodyEnd   = $tokens[$i]['scope_closer'];
                        $body      = '';
                        for ($j = $bodyStart; $j < $bodyEnd; $j++) {
                            $body .= $tokens[$j]['content'];
                        }
                        // If 'serialize' => TRUE appears, warn.
                        if (preg_match("/['\"]serialize['\"]\s*=>\s*TRUE/i", $body)) {
                            $phpcsFile->addWarning(
                                'FieldType schema() uses `serialize => TRUE`; this can expose PHP object injection risks.',
                                $i,
                                'FieldTypeSerialize'
                            );
                        }
                    }
                    return;
                }
            }
        }
    }
}