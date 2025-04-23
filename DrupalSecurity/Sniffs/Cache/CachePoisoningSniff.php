<?php

namespace DrupalSecurity\Sniffs\Cache;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

class CachePoisoningSniff implements Sniff
{
    public function register()
    {
        return [T_DOUBLE_COLON];
    }

    public function process(File $phpcsFile, $stackPtr)
    {

        // Only analyze PHP, .module, .inc and .install files.
        $filename = $phpcsFile->getFilename();
        $ext = pathinfo($filename, PATHINFO_EXTENSION);
        if (!in_array($ext, ['php', 'module', 'install', 'inc'], true)) {
            return ($phpcsFile->numTokens + 1);
        }
        
        $tokens = $phpcsFile->getTokens();


        // Check for AccessResult::allowed or ::forbidden
        $prev = $phpcsFile->findPrevious([T_STRING], $stackPtr - 1, null, false, 'AccessResult');
        if ($prev === false) {
            return;
        }
        $const = $phpcsFile->findNext([T_STRING], $stackPtr + 1, null, false);
        if (!in_array($tokens[$const]['content'], ['allowed', 'forbidden'], true)) {
            return;
        }

        // Find end of statement
        $semicolon = $phpcsFile->findNext(T_SEMICOLON, $stackPtr);
        if ($semicolon === false) {
            return;
        }

        // Extract code between the method and semicolon
        $content = '';
        for ($i = $const; $i < $semicolon; $i++) {
            $content .= $tokens[$i]['content'];
        }

        // Flag if no cacheability methods are present
        if (stripos($content, 'addCacheableDependency') === false
            && stripos($content, 'addCacheContexts') === false
            && stripos($content, 'addCacheTags') === false
            && stripos($content, 'cachePerPermissions') === false
            && stripos($content, 'setCacheMaxAge') === false
        ) {
            $error = 'AccessResult::%s() without cacheability metadata may enable cache poisoning. Found "%s".';
            $phpcsFile->addWarning(
                sprintf($error, $tokens[$const]['content'], trim($content)),
                $stackPtr,
                'MissingCacheMetadata'
            );
        }
    }
}