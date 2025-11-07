<?php

namespace DrupalSecurity\Sniffs\PHP;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Util\Tokens;
use PHPCSUtils\Utils\UseStatements;

/**
 * Flags risky archive extraction APIs.
 */
class ZipExtractSniff implements Sniff
{
    private const TARGETS = [
        'ziparchive' => [
            'fqn' => 'ZipArchive',
            'short' => 'ZipArchive',
            'methods' => [
                'extractto' => [
                    'name' => 'extractTo',
                    'message' => 'ZipArchive::extractTo() may introduce Zip Slip vulnerabilities when handling untrusted archives.',
                    'code' => 'ZipArchiveExtractTo',
                ],
                'open' => [
                    'name' => 'open',
                    'message' => 'ZipArchive::open() may expose untrusted archives; validate the source before extracting.',
                    'code' => 'ZipArchiveOpen',
                ],
            ],
        ],
        'drupal\\core\\archiver\\zip' => [
            'fqn' => 'Drupal\\Core\\Archiver\\Zip',
            'short' => 'Zip',
            'methods' => [
                'extract' => [
                    'name' => 'extract',
                    'message' => 'Drupal\\Core\\Archiver\\Zip::extract() may introduce Zip Slip vulnerabilities when handling untrusted archives.',
                    'code' => 'DrupalZipExtract',
                ],
            ],
        ],
    ];

    /**
     * Cache of aliases per target per file.
     *
     * @var array<string, array<string, array<int, string>>>
     */
    private $aliasCache = [];

    /**
     * Cache of variable/property names per target per file.
     *
     * @var array<string, array<string, array{variables: string[], properties: string[]}>>
     */
    private $variableCache = [];

    /**
     * Cache of import use statements per file.
     *
     * @var array<string, array<string, array<string, string>>>
     */
    private $importsCache = [];

    /**
     * {@inheritdoc}
     */
    public function register()
    {
        return [T_DOUBLE_COLON, T_OBJECT_OPERATOR];
    }

    /**
     * {@inheritdoc}
     */
    public function process(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        if ($tokens[$stackPtr]['code'] === T_DOUBLE_COLON) {
            $this->processStaticCall($phpcsFile, $stackPtr);
            return;
        }

        $this->processObjectCall($phpcsFile, $stackPtr);
    }

    private function processStaticCall(File $phpcsFile, int $stackPtr): void
    {
        $tokens = $phpcsFile->getTokens();
        $className = $this->getClassName($phpcsFile, $stackPtr);
        if ($className === '') {
            return;
        }

        $targetKey = $this->identifyTarget($phpcsFile, $className);
        if ($targetKey === null) {
            return;
        }

        $config = self::TARGETS[$targetKey];
        $methodPtr = $phpcsFile->findNext(T_STRING, $stackPtr + 1, null, false);
        if ($methodPtr === false) {
            return;
        }

        $methodConfig = $this->getMethodConfig($config, $tokens[$methodPtr]['content']);
        if ($methodConfig === null) {
            return;
        }

        $this->addExtractWarning($phpcsFile, $methodPtr, $methodConfig);
    }

    private function processObjectCall(File $phpcsFile, int $stackPtr): void
    {
        $tokens = $phpcsFile->getTokens();
        $methodPtr = $phpcsFile->findNext(Tokens::$emptyTokens, $stackPtr + 1, null, true);
        if ($methodPtr === false || $tokens[$methodPtr]['code'] !== T_STRING) {
            return;
        }

        $methodName = $tokens[$methodPtr]['content'];
        foreach (self::TARGETS as $targetKey => $config) {
            $methodConfig = $this->getMethodConfig($config, $methodName);
            if ($methodConfig === null) {
                continue;
            }

            if ($this->isTargetVariable($phpcsFile, $stackPtr, $targetKey)) {
                $this->addExtractWarning($phpcsFile, $methodPtr, $methodConfig);
                break;
            }
        }
    }

    private function addExtractWarning(File $phpcsFile, int $methodPtr, array $methodConfig): void
    {
        $phpcsFile->addWarning($methodConfig['message'], $methodPtr, $methodConfig['code']);
    }

    private function getClassName(File $phpcsFile, int $stackPtr): string
    {
        $tokens = $phpcsFile->getTokens();
        $ptr = $stackPtr - 1;
        $parts = [];
        while ($ptr >= 0 && in_array($tokens[$ptr]['code'], [T_STRING, T_NS_SEPARATOR], true)) {
            array_unshift($parts, $tokens[$ptr]['content']);
            $ptr--;
        }

        return implode('', $parts);
    }

    private function identifyTarget(File $phpcsFile, string $className): ?string
    {
        $normalized = ltrim(strtolower($className), '\\');
        if (isset(self::TARGETS[$normalized])) {
            return $normalized;
        }

        if (strpos($normalized, '\\') !== false) {
            return null;
        }

        $shortName = ltrim($className, '\\');
        foreach (self::TARGETS as $targetKey => $config) {
            foreach ($this->getTargetAliases($phpcsFile, $targetKey) as $alias) {
                if (strcasecmp($alias, $shortName) === 0) {
                    return $targetKey;
                }
            }
        }

        return null;
    }

    private function getMethodConfig(array $targetConfig, string $methodName): ?array
    {
        $methodName = strtolower($methodName);
        if (!isset($targetConfig['methods'][$methodName])) {
            return null;
        }

        return $targetConfig['methods'][$methodName];
    }

    /**
     * @return array<int, string>
     */
    private function getTargetAliases(File $phpcsFile, string $targetKey): array
    {
        $filename = $phpcsFile->getFilename();
        if (isset($this->aliasCache[$targetKey][$filename])) {
            return $this->aliasCache[$targetKey][$filename];
        }

        $config   = self::TARGETS[$targetKey];
        $aliases  = [$config['short'], ltrim($config['fqn'], '\\')];
        $imports  = $this->getImportUseStatements($phpcsFile);
        $fqnLower = strtolower(ltrim($config['fqn'], '\\'));

        foreach ($imports['name'] as $alias => $importedClass) {
            if (strtolower(ltrim($importedClass, '\\')) === $fqnLower) {
                $aliases[] = $alias;
            }
        }

        $this->aliasCache[$targetKey][$filename] = array_values(array_unique($aliases, SORT_STRING));
        return $this->aliasCache[$targetKey][$filename];
    }

    /**
     * @return array{variables: string[], properties: string[]}
     */
    private function getTargetVariables(File $phpcsFile, string $targetKey): array
    {
        $filename = $phpcsFile->getFilename();
        if (isset($this->variableCache[$targetKey][$filename])) {
            return $this->variableCache[$targetKey][$filename];
        }

        $defaults = ['variables' => [], 'properties' => []];
        $config = self::TARGETS[$targetKey];
        $classNames = array_map('strtolower', $this->buildClassNameAlternatives($phpcsFile, $targetKey, $config['fqn']));

        $contents = @file_get_contents($filename);
        if ($contents === false) {
            $this->variableCache[$targetKey][$filename] = $defaults;
            return $defaults;
        }

        $variables = [];
        $variablePattern = '/\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+(\\\\?[A-Za-z_\\\\][A-Za-z0-9_\\\\]*)/i';
        if (preg_match_all($variablePattern, $contents, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $class = strtolower(ltrim($match[2], '\\'));
                if (in_array($class, $classNames, true)) {
                    $variables[] = strtolower($match[1]);
                }
            }
            $variables = array_values(array_unique($variables));
        }

        $properties = [];
        $propertyPattern = '/\$this->([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+(\\\\?[A-Za-z_\\\\][A-Za-z0-9_\\\\]*)/i';
        if (preg_match_all($propertyPattern, $contents, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $class = strtolower(ltrim($match[2], '\\'));
                if (in_array($class, $classNames, true)) {
                    $properties[] = strtolower($match[1]);
                }
            }
            $properties = array_values(array_unique($properties));
        }

        return $this->variableCache[$targetKey][$filename] = [
            'variables' => $variables,
            'properties' => $properties,
        ];
    }

    /**
     * @return array<int, string>
     */
    private function buildClassNameAlternatives(File $phpcsFile, string $targetKey, string $fqn): array
    {
        $names = [ltrim($fqn, '\\')];
        foreach ($this->getTargetAliases($phpcsFile, $targetKey) as $alias) {
            $names[] = ltrim($alias, '\\');
        }

        return array_values(array_unique($names, SORT_STRING));
    }

    private function getImportUseStatements(File $phpcsFile): array
    {
        $filename = $phpcsFile->getFilename();
        if (isset($this->importsCache[$filename])) {
            return $this->importsCache[$filename];
        }

        $useStatements = [
            'name'     => [],
            'function' => [],
            'const'    => [],
        ];

        $stackPtr = 0;
        while (($stackPtr = $phpcsFile->findNext(T_USE, $stackPtr)) !== false) {
            try {
                if (UseStatements::isImportUse($phpcsFile, $stackPtr) === false) {
                    $stackPtr++;
                    continue;
                }
            } catch (\Throwable $throwable) {
                $stackPtr++;
                continue;
            }

            $useStatements = UseStatements::splitAndMergeImportUseStatement(
                $phpcsFile,
                $stackPtr,
                $useStatements
            );

            $stackPtr++;
        }

        return $this->importsCache[$filename] = $useStatements;
    }

    private function isTargetVariable(File $phpcsFile, int $stackPtr, string $targetKey): bool
    {
        $tokens = $phpcsFile->getTokens();
        $prev = $phpcsFile->findPrevious(Tokens::$emptyTokens, $stackPtr - 1, null, true);
        if ($prev === false) {
            return false;
        }

        $map = $this->getTargetVariables($phpcsFile, $targetKey);

        if ($tokens[$prev]['code'] === T_VARIABLE) {
            $name = strtolower(substr($tokens[$prev]['content'], 1));
            return in_array($name, $map['variables'], true);
        }

        if ($tokens[$prev]['code'] === T_STRING) {
            $operatorPtr = $phpcsFile->findPrevious(Tokens::$emptyTokens, $prev - 1, null, true);
            if ($operatorPtr === false || $tokens[$operatorPtr]['code'] !== T_OBJECT_OPERATOR) {
                return false;
            }

            $basePtr = $phpcsFile->findPrevious(Tokens::$emptyTokens, $operatorPtr - 1, null, true);
            if ($basePtr === false || $tokens[$basePtr]['code'] !== T_VARIABLE || $tokens[$basePtr]['content'] !== '$this') {
                return false;
            }

            $property = strtolower($tokens[$prev]['content']);
            return in_array($property, $map['properties'], true);
        }

        return false;
    }
}
