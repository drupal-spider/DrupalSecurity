<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class HardcodedCredentialsSniffTest extends TestCase
{
    public function testPhpFixtureReportsExpectedErrorsAndLines(): void
    {
        $result = $this->runSniff('test_hardcoded_credentials.php');

        $expectedLines = [
            7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            20, 21, 22, 23, 24, 25,
        ];

        self::assertSame(16, $result['errorCount']);
        self::assertSame($expectedLines, $result['errorLines']);

        // Safe and suppressed lines should not report this sniff.
        self::assertNotContains(31, $result['errorLines']);
        self::assertNotContains(36, $result['errorLines']);
        self::assertNotContains(41, $result['errorLines']);
        self::assertNotContains(55, $result['errorLines']);
        self::assertNotContains(60, $result['errorLines']);
        self::assertNotContains(61, $result['errorLines']);
        self::assertNotContains(64, $result['errorLines']);
    }

    public function testYamlFixtureReportsExpectedErrorsAndLines(): void
    {
        $result = $this->runSniff('test_hardcoded_credentials.yml', 'yml,yaml');

        $expectedLines = [
            8, 12, 16, 17, 18, 21, 22, 23, 26,
            27, 28, 31, 32, 33, 36, 37, 40, 51,
        ];

        self::assertSame(18, $result['errorCount']);
        self::assertSame($expectedLines, $result['errorLines']);

        // Safe and suppressed lines should not report this sniff.
        self::assertNotContains(44, $result['errorLines']);
        self::assertNotContains(45, $result['errorLines']);
        self::assertNotContains(55, $result['errorLines']);
        self::assertNotContains(64, $result['errorLines']);
        self::assertNotContains(68, $result['errorLines']);
        self::assertNotContains(78, $result['errorLines']);
        self::assertNotContains(86, $result['errorLines']);
    }

    public function testIgnoreFileYamlFixtureHasNoErrors(): void
    {
        $result = $this->runSniff('test_ignorefile.yml', 'yml,yaml');

        self::assertSame(0, $result['errorCount']);
        self::assertSame([], $result['errorLines']);
    }

    /**
     * @return array{errorCount:int,errorLines:int[]}
     */
    private function runSniff(string $fixtureName, ?string $extensions = null): array
    {
        $root = dirname(__DIR__, 3);
        $phpcsBin = $root . '/vendor/bin/phpcs';
        $fixturePath = __DIR__ . '/' . $fixtureName;

        $command = sprintf(
            'cd %s && %s %s --standard=DrupalSecurity --sniffs=DrupalSecurity.Credentials.HardcodedCredentials --report=json%s %s 2>&1',
            escapeshellarg($root),
            escapeshellarg(PHP_BINARY),
            escapeshellarg($phpcsBin),
            $extensions ? ' --extensions=' . escapeshellarg($extensions) : '',
            escapeshellarg($fixturePath)
        );

        $output = [];
        $exitCode = 0;
        exec($command, $output, $exitCode);

        $json = $this->extractJson(implode("\n", $output));
        $decoded = json_decode($json, true);

        self::assertIsArray(
            $decoded,
            sprintf('Unable to decode PHPCS JSON output (exit code %d). Raw output: %s', $exitCode, implode("\n", $output))
        );

        $errorLines = [];
        if (!empty($decoded['files']) && is_array($decoded['files'])) {
            foreach ($decoded['files'] as $fileReport) {
                if (empty($fileReport['messages']) || !is_array($fileReport['messages'])) {
                    continue;
                }
                foreach ($fileReport['messages'] as $message) {
                    if (($message['source'] ?? '') !== 'DrupalSecurity.Credentials.HardcodedCredentials.HardcodedCredential') {
                        continue;
                    }
                    $errorLines[] = (int) $message['line'];
                }
            }
        }

        sort($errorLines);

        return [
            'errorCount' => (int) ($decoded['totals']['errors'] ?? count($errorLines)),
            'errorLines' => $errorLines,
        ];
    }

    private function extractJson(string $rawOutput): string
    {
        $start = strpos($rawOutput, '{');
        $end = strrpos($rawOutput, '}');

        self::assertNotFalse($start, 'PHPCS output did not contain JSON start.');
        self::assertNotFalse($end, 'PHPCS output did not contain JSON end.');
        self::assertGreaterThanOrEqual($start, $end, 'PHPCS JSON output is malformed.');

        return substr($rawOutput, (int) $start, ((int) $end - (int) $start + 1));
    }
}
