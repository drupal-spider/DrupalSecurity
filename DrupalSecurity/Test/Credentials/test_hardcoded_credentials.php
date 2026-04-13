<?php
// Test fixture for HardcodedCredentialsSniff (PHP scanning).
// Lines marked "should trigger" have hardcoded credentials.
// Lines marked "safe" should NOT trigger errors.

// --- Should trigger errors (variable assignments) ---
$password = 'SuperSecret123!';
$api_key = 'ak_live_1234567890abcdef';
$api_secret = 'sk_live_abcdef1234567890';
$client_secret = 'oauth-client-secret-value';
$access_token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
$smtp_password = 's3ndgr1d_p@ss';
$aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
$private_key = 'base64encodedkey==';
$auth_token = 'xoxb-000000000-xxxxxxxxxxxx';
$encryption_key = 'my-encryption-key-value';

// --- Should trigger errors (array key => value) ---
$config = [
  'password' => 'my_db_password',
  'api_key' => 'ak_live_1234567890',
  'secret' => 'super-secret-value',
  'bearer_token' => 'eyJhbGciOiJIUzI1NiJ9.test',
  'azure_key' => 'azure-storage-key-value',
  'key_value' => 'my-super-secret-key-stored-in-config',
];

// --- Should NOT trigger errors (safe) ---

// Non-credential variable names.
$username = 'admin';
$hostname = 'db.example.com';
$title = 'My Website';

// Credential names but assigned from variables (not hardcoded).
$password = $user_input;
$api_key = $config_value;
$secret = getenv('APP_SECRET');

// Credential names but empty/placeholder values.
$password = '';
$api_key = 'changeme';
$secret = 'TODO';
$auth_token = 'xxx';

// Non-credential array keys.
$settings = [
  'driver' => 'mysql',
  'host' => 'localhost',
  'database' => 'drupal',
];

// Credential array keys but with variable values.
$settings = [
  'password' => $db_password,
  'api_key' => $api_key_from_env,
];

// Suppressed with phpcs:ignore — native PHPCS mechanism works for PHP files.
$password = 'suppressed-hardcoded'; // phpcs:ignore DrupalSecurity.Credentials.HardcodedCredentials.HardcodedCredential
$api_key = 'also-suppressed'; // phpcs:ignore

// Drupal Key module — using the Key repository service is safe.
$key_value = \Drupal::service('key.repository')->getKeyValue('my_key');
