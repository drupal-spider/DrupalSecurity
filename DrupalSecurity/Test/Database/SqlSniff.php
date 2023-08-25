<?php
$query = 'query';

$user = $_GET['user'];

$user_input = $_GET['input'];

// Unsafe, concatenate data directly into SQL queries.
\Database::getConnection()->query('SELECT foo FROM {table} t WHERE t.name = '. $_GET['user']);


// Unsafe, a LIKE query might contain wildcard characters like "%".
db_select('table', 't')
->condition('t.field', $_GET['user'], 'LIKE')
->execute();

// Unsafe, users provides operator to a query's condition.
db_select('table', 't')
->condition('t.field', $user, $user_input)
->execute();

// Unsafe, this gets all articles that exist regardless of access.
$ids = \Drupal::entityQuery('node')
->accessCheck(FALSE)
->condition('type', 'article')
->execute();

// Mutiple entities loading won't check the access. You have to check the access for those entities after loading.
$entities = \Drupal::entityTypeManager()->getStorage($entityType)->loadMultiple();


$properties = [
  $entityStorage->getEntityType()->getKey('bundle') => $bundleID,
];
// Load entities by their property values without any access checks. @see https://api.drupal.org/api/drupal/core%21lib%21Drupal%21Core%21Entity%21EntityStorageBase.php/function/EntityStorageBase%3A%3AloadByProperties/10
$entities = $entityStorage->loadByProperties($properties);

// Use the access() function to check the access for each entity.
foreach ($entities as $entity) {
  if ($entity->access('view')) {
  }
}

// Safe
\Database::getConnection()->query('SELECT foo FROM {table} t WHERE t.name = :name', [':name' => $_GET['user']]);

$users = ['joe', 'poe', $_GET['user']];
\Database::getConnection()->query('SELECT f.bar FROM {foo} f WHERE f.bar IN (:users[])',  [':users[]' => $users]);

$users = ['joe', 'poe', $_GET['user']];
$result = \Database::getConnection()->select('foo', 'f')
->fields('f', ['bar'])
->condition('f.bar', $users)
->execute();

// This gets all articles the current user can view.
$ids = \Drupal::entityQuery('node')
->accessCheck(TRUE)
->condition('type', 'article')
->execute();