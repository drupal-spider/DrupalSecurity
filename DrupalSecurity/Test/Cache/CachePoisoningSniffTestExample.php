<?php

namespace Drupal\custom_module\Access;

use Drupal\Core\Access\AccessInterface;
use Drupal\Core\Access\AccessResult;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Session\AccountInterface;

/**
 * Example access check with missing cache metadata (should trigger the sniff).
 */
class BadAccessCheck implements AccessInterface {
  public function access(EntityInterface $entity, $operation, AccountInterface $account) {
    // Triggers CachePoisoningSniff: no cache metadata.
    return AccessResult::allowed();
  }
}

/**
 * Example access check with proper cache metadata (should not trigger the sniff).
 */
class GoodAccessCheck implements AccessInterface {
  public function access(EntityInterface $entity, $operation, AccountInterface $account) {
    // Correct usage: cache metadata chained.
    return AccessResult::allowed()
      ->addCacheableDependency($entity)
      ->cachePerPermissions();
  }
}