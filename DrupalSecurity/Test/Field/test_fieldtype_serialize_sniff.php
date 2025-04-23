<?php
// test_fieldtype_serialize_sniff.php

namespace Drupal\custom_module\Plugin\Field\FieldType;

use Drupal\Core\Field\FieldItemBase;
use Drupal\Core\Field\FieldStorageDefinitionInterface;

/**
 * Plugin implementation of the 'example' field type.
 *
 * @FieldType(
 *   id = "example",
 *   label = @Translation("Example field"),
 *   description = @Translation("An example field that uses PHP serialization."),
 *   default_widget = "example_widget",
 *   default_formatter = "example_formatter"
 * )
 */
class ExampleFieldType extends FieldItemBase {

  /**
   * {@inheritdoc}
   */
  public static function schema(FieldStorageDefinitionInterface $field_definition) {
    return [
      'columns' => [
        // This serialize => TRUE should be picked up by the sniff.
        'data' => [
          'type'      => 'blob',
          'size'      => 'normal',
          'serialize' => TRUE,
        ],
      ],
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function isEmpty() {
    return empty($this->get('data')->getValue());
  }
}