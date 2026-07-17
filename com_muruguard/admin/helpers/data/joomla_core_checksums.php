<?php

defined('_JEXEC') or die;

/**
 * Bundled SHA-256 checksums for a curated set of security-critical,
 * site-independent Joomla core files (entry points + static
 * protection files), keyed by exact Joomla core version. Computed
 * directly from the official joomla/joomla-cms GitHub release tags --
 * these plain PHP/text files are not build/minify artifacts, so tag
 * content matches the released package byte-for-byte. Covers the
 * latest patch of the 4.x LTS, 5.x, and 6.x lines as of 2026-07-17;
 * extend with more versions as needed -- an unlisted version simply
 * means checksum verification is skipped for that install (falls
 * back to the existing heuristic checks), never a false positive.
 */
return array (
  '6.1.2' => 
  array (
    'index.php' => '2d180c20f102986b1235d2d418c7846d51e9dc942a8e3e58386c5cbc63b74208',
    'administrator/index.php' => '1de0f0351ae50b9c01ec76ab27a97a638a40477f5f99ea20717f8f06e522550e',
    'api/index.php' => '631ca6cc09b25cc3e832e4a81c8aa11ba51ed2dcd75f3cec13307f0011890681',
    'includes/app.php' => '332157bec452ec181aea94493c5d571b0993a486074712dd9d3519c273a412b8',
    'includes/framework.php' => '577d2ec1deebe0d609fc743028433a68c7470fbb1c22643716715056e9cababa',
    'robots.txt.dist' => 'f1a6b5e3f6e69a71c53516c4bce70e2414429d23dab6814239500999eb80907e',
    'htaccess.txt' => 'a81a5278e7e61a51df9c114ec5d38217811c138d2f246ef8ae9cd6a349e62de9',
    'web.config.txt' => 'f712f94ab6dcd0e0336833663136340d06f06a7fe1eaf5bc44b9ba2390f8934d',
  ),
  '5.4.7' => 
  array (
    'index.php' => 'bba2171c2b43f211d2260e74c3e686b29fad99b4922f6df1491f1334e0ee93d8',
    'administrator/index.php' => 'fd16487f66f084f8d9b1c7cfa93ab0b15f8598c6411496d8a2675dde9006c84a',
    'api/index.php' => 'add9ad72b2a5a8fe07a93cc8bd998bbe50ad2e72440f5a8c76b2c337014c03a8',
    'includes/app.php' => '332157bec452ec181aea94493c5d571b0993a486074712dd9d3519c273a412b8',
    'includes/framework.php' => '577d2ec1deebe0d609fc743028433a68c7470fbb1c22643716715056e9cababa',
    'robots.txt.dist' => 'f1a6b5e3f6e69a71c53516c4bce70e2414429d23dab6814239500999eb80907e',
    'htaccess.txt' => 'a81a5278e7e61a51df9c114ec5d38217811c138d2f246ef8ae9cd6a349e62de9',
    'web.config.txt' => 'f712f94ab6dcd0e0336833663136340d06f06a7fe1eaf5bc44b9ba2390f8934d',
  ),
  '4.4.14' => 
  array (
    'index.php' => '34a77258a0443abac704b1a92bf54f27b7b80c7f24ee52f0ede517af6b831748',
    'administrator/index.php' => 'e952a71cb0fc620227d382249b222fd9a211705ccc1c428ccff17d3fc9e17b75',
    'api/index.php' => 'be58080988893eac87c5192b7211c5ff98247c78cf954558592a51258e81dd0a',
    'includes/app.php' => '8d2776a3d3ab6e122ff9348840fc6b7e4b47e32c1cc9f1ccfc2eebaa6fb11884',
    'includes/framework.php' => 'e32e45b318cf691486099c409a4efc79b8ee17215a21f4d3fc390bf8961e13f1',
    'robots.txt.dist' => 'f1a6b5e3f6e69a71c53516c4bce70e2414429d23dab6814239500999eb80907e',
    'htaccess.txt' => 'a81a5278e7e61a51df9c114ec5d38217811c138d2f246ef8ae9cd6a349e62de9',
    'web.config.txt' => 'f712f94ab6dcd0e0336833663136340d06f06a7fe1eaf5bc44b9ba2390f8934d',
  ),
);
