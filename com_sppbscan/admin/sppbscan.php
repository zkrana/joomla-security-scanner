<?php
/**
 * @package     com_sppbscan
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     MIT
 *
 * Standard Joomla admin component entry point. Joomla's own login screen,
 * session handling, and ACL (see access.xml) gate everything below this
 * line -- there is no custom key/lockout/CSRF system here anymore, because
 * the framework already provides all of it.
 */

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Controller\BaseController;

require_once JPATH_ADMINISTRATOR . '/components/com_sppbscan/helpers/sppbscan.php';

SppbscanHelper::requireManageAccess();

$controller = BaseController::getInstance('Sppbscan');
$controller->execute(Factory::getApplication()->input->getCmd('task'));
$controller->redirect();
