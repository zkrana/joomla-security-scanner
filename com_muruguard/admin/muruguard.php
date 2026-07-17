<?php
/**
 * @package     com_muruguard
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

require_once JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/muruguard.php';

$task = Factory::getApplication()->input->getCmd('task');

// scanner.scheduledcheck is the webcron entry point (see
// ScannerController::scheduledcheck()) -- it authenticates via its own
// secret token instead of a logged-in admin session, since a cron/curl
// request has no Joomla session to present. Without this exemption the
// blanket check below would throw NotAllowed for every such request
// before that task's own token check ever runs, making scheduled
// scanning completely unreachable. Every other task still requires a
// real, authorised admin session exactly as before.
if ($task !== 'scanner.scheduledcheck') {
    MuruguardHelper::requireManageAccess();
}

$controller = BaseController::getInstance('Muruguard');
$controller->execute($task);
$controller->redirect();
