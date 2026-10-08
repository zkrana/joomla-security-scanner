<?php
/**
 * @package     com_muruguard
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Controller\BaseController;

require_once JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/compat.php';
require_once JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/muruguard.php';
require_once JPATH_ADMINISTRATOR . '/components/com_muruguard/controllers/scanner.php';

/**
 * Extends MuruguardControllerScanner (not BaseController directly) so
 * every task -- scan, delete, cleancode, cleanmenu, deleteassets,
 * scheduledcheck, savesettings, and plain display -- lives as a real,
 * reflectable method on the SAME object Joomla's
 * BaseController::getInstance('Muruguard') actually instantiates for
 * a request, regardless of whether Joomla's own "prefix.task" dot-
 * notation (e.g. task=scanner.scan) additionally tries to swap in
 * MuruguardControllerScanner on its own. Either way, the task method
 * ends up reachable on this object -- this class inheriting from it is
 * what guarantees that, rather than depending on assumptions about
 * exactly how that dot-notation resolves in a given Joomla version.
 */
class MuruguardController extends MuruguardControllerScanner
{
    public function display($cachable = false, $urlparams = [])
    {
        MuruguardHelper::requireManageAccess();
        // Same input object $this->input wraps on Joomla 4+, read straight
        // from the application instead -- Joomla 3's legacy controller
        // does not guarantee a populated $this->input property.
        $input = Factory::getApplication()->input;
        $input->set('view', $input->getCmd('view', 'scanner'));
        return parent::display($cachable, $urlparams);
    }
}
