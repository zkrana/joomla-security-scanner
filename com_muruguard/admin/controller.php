<?php
/**
 * @package     com_muruguard
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     MIT
 */

defined('_JEXEC') or die;

use Joomla\CMS\MVC\Controller\BaseController;

require_once JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/muruguard.php';

class MuruguardController extends BaseController
{
    public function display($cachable = false, $urlparams = [])
    {
        MuruguardHelper::requireManageAccess();
        $this->input->set('view', $this->input->getCmd('view', 'scanner'));
        return parent::display($cachable, $urlparams);
    }
}
