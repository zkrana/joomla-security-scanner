<?php
/**
 * @package     com_sppbscan
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     MIT
 */

defined('_JEXEC') or die;

use Joomla\CMS\MVC\Controller\BaseController;

require_once JPATH_ADMINISTRATOR . '/components/com_sppbscan/helpers/sppbscan.php';

class SppbscanController extends BaseController
{
    public function display($cachable = false, $urlparams = [])
    {
        SppbscanHelper::requireManageAccess();
        $this->input->set('view', $this->input->getCmd('view', 'scanner'));
        return parent::display($cachable, $urlparams);
    }
}
