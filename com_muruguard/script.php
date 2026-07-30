<?php
/**
 * @package     com_muruguard
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     MIT
 */

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Table\Asset;

/**
 * Joomla's own Super Users group always bypasses every ACL check
 * regardless of what's configured here -- that's core Joomla behaviour,
 * not something a component can or should override. What a component
 * CAN control is the default for every other group: without this, a
 * fresh install inherits whatever the site's root ACL already grants
 * Manager/Administrator-group accounts (often broad backend access by
 * default), so a security scanner ends up visible/usable by anyone with
 * general admin access, not just the site's actual Super Users.
 *
 * Class name intentionally uses the legacy "{element}InstallerScript"
 * convention (lowercase element + "InstallerScript", no base class) --
 * the one naming pattern Joomla's installer has reliably recognised
 * across 3.x/4.x/5.x, matching this project's stated cross-version
 * compatibility elsewhere.
 */
class com_muruguardInstallerScript
{
    public function postflight($type, $parent)
    {
        if (!in_array($type, ['install', 'update'], true)) {
            return;
        }

        try {
            $db = Factory::getDbo();
            $query = $db->getQuery(true)
                ->select($db->quoteName(['id', 'rules']))
                ->from($db->quoteName('#__assets'))
                ->where($db->quoteName('name') . ' = ' . $db->quote('com_muruguard'));
            $db->setQuery($query);
            $row = $db->loadObject();
            if ($row === null) {
                return; // Asset row not created yet -- nothing to set rules on.
            }

            // Only ever touches an untouched (empty-rules) asset -- if the
            // site owner has already made ANY ACL choice for this
            // component (including re-enabling it for a group themselves),
            // an update must never silently overwrite that.
            $existingRules = json_decode((string) $row->rules, true);
            if (!empty($existingRules)) {
                return;
            }

            // Standard default Joomla group IDs on a stock install: 6 =
            // Manager, 7 = Administrator. Super Users (8) are deliberately
            // NOT listed -- see class docblock. A site with a customised
            // user-group tree can still grant/adjust access normally via
            // System > Users > Access Levels afterwards; this is only the
            // out-of-the-box starting point.
            $defaultRules = [
                'core.admin'  => ['6' => 0, '7' => 0],
                'core.manage' => ['6' => 0, '7' => 0],
                'core.delete' => ['6' => 0, '7' => 0],
                'core.edit'   => ['6' => 0, '7' => 0],
            ];

            $asset = new Asset($db);
            if ($asset->load((int) $row->id)) {
                $asset->rules = json_encode($defaultRules);
                $asset->store();
            }
        } catch (\Throwable $e) {
            // Never let a default-ACL step block the install/update itself.
        }
    }
}
