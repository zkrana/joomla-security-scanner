<?php
/**
 * @package     com_muruguard
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     MIT
 */

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Table\Asset;
use Joomla\CMS\Table\Table;

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

        $this->addAdminSubmenuItems();
    }

    /**
     * The manifest's own <menu> tag only ever creates ONE top-level
     * #__menu row (client_id=1) for "MuRu Guard" -- Joomla does not
     * generate an expandable, arrow-icon submenu under it just from that.
     * Components that DO show one there (SP Page Builder's own Settings/
     * Pages/... submenu is the example this was modelled on) have
     * multiple #__menu rows sharing that same parent_id. This adds
     * "Dashboard", "Settings", and "Support" as children of the auto-
     * created "MuRu Guard" item -- Dashboard is listed explicitly (not
     * left implicit via the parent's own link) since that's what's
     * actually expected here, matching every other multi-item Joomla
     * admin submenu.
     *
     * Uses Joomla's own Table\Menu class -- #__menu is a nested-set tree
     * (lft/rgt columns shared by EVERY admin menu item on the whole
     * site, not just this component's), so raw INSERT statements risk
     * corrupting that tree for every other menu item too; setLocation()
     * + store() is the safe, official way to insert into it. Idempotency
     * is checked PER ITEM (by exact link, not just "does the parent have
     * any children at all") so a later update can add a newly-introduced
     * item -- like Dashboard here, added after some sites already had
     * Settings/Support from an earlier release -- without duplicating
     * rows that already exist, and never touches any menu item other
     * than this component's own children.
     */
    protected function addAdminSubmenuItems(): void
    {
        try {
            $db = Factory::getDbo();
            $query = $db->getQuery(true)
                ->select($db->quoteName(['id', 'menutype', 'component_id', 'access']))
                ->from($db->quoteName('#__menu'))
                ->where($db->quoteName('client_id') . ' = 1')
                ->where($db->quoteName('type') . ' = ' . $db->quote('component'))
                ->where($db->quoteName('link') . ' = ' . $db->quote('index.php?option=com_muruguard'));
            $db->setQuery($query);
            $parentMenu = $db->loadObject();
            if ($parentMenu === null) {
                return; // Manifest <menu> item not created yet -- nothing to attach children to.
            }

            $children = [
                ['title' => 'Dashboard', 'link' => 'index.php?option=com_muruguard&view_panel=dashboard', 'position' => 'first-child'],
                ['title' => 'Settings',  'link' => 'index.php?option=com_muruguard&view_panel=settings',  'position' => 'last-child'],
                ['title' => 'Support',   'link' => 'index.php?option=com_muruguard&view_panel=support',   'position' => 'last-child'],
            ];

            $anyCreated = false;
            foreach ($children as $child) {
                $existsQuery = $db->getQuery(true)
                    ->select('COUNT(*)')
                    ->from($db->quoteName('#__menu'))
                    ->where($db->quoteName('parent_id') . ' = ' . (int) $parentMenu->id)
                    ->where($db->quoteName('link') . ' = ' . $db->quote($child['link']));
                $db->setQuery($existsQuery);
                if ((int) $db->loadResult() > 0) {
                    continue; // This specific item already exists -- leave it alone.
                }

                /** @var \Joomla\CMS\Table\Menu $table */
                $table = Table::getInstance('Menu');
                $table->setLocation((int) $parentMenu->id, $child['position']);
                $table->menutype     = (string) $parentMenu->menutype;
                $table->title        = $child['title'];
                $table->alias        = $child['title'];
                $table->note         = '';
                $table->link         = $child['link'];
                $table->type         = 'component';
                $table->published    = 1;
                $table->parent_id    = (int) $parentMenu->id;
                $table->component_id = (int) $parentMenu->component_id;
                $table->client_id    = 1;
                $table->browserNav   = 0;
                $table->access       = (int) $parentMenu->access;
                $table->img          = 'class:default';
                $table->language     = '*';
                $table->params       = '{}';
                $table->home         = 0;

                if ($table->check()) {
                    $table->store();
                    $anyCreated = true;
                }
            }

            if ($anyCreated) {
                // Recalculates lft/rgt for the whole tree from parent_id
                // relationships -- the safe way to guarantee a consistent
                // nested set after inserting new nodes via setLocation().
                Table::getInstance('Menu')->rebuild();
            }
        } catch (\Throwable $e) {
            // Never let this block the install/update itself -- worst
            // case, the submenu just doesn't appear and the component is
            // still fully reachable via its own top-level menu link.
        }
    }
}
