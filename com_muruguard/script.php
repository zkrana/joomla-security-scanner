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

        // Genuine root cause of "MuRu Settings/submenu vanish after any
        // update, come back after uninstall+reinstall" -- NOT a nested-set
        // staleness or duplicate-row issue (two earlier, wrong theories).
        // applyDefaultAclRules() below used to be inlined directly in this
        // method with `return;` as its early-exit for "nothing to do
        // here" -- but a bare `return` inside a method exits the WHOLE
        // method, not just the enclosing try block. On literally every
        // update (not just some), the asset row already has the rules
        // THIS SAME SCRIPT set on the original install, so the "already
        // has rules, nothing to do" branch always hit that early return
        // and skipped addAdminSubmenuItems() below entirely, every single
        // time. A fresh install never hits it (empty rules the first
        // time), which is exactly why uninstall+reinstall always "fixed"
        // it. Extracting the ACL step into its own method means its early
        // returns can only ever exit that method, never this one.
        $this->applyDefaultAclRules();
        $this->addAdminSubmenuItems();
    }

    /**
     * Sets default ACL rules (deny Manager/Administrator groups) on this
     * component's #__assets row, but ONLY the very first time it's ever
     * seen with no rules at all -- never overwrites a site owner's own
     * later ACL customisation. See postflight()'s docblock above for why
     * this is its own method rather than inlined there.
     */
    private function applyDefaultAclRules(): void
    {
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

    /**
     * The manifest's own <menu> tag only ever creates ONE top-level
     * #__menu row (client_id=1) for "MuRu Guard" -- Joomla does not
     * generate an expandable, arrow-icon submenu under it just from that.
     * Components that DO show one there (SP Page Builder's own Settings/
     * Pages/... submenu is the example this was modelled on) have
     * multiple #__menu rows sharing that same parent_id. This adds
     * "Dashboard", "MuRu Settings", and "Support" as children of the
     * auto-created "MuRu Guard" item -- Dashboard is listed explicitly
     * (not left implicit via the parent's own link) since that's what's
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

            // Joomla's own installer can, on some reinstall-the-same-version
            // update paths, insert a SECOND fresh top-level #__menu row for
            // this component instead of reusing the existing one -- leaving
            // TWO rows that both match link='index.php?option=com_muruguard'.
            // Trusting a single loadObject() here risks silently attaching
            // (or finding existing) children under the STALE row while the
            // NEW row is the one actually wired into the live admin nav
            // tree -- which renders as "the submenu vanished" even though
            // the child rows still exist untouched in the database. Fetch
            // every matching row instead of assuming there's only one.
            $query = $db->getQuery(true)
                ->select($db->quoteName(['id', 'menutype', 'component_id', 'access']))
                ->from($db->quoteName('#__menu'))
                ->where($db->quoteName('client_id') . ' = 1')
                ->where($db->quoteName('type') . ' = ' . $db->quote('component'))
                ->where($db->quoteName('link') . ' = ' . $db->quote('index.php?option=com_muruguard'))
                ->order($db->quoteName('id') . ' ASC');
            $db->setQuery($query);
            $candidates = $db->loadObjectList() ?: [];
            if (empty($candidates)) {
                return; // Manifest <menu> item not created yet -- nothing to attach children to.
            }

            // The canonical row is whichever one #__extensions actually
            // points a fresh component_id lookup at -- the same signal
            // Joomla's own core installer uses to decide "does this
            // component already have a menu item". Falls back to the
            // most-recently-created candidate (highest id) if that lookup
            // comes up empty, since that's the row Joomla just created/kept
            // as part of THIS install run.
            $extensionId = (int) $db->setQuery(
                $db->getQuery(true)
                    ->select($db->quoteName('extension_id'))
                    ->from($db->quoteName('#__extensions'))
                    ->where($db->quoteName('element') . ' = ' . $db->quote('com_muruguard'))
                    ->where($db->quoteName('type') . ' = ' . $db->quote('component'))
            )->loadResult();

            $parentMenu = null;
            if ($extensionId > 0) {
                foreach ($candidates as $candidate) {
                    if ((int) $candidate->component_id === $extensionId) {
                        $parentMenu = $candidate;
                        break;
                    }
                }
            }
            if ($parentMenu === null) {
                $parentMenu = end($candidates);
            }

            // Any OTHER candidate is a stale duplicate -- migrate its
            // children (if this component's own postflight created any
            // there on a previous run, before this bug was understood)
            // onto the canonical parent, then remove the now-empty
            // duplicate so it doesn't linger as clutter.
            foreach ($candidates as $candidate) {
                if ((int) $candidate->id === (int) $parentMenu->id) {
                    continue;
                }
                $db->setQuery(
                    $db->getQuery(true)
                        ->update($db->quoteName('#__menu'))
                        ->set($db->quoteName('parent_id') . ' = ' . (int) $parentMenu->id)
                        ->where($db->quoteName('parent_id') . ' = ' . (int) $candidate->id)
                )->execute();
                $db->setQuery(
                    $db->getQuery(true)
                        ->delete($db->quoteName('#__menu'))
                        ->where($db->quoteName('id') . ' = ' . (int) $candidate->id)
                )->execute();
            }

            $children = [
                ['title' => 'Dashboard',     'link' => 'index.php?option=com_muruguard&view_panel=dashboard', 'position' => 'first-child'],
                ['title' => 'MuRu Settings', 'link' => 'index.php?option=com_muruguard&view_panel=settings',  'position' => 'last-child'],
                ['title' => 'Support',       'link' => 'index.php?option=com_muruguard&view_panel=support',   'position' => 'last-child'],
            ];

            // The per-item idempotency check below only creates a row if
            // one doesn't already exist -- it never renames an existing
            // one, so an existing install updating from an older version
            // would keep showing the old "Settings" title forever. Rename
            // it, but ONLY if it still has the exact old default -- if an
            // admin renamed it themselves via Joomla's own Menus manager,
            // that custom title is left alone.
            $db->setQuery(
                $db->getQuery(true)
                    ->update($db->quoteName('#__menu'))
                    ->set($db->quoteName('title') . ' = ' . $db->quote('MuRu Settings'))
                    ->set($db->quoteName('alias') . ' = ' . $db->quote('MuRu Settings'))
                    ->where($db->quoteName('parent_id') . ' = ' . (int) $parentMenu->id)
                    ->where($db->quoteName('link') . ' = ' . $db->quote('index.php?option=com_muruguard&view_panel=settings'))
                    ->where($db->quoteName('title') . ' = ' . $db->quote('Settings'))
            )->execute();

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
                }
            }

            // Unconditional, not just when a new row was created this run
            // -- on a fresh install this would always run anyway (every
            // child is new), but on an UPDATE over an already-installed
            // copy the 3 children usually already exist (nothing new to
            // create this run), yet Joomla's own installer can still touch
            // the tree around our top-level parent item during that same
            // update. parent_id stays correct either way, but lft/rgt can
            // go stale relative to the current tree shape -- and the admin
            // sidebar is built from lft/rgt (a nested-set range query), not
            // parent_id alone, so stale values make already-existing,
            // correctly-parented rows silently stop rendering even though
            // they're still sitting in #__menu untouched. Recalculating
            // every time this runs is what makes the submenu self-heal on
            // every update, not just a fresh install.
            Table::getInstance('Menu')->rebuild();
        } catch (\Throwable $e) {
            // Never let this block the install/update itself -- worst
            // case, the submenu just doesn't appear and the component is
            // still fully reachable via its own top-level menu link.
        }
    }
}
