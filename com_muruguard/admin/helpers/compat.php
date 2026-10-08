<?php
/**
 * @package     com_muruguard
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 *
 * Joomla 3 / Joomla 4+ compatibility layer -- the ONLY file in this
 * component that is allowed to know the two platforms apart (enforced by
 * tests/static-checks.php, section 10). Supported range is Joomla 3.10+
 * (PHP 7.4+) through Joomla 6.x (PHP 8.1+).
 *
 * Joomla 3 ships the legacy J-prefixed API (JFactory, JControllerLegacy,
 * ...) while Joomla 4+ ships the namespaced one (Joomla\CMS\Factory,
 * Joomla\CMS\MVC\Controller\BaseController, ...). On Joomla 3 this file
 * aliases every namespaced name the component references onto its legacy
 * twin, so the rest of the codebase keeps using the modern names
 * unconditionally. On Joomla 4+ this file defines no aliases at all and
 * every MuruguardCompat:: helper below takes the native path, so the
 * Joomla 4/5/6 behaviour is byte-for-byte what it was before this file
 * existed.
 *
 * Load order: required FIRST by the component entry point
 * (admin/muruguard.php) and by helpers/muruguard.php (which every model,
 * view, and controller transitively loads), so the aliases always exist
 * before any `extends Joomla\CMS\...` class declaration executes. The
 * Shield plugin and the installer script intentionally do NOT load this
 * file -- the plugin must also run (inertly) without the component
 * installed, and the installer runs from the extracted package before
 * any component path exists -- so both carry a tiny inline copy of just
 * the aliases they need instead; see the top of
 * plg_muruguardshield/muruguardshield.php and com_muruguard/script.php.
 */

defined('_JEXEC') or die;

if (!defined('MURUGUARD_COMPAT_LOADED')) {
    define('MURUGUARD_COMPAT_LOADED', true);

    // Both alias probes below deliberately pass false (no autoload):
    // probing the alias must never trigger Joomla's loader itself. Where
    // another copy of this same block already ran (plugin inline block
    // first, component file second, or vice versa), the first probe makes
    // the second run a no-op instead of a "Cannot declare class"
    // warning -- and the re-probe after loading the original covers
    // Joomla 3's own loader, which materialises its core-registered
    // forward alias for the same modern name as a side effect of that
    // load (see the loop body).
    if (defined('JVERSION') && version_compare(JVERSION, '4.0', '<')) {
        $muruguardCompatAliases = [
            // alias (modern name, used by this codebase) => original (J3 name)
            'Joomla\\CMS\\Factory'                    => 'JFactory',
            'Joomla\\CMS\\Language\\Text'             => 'JText',
            'Joomla\\CMS\\Uri\\Uri'                   => 'JUri',
            'Joomla\\CMS\\Router\\Route'              => 'JRoute',
            'Joomla\\CMS\\HTML\\HTMLHelper'           => 'JHtml',
            'Joomla\\CMS\\Session\\Session'           => 'JSession',
            'Joomla\\CMS\\Component\\ComponentHelper' => 'JComponentHelper',
            'Joomla\\CMS\\MVC\\Controller\\BaseController' => 'JControllerLegacy',
            'Joomla\\CMS\\MVC\\View\\HtmlView'        => 'JViewLegacy',
            'Joomla\\CMS\\Plugin\\CMSPlugin'          => 'JPlugin',
            'Joomla\\CMS\\Table\\Table'               => 'JTable',
            'Joomla\\CMS\\Toolbar\\ToolbarHelper'     => 'JToolbarHelper',
            // Joomla's own "not authorised" exception: thrown for guests
            // and under-privileged users by MuruguardHelper's ACL gates,
            // rendered as a 403 page by Joomla core on both platforms.
            // Present since Joomla 3.6.3, so always available on 3.10+.
            'Joomla\\CMS\\Exception\\NotAllowed'      => 'JAccessExceptionNotallowed',
        ];
        foreach ($muruguardCompatAliases as $alias => $original) {
            // Probed twice, deliberately: class_exists($original) autoloads
            // the legacy class, and Joomla 3's own loader materialises its
            // core-registered forward alias for the same modern name as a
            // side effect of that load (confirmed live on 3.10: Route,
            // HTMLHelper, BaseController, HtmlView and ToolbarHelper all
            // arrive pre-aliased this way). Re-checking afterwards turns
            // that into a silent skip -- Joomla's alias points at the same
            // class ours would have -- instead of a "Cannot declare class"
            // warning, which would corrupt every JSON chunk response and
            // abort the scan.
            if (!class_exists($alias, false) && class_exists($original) && !class_exists($alias, false)) {
                class_alias($original, $alias);
            }
        }
        unset($muruguardCompatAliases, $alias, $original);
    }
}

/**
 * Version branches for the handful of calls where a plain class alias is
 * not enough because the API itself differs between Joomla 3 and 4+.
 */
final class MuruguardCompat
{
    /**
     * True on Joomla 4.0+. An undefined JVERSION (should never happen at
     * runtime -- Joomla always defines it) defaults to the modern path,
     * which is the behaviour this codebase shipped for years.
     */
    public static function isJoomla4(): bool
    {
        return !defined('JVERSION') || version_compare(JVERSION, '4.0', '>=');
    }

    /**
     * The current user object. Joomla 4+: the application's identity;
     * Joomla 3: JFactory::getUser(). Both return an object with the same
     * ->guest / ->id / ->authorise() surface this codebase relies on.
     *
     * @return object
     */
    public static function getUser()
    {
        if (self::isJoomla4()) {
            return \Joomla\CMS\Factory::getApplication()->getIdentity();
        }

        return \JFactory::getUser();
    }

    /**
     * The current session object. Joomla 4+: the application's session;
     * Joomla 3: JFactory::getSession(). Same ->get()/->set() surface on
     * both (Joomla 3's application object has no getSession() method of
     * its own).
     *
     * @return object
     */
    public static function getSession()
    {
        if (self::isJoomla4()) {
            return \Joomla\CMS\Factory::getApplication()->getSession();
        }

        return \JFactory::getSession();
    }

    /**
     * True when $app is the administrator application. Joomla 4+:
     * isClient('administrator'); Joomla 3: isAdmin(). Capability-ordered
     * (isClient first where it exists) rather than version-ordered, so a
     * hypothetical Joomla 3 with a backported isClient() still works.
     *
     * @param object $app Joomla application object (either platform).
     */
    public static function isAdminClient($app): bool
    {
        if (is_object($app) && method_exists($app, 'isClient')) {
            return (bool) $app->isClient('administrator');
        }
        if (is_object($app) && method_exists($app, 'isAdmin')) {
            return (bool) $app->isAdmin();
        }

        return false;
    }
}

// Database-model base with a uniform getDatabase() on both platforms.
// Joomla 4+: the native base class, unchanged. Joomla 3: JModelLegacy,
// which only offers getDbo(), plus a getDatabase() polyfill forwarding
// to it -- so the model's eighteen $this->getDatabase() call sites need
// no version checks of their own. (Deliberately NOT done as a plain
// class_alias of BaseDatabaseModel: the polyfill method has to live
// somewhere, and a conditional subclass is that somewhere.)
if (MuruguardCompat::isJoomla4()) {
    class MuruguardCompatDatabaseModel extends \Joomla\CMS\MVC\Model\BaseDatabaseModel
    {
    }
} else {
    class MuruguardCompatDatabaseModel extends \JModelLegacy
    {
        /**
         * @return object Joomla 3 database driver (same query-builder and
         *               load*() surface the model uses on Joomla 4+).
         */
        public function getDatabase()
        {
            return $this->getDbo();
        }
    }
}
