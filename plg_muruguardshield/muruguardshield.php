<?php
/**
 * @package     plg_system_muruguardshield
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 *
 * Companion plugin to the MuRu Guard Security Scanner component
 * (com_muruguard). A component only runs when someone visits its own
 * admin page, so real-time request-level protection has to live in a
 * plugin instead -- this is the only extension type Joomla invokes on
 * every single page load, before routing even happens.
 *
 * Deliberately has NO settings of its own (no config.xml, no <field>
 * params): everything it does is controlled from com_muruguard's own
 * Settings panel / Global Configuration, read directly from that
 * component's params on every check. This keeps configuration in one
 * place instead of split across two separate admin screens for what is,
 * from the site owner's point of view, one feature.
 */

defined('_JEXEC') or die;

// Joomla 3 compatibility aliases -- a tiny inline copy of the relevant
// entries from the component's helpers/compat.php, kept inline (rather
// than requiring that file) because this plugin must also load --
// inertly -- without the component installed at all. Only the three
// names this file itself references; everything the component helper
// needs is aliased by compat.php when loadShieldHelper() pulls it in.
// Guarded per alias so running after (or before) compat.php is a no-op
// instead of a "Cannot declare class" warning -- and re-checked after
// loading the original, since Joomla 3's own loader may materialise its
// own alias for the same name as a side effect (see compat.php).
if (defined('JVERSION') && version_compare(JVERSION, '4.0', '<')) {
    $muruguardShieldAliases = [
        'Joomla\\CMS\\Factory'              => 'JFactory',
        'Joomla\\CMS\\Plugin\\CMSPlugin'    => 'JPlugin',
        'Joomla\\CMS\\Component\\ComponentHelper' => 'JComponentHelper',
    ];
    foreach ($muruguardShieldAliases as $alias => $original) {
        if (!class_exists($alias, false) && class_exists($original) && !class_exists($alias, false)) {
            class_alias($original, $alias);
        }
    }
    unset($muruguardShieldAliases, $alias, $original);
}

use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Component\ComponentHelper;
use Joomla\CMS\Language\Text;

/**
 * Everything the plugin does. The class Joomla loads, plgSystemMuruguardshield,
 * is declared at the bottom of this file in one of two shapes, because the
 * scheduled-scan bridge (onAjaxMuruguardshield) needs a different method
 * signature on Joomla 3 than on Joomla 4 and later.
 */
abstract class plgSystemMuruguardshieldBase extends CMSPlugin
{
    /**
     * True when $app is the administrator application. Same two-method
     * probe as MuruguardCompat::isAdminClient(), duplicated here (rather
     * than called) because this plugin file must stand alone without the
     * component installed -- see the alias block at the top of this file.
     *
     * @param object $app Joomla application object (either platform).
     */
    private static function isAdminClient($app): bool
    {
        if (is_object($app) && method_exists($app, 'isClient')) {
            return (bool) $app->isClient('administrator');
        }
        if (is_object($app) && method_exists($app, 'isAdmin')) {
            // Joomla 3's name for the same check.
            return (bool) $app->isAdmin();
        }

        return false;
    }

    /**
     * The current user object. Same branch as
     * MuruguardCompat::getUser(), duplicated here for the same
     * standalone reason as isAdminClient() above.
     *
     * @return object
     */
    private static function getCurrentUser()
    {
        $app = Factory::getApplication();
        if (method_exists($app, 'getIdentity')) {
            return $app->getIdentity();
        }

        // Joomla 3, which has no getIdentity().
        return \JFactory::getUser();
    }

    /**
     * Fires on every request, before routing. Every code path below is
     * wrapped in a try/catch that swallows any Throwable -- this plugin
     * runs on EVERY page load of the entire site (frontend, backend,
     * API, everything), so a bug here must never be able to fatal the
     * whole site over a security feature meant to protect it.
     */
    public function onAfterInitialise()
    {
        $started = microtime(true);
        try {
            $this->checkBasicAuthGate();
        } catch (\Throwable $e) {
            $this->noteFailure('checkBasicAuthGate', $e);
            // Fail open -- see class docblock.
        }
        try {
            $this->runShieldCheck();
        } catch (\Throwable $e) {
            $this->noteFailure('runShieldCheck', $e);
            // Fail open -- see class docblock.
        }
        try {
            $this->checkAdminLockdownGate();
        } catch (\Throwable $e) {
            $this->noteFailure('checkAdminLockdownGate', $e);
            // Fail open -- see class docblock.
        }
        $this->noteTiming(microtime(true) - $started);
    }

    /**
     * Records how long the checks above took, for the Shield speed shown in
     * the Threat Monitor. Only 1 request in 50 is written, and only while
     * Protection Mode is on, so measuring never adds a file write to every
     * request. A refused request never gets here (it stops in rejectRequest()).
     */
    private function noteTiming(float $seconds): void
    {
        try {
            if (mt_rand(1, 50) !== 1) return;
            if (!class_exists('MuruguardHelper', false) || !method_exists('MuruguardHelper', 'recordShieldTiming')) return;
            if (!ComponentHelper::getParams('com_muruguard')->get('shield_enabled', 0)) return;
            \MuruguardHelper::recordShieldTiming($seconds * 1000);
        } catch (\Throwable $e) {
        }
    }

    /** Records a swallowed failure so Site Protection can show that protection had a problem (never throws). */
    private function noteFailure(string $where, \Throwable $e): void
    {
        try {
            if (class_exists('MuruguardHelper', false) && method_exists('MuruguardHelper', 'recordShieldError')) {
                \MuruguardHelper::recordShieldError($where, $e);
            }
        } catch (\Throwable $ignored) {
        }
    }

    /**
     * PHP-level equivalent of MuRu Shield Hardening's .htaccess Basic
     * Auth block -- .htaccess is an APACHE-ONLY mechanism (Nginx never
     * reads it at all, and even on Apache it depends on AllowOverride
     * being permissive and mod_auth_basic being loaded), so on any host
     * where that doesn't hold, the .htaccess block this plugin's
     * companion component writes is silently ignored and Backend Access
     * never actually did anything. This check re-implements the same
     * gate in pure PHP against the request's Authorization header,
     * checked here on every request regardless of web server --
     * Apache/Nginx/LiteSpeed/IIS all populate this the same way once PHP
     * is running. Reads the SAME .htpasswd file the component's
     * MuruguardHardeningHelper already writes and self-tests against, so
     * activating Backend Access continues to "just work" on Nginx too --
     * no separate configuration, no separate credentials.
     *
     * Runs independently of the shield_enabled toggle above (Protection
     * Mode/Site Protection and Backend Access are separate opt-in
     * features) and is a strictly ADDITIVE check on top of whatever the
     * .htaccess block may or may not already be enforcing -- on a host
     * where .htaccess IS working, both layers simply agree; on one where
     * it isn't, this is the layer that's actually doing the work.
     */
    private function checkBasicAuthGate(): void
    {
        $params = ComponentHelper::getParams('com_muruguard');
        $backendAuthEnabled   = (bool) $params->get('backend_auth_enabled', 0);
        $emergencyModeEnabled = (bool) $params->get('emergency_mode_enabled', 0);
        if (!$backendAuthEnabled && !$emergencyModeEnabled) return;

        $app = Factory::getApplication();

        // Backend Access alone only ever gates /administrator; Emergency
        // Mode (which reuses the exact same credentials -- see
        // MuruguardHardeningHelper::activateEmergencyMode()) extends that
        // to every request on the site.
        $isAdminClient = self::isAdminClient($app);
        if (!$emergencyModeEnabled && !$isAdminClient) return;

        // Same file MuruguardHardeningHelper::writeHtpasswd() writes and
        // MuruguardHardeningHelper::verifyBackendPassword() reads --
        // deliberately not duplicating credential storage. Missing file
        // means Backend Access isn't actually active (or was just
        // deactivated) -- fail open, matching .htaccess's own behaviour
        // when there's nothing to enforce.
        $htpasswdPath = JPATH_ADMINISTRATOR . '/.htpasswd';
        if (!is_file($htpasswdPath)) return;

        $line = trim((string) @file_get_contents($htpasswdPath));
        [$storedUser, $storedHash] = array_pad(explode(':', $line, 2), 2, '');
        if ($storedUser === '' || $storedHash === '') return;

        [$providedUser, $providedPass] = self::readBasicAuthCredentials();
        if (
            $providedUser !== null
            && hash_equals($storedUser, $providedUser)
            && password_verify((string) $providedPass, $storedHash)
        ) {
            return; // Correct credentials -- let the request through.
        }

        header('WWW-Authenticate: Basic realm="Restricted Area"');
        http_response_code(401);
        header('Content-Type: text/plain; charset=utf-8');
        echo "Unauthorized\n";
        $app->close();
    }

    /**
     * $_SERVER['PHP_AUTH_USER']/PHP_AUTH_PW are populated automatically
     * under mod_php and most PHP-FPM + Apache/LiteSpeed setups, but a
     * default Nginx + PHP-FPM config does NOT forward the Authorization
     * header into PHP_AUTH_* unless the site's fastcgi_params explicitly
     * sets `fastcgi_param HTTP_AUTHORIZATION $http_authorization;` --
     * parsing HTTP_AUTHORIZATION directly as a fallback means this works
     * out of the box on a stock Nginx host too, with no server config
     * changes required from the site owner.
     *
     * @return array{0: ?string, 1: ?string}
     */
    private static function readBasicAuthCredentials(): array
    {
        if (isset($_SERVER['PHP_AUTH_USER'])) {
            return [(string) $_SERVER['PHP_AUTH_USER'], (string) ($_SERVER['PHP_AUTH_PW'] ?? '')];
        }
        $header = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
        if ($header !== '' && stripos($header, 'Basic ') === 0) {
            $decoded = base64_decode(substr($header, 6), true);
            if ($decoded !== false && strpos($decoded, ':') !== false) {
                [$user, $pass] = explode(':', $decoded, 2);
                return [$user, $pass];
            }
        }
        return [null, null];
    }

    /**
     * Records every failed backend login for the brute-force threshold
     * check in runShieldCheck() -- this event itself never blocks
     * anything; the actual rejection happens in onAfterInitialise() on
     * that IP's NEXT request once its failure count crosses the
     * configured threshold.
     *
     * @param array|object $response The authentication response Joomla
     *                                passes for this event (legacy
     *                                plugins receive it as a plain
     *                                array, not the modern Event object).
     */
    public function onUserLoginFailure($response)
    {
        try {
            if (!$this->loadShieldHelper()) return;

            $params = ComponentHelper::getParams('com_muruguard');
            if (!$params->get('shield_enabled', 0)) return;

            $ip = \MuruguardHelper::resolveClientIp(
                Factory::getApplication()->input->server,
                (string) $params->get('shield_trusted_proxy_header', '')
            );
            if ($ip === '') return;

            $username = '';
            if (is_array($response) && isset($response['username'])) {
                $username = (string) $response['username'];
            } elseif (is_object($response) && isset($response->username)) {
                $username = (string) $response->username;
            }

            \MuruguardHelper::recordLoginFailure($ip, $username);
            \MuruguardHelper::recordAttackLogEntry([
                'type'       => 'bruteforce',
                'ip'         => $ip,
                'time'       => time(),
                'blocked'    => false,
                'rule'       => 'login_failure',
                'severity'   => 'medium',
                'why'        => 'Failed backend login attempt.',
                'matched'    => $username !== '' ? "username: {$username}" : '',
                'uri'        => '',
                'user_agent' => mb_substr((string) Factory::getApplication()->input->server->get('HTTP_USER_AGENT', '', 'string'), 0, 200),
            ]);
        } catch (\Throwable $e) {
            // Never let logging break the login flow itself.
        }
    }

    /**
     * Admin Lockdown, enforced where the user is actually created: refuses
     * any NEW user from the backend or the Web Services API, whatever task
     * name or controller form the request used. Frontend registration is
     * not affected.
     */
    public function onUserBeforeSave($oldUser, $isNew = false, $newUser = [])
    {
        try {
            if (!$isNew) return true;
            if (class_exists('MuruguardHelper', false) && method_exists('MuruguardHelper', 'isInternalUserCreate') && \MuruguardHelper::isInternalUserCreate()) return true;
            $app = Factory::getApplication();
            $isApi = method_exists($app, 'isClient') && $app->isClient('api');
            if (!self::isAdminClient($app) && !$isApi) return true;
            if (!ComponentHelper::getParams('com_muruguard')->get('harden_lock_admin_actions', 0)) return true;
            $app->enqueueMessage('Creating a new user is locked by MuRu Guard Admin Lockdown (Settings > Site Protection). Switch it off there first.', 'error');
            return false;
        } catch (\Throwable $e) {
            return true;
        }
    }

    public function onUserAfterSave($user, $isNew = false, $success = true, $msg = '')
    {
        $this->refreshProtectedBaselineAfterAdminChange($user, (bool) $success);
    }

    public function onUserAfterDelete($user, $success = true, $msg = '')
    {
        $this->refreshProtectedBaselineAfterAdminChange($user, (bool) $success);
    }

    /**
     * A Super User blocking, demoting or deleting an account in the
     * backend is a deliberate change: update the protected-user baseline
     * so the scheduled check doesn't "repair" it back.
     */
    private function refreshProtectedBaselineAfterAdminChange($user, bool $success): void
    {
        try {
            if (!$success || !$this->loadShieldHelper()) return;
            if (!method_exists('MuruguardHelper', 'refreshProtectedUserBaseline')) return;
            $app = Factory::getApplication();
            if (!self::isAdminClient($app)) return;
            $actor = self::getCurrentUser();
            if (!$actor || $actor->guest || !$actor->authorise('core.admin')) return;
            $id = is_array($user) ? (int) ($user['id'] ?? 0) : (int) ($user->id ?? 0);
            \MuruguardHelper::refreshProtectedUserBaseline($id);
        } catch (\Throwable $e) {
        }
    }

    /**
     * Bridges Joomla's own guest-reachable com_ajax entry point --
     * index.php?option=com_ajax&plugin=muruguardshield&group=system&format=raw&token=...
     * -- into com_muruguard's existing scheduledcheck() controller
     * action, so the webcron URL Settings shows customers actually works
     * for a real, unauthenticated cron caller.
     *
     * Why this bridge exists at all: Joomla core's
     * AdministratorApplication::findOption() (confirmed against real
     * Joomla 6 core source, @since 4.0.0 -- not new, not this site's own
     * config) hardcodes $allowedUnprivilegedOptions to exactly
     * ['com_login', 'com_ajax']. A GUEST request for ANY other option,
     * including com_muruguard itself, gets silently swapped to com_login
     * before it ever reaches scheduledcheck()'s own cron_enabled/token
     * check -- meaning a direct
     * option=com_muruguard&task=scanner.scheduledcheck hit from a real
     * external cron job (curl/wget, no session) has never actually run
     * on Joomla 4+; it only ever appeared to work when tested from an
     * already-logged-in browser tab. com_ajax is the one guest-reachable
     * admin entry point Joomla itself provides for exactly this case
     * (its own docblock: "administrative callbacks without logging in"),
     * and this plugin is already loaded on every single admin request
     * regardless of login state, so it's the natural bridge -- no new
     * plugin needed.
     *
     * scheduledcheck() still does its OWN complete cron_enabled/token
     * validation and echoes its own plain-text response before calling
     * Factory::getApplication()->close() on every path (success and
     * 403 alike) -- this method's only job is getting the request to
     * it at all; every actual authorization and response decision still
     * lives in exactly the one place it always has.
     *
     * Joomla 3 note: com_ajax there is a frontend-only component, and the
     * Joomla 3 administrator sends every signed-out visitor to the login
     * screen before com_ajax ever runs -- so on Joomla 3 the webcron URL
     * Settings shows points at the site frontend
     * (index.php?option=com_ajax&...) instead of /administrator. This
     * bridge method itself is identical on both platforms.
     */
    protected function runWebcronBridge(): void
    {
        // This bridge deliberately runs OUTSIDE Joomla's normal
        // option=com_muruguard dispatch (that's the whole point -- see
        // the docblock above), which means the legacy MVC autoloading
        // Joomla normally wires up for a component's own model/controller
        // classes when IT dispatches them is never registered here.
        // require_once-ing the controller file alone isn't enough:
        // scheduledcheck() below does `new MuruguardModelScanner()`, and
        // that class' own file was never required by anything in this
        // chain. Confirmed real, reported from a live site: this
        // surfaced as an uncaught "Class ... not found" fatal on every
        // scheduled cron hit -- and unlike every check in
        // onAfterInitialise() above, this method has no enclosing
        // try/catch, so the fatal was fully visible instead of failing
        // open silently. Load every class this call chain needs
        // explicitly, in dependency order, rather than depending on
        // ambient autoloading that only exists on the request shape this
        // bridge exists specifically to NOT go through.
        if (!$this->loadShieldHelper()) return; // component not installed -- nothing to bridge to

        $modelPath = JPATH_ADMINISTRATOR . '/components/com_muruguard/models/scanner.php';
        $controllerPath = JPATH_ADMINISTRATOR . '/components/com_muruguard/controllers/scanner.php';
        if (!is_file($modelPath) || !is_file($controllerPath)) return;

        require_once $modelPath;
        require_once $controllerPath;
        if (!class_exists('MuruguardControllerScanner')) return;

        $controller = new \MuruguardControllerScanner();
        $controller->scheduledcheck();
        // Unreachable: scheduledcheck() always calls $app->close() itself.
    }

    /**
     * True once com_muruguard's helper class is loaded and usable.
     * False (without throwing) if the component isn't installed --
     * this plugin has zero effect on its own, it is entirely inert
     * until its companion component is present.
     */
    private function loadShieldHelper(): bool
    {
        if (class_exists('MuruguardHelper')) return true;

        $helperPath = JPATH_ADMINISTRATOR . '/components/com_muruguard/helpers/muruguard.php';
        if (!is_file($helperPath)) return false;

        require_once $helperPath;
        return class_exists('MuruguardHelper');
    }

    private function runShieldCheck(): void
    {
        if (!$this->loadShieldHelper()) return;

        $params = ComponentHelper::getParams('com_muruguard');
        if (!$params->get('shield_enabled', 0)) return;

        $app   = Factory::getApplication();
        $input = $app->input;
        $ip    = \MuruguardHelper::resolveClientIp($input->server, (string) $params->get('shield_trusted_proxy_header', ''));

        // Manual IP allow/block list -- checked FIRST, ahead of every
        // other check below, including brute-force. An explicit "allow"
        // entry bypasses everything else entirely (a trusted admin IP or
        // monitoring service should never trip a pattern/country/brute-
        // force rule); an explicit "block" entry rejects unconditionally,
        // regardless of what the request itself looks like.
        if ($ip !== '') {
            $ipListResult = \MuruguardHelper::checkIpList($ip);
            if ($ipListResult === 'allow') return;
            if ($ipListResult === 'block') {
                \MuruguardHelper::recordAttackLogEntry([
                    'type'       => 'ip_list',
                    'ip'         => $ip,
                    'time'       => time(),
                    'blocked'    => true,
                    'rule'       => 'manual_ip_block',
                    'severity'   => 'high',
                    'why'        => 'IP blocked: matches a manually-added entry in the IP Access List.',
                    'matched'    => '',
                    'uri'        => mb_substr((string) $input->server->get('REQUEST_URI', '', 'string'), 0, 300),
                    'user_agent' => mb_substr((string) $input->server->get('HTTP_USER_AGENT', '', 'string'), 0, 200),
                ]);
                $this->rejectRequest();
                return;
            }
        }

        // Brute-force IP block -- regardless of who's asking, since an
        // attacker hammering the login form is by definition not an
        // authenticated user yet.
        // A private or proxy address is never brute-force blocked: behind an
        // unconfigured proxy every visitor shares it, so one attacker would
        // lock everyone out.
        if ($params->get('shield_block_bruteforce', 0) && $ip !== '' && !\MuruguardHelper::isPrivateOrReservedIp($ip)) {
            $threshold = (int) $params->get('shield_bruteforce_threshold', 5);
            $window    = (int) $params->get('shield_bruteforce_window', 15);

            if (\MuruguardHelper::isBruteForceThresholdExceeded($ip, $threshold, $window)) {
                \MuruguardHelper::recordAttackLogEntry([
                    'type'       => 'bruteforce',
                    'ip'         => $ip,
                    'time'       => time(),
                    'blocked'    => true,
                    'rule'       => 'bruteforce_threshold',
                    'severity'   => 'high',
                    'why'        => 'IP blocked: exceeded failed-login threshold.',
                    'matched'    => '',
                    'uri'        => mb_substr((string) $input->server->get('REQUEST_URI', '', 'string'), 0, 300),
                    'user_agent' => mb_substr((string) $input->server->get('HTTP_USER_AGENT', '', 'string'), 0, 200),
                ]);
                $this->rejectRequest();
                return;
            }
        }

        // Request-pattern AND country checks below never actively BLOCK a
        // user who genuinely has backend admin access -- core.login.admin
        // is the exact same permission Joomla itself uses to decide who
        // is even allowed to log into the administrator, deliberately
        // narrower than "any authenticated session": Joomla ships
        // frontend user registration on by default, so a self-registered
        // "Registered" account has NO admin access and gets full
        // protection, identical to a guest. A genuine admin's own
        // legitimate action (or their own IP resolving to a blocked
        // country while travelling/on a VPN) still never trips a false
        // block and locks them out of their own site -- but unlike
        // blocking, LOGGING is never skipped for them: an admin-exempt
        // match is still recorded (marked not-blocked), so this exemption
        // can't become a silent blind spot for an attacker who happens to
        // hold a low-privilege authenticated account.
        // getIdentity() is Joomla 4-only (Joomla 3: JFactory::getUser()).
        $user = self::getCurrentUser();
        $isAdminExempt = (bool) ($user && !$user->guest && $user->authorise('core.login.admin'));

        // Country block -- independent of, and checked before, pattern
        // matching. lookupCountryForIp() answers from the local DB-IP
        // database and fails open (returns null, never blocks) when that
        // database is missing or unreadable.
        if ($params->get('shield_block_countries', 0) && $ip !== '') {
            $blockedCountries = (string) $params->get('shield_blocked_countries', '');
            if ($blockedCountries !== '') {
                $country = \MuruguardHelper::lookupCountryForIp($ip);
                if (\MuruguardHelper::isCountryBlocked($country, $blockedCountries)) {
                    $blocked = !$isAdminExempt;
                    \MuruguardHelper::recordAttackLogEntry([
                        'type'       => 'country',
                        'ip'         => $ip,
                        'time'       => time(),
                        'blocked'    => $blocked,
                        'rule'       => 'country_block',
                        'severity'   => 'medium',
                        'why'        => "IP blocked: resolved to country {$country}, which is on the blocked-countries list.",
                        'matched'    => (string) $country,
                        'uri'        => mb_substr((string) $input->server->get('REQUEST_URI', '', 'string'), 0, 300),
                        'user_agent' => mb_substr((string) $input->server->get('HTTP_USER_AGENT', '', 'string'), 0, 200),
                    ]);
                    if ($blocked) {
                        $this->rejectRequest();
                        return;
                    }
                }
            }
        }

        $uri       = (string) $input->server->get('REQUEST_URI', '', 'string');
        $userAgent = (string) $input->server->get('HTTP_USER_AGENT', '', 'string');
        $get       = $input->get->getArray();
        $post      = $input->post->getArray();

        if ($this->runSppbGuard($params, $ip, $uri, $userAgent)) return;

        $match = \MuruguardHelper::scanRequestForAttack($get, $post, $uri, $userAgent);
        if ($match === null) return;

        // Bad-user-agent matches are gated behind their own dedicated
        // toggle, not the general pattern-block switch -- blocking on a
        // User-Agent string ALONE is a meaningfully different (and more
        // false-positive-prone) risk than an actual code-execution
        // payload in a query parameter, so an admin who wants one
        // shouldn't be forced to accept the other.
        // A logged-in admin is exempt from the softer rules, but a high-
        // severity exploit payload is still blocked for them, so a stolen
        // admin session can't carry one past the Shield. Backend form
        // posts stay exempt (an admin may legitimately save code).
        $adminBlocked = $match['rule'] !== 'known_scanner_user_agent'
            && $this->adminMatchStillBlocks($match, function () use ($get, $uri, $userAgent) {
                return \MuruguardHelper::scanRequestForAttack($get, [], $uri, $userAgent);
            });
        $shouldBlock = (!$isAdminExempt || $adminBlocked) && ($match['rule'] === 'known_scanner_user_agent'
            ? (bool) $params->get('shield_block_useragents', 0)
            : ($match['block_eligible'] && (bool) $params->get('shield_block_patterns', 0)));

        \MuruguardHelper::recordAttackLogEntry([
            'type'       => 'request',
            'ip'         => $ip,
            'time'       => time(),
            'blocked'    => $shouldBlock,
            'rule'       => $match['rule'],
            'severity'   => $match['severity'],
            'why'        => $match['why'],
            'matched'    => $match['matched_text'],
            'uri'        => mb_substr($uri, 0, 300),
            'user_agent' => mb_substr($userAgent, 0, 200),
        ]);

        if ($shouldBlock) {
            $this->rejectRequest();
        }
    }

    /**
     * Admin Lockdown -- an explicit opt-in toggle (off by default, same
     * as every other Shield gate) that blocks the two backend actions an
     * attacker who already has SOME admin access (a compromised session,
     * a webshell reached far enough to forge a request) would use to
     * turn that foothold into something durable: installing a brand new
     * malicious extension, or creating a fresh Super User account of
     * their own that survives a cleanup of whatever got them in.
     *
     * Deliberately does NOT touch com_joomlaupdate (Joomla's own core-
     * version updater) -- blocking that would actively work against
     * site security by preventing a genuine core patch from landing.
     * "Disable the installer" here means the *extension* installer only.
     *
     * Deliberately does NOT touch editing an existing user (including
     * the logged-in admin's own profile) -- only the CREATE path. Uses
     * the exact same `id` request var Joomla's own FormController::
     * save() reads to decide new-vs-edit (confirmed against the
     * installed Joomla core source, libraries/src/MVC/Controller/
     * FormController.php -- $recordId = $this->input->getInt($urlVar)
     * where $urlVar defaults to the table's key name, 'id' for
     * #__users -- NOT $_POST['jform']['id'], which FormController
     * overwrites with this same value before it ever reaches the model).
     */
    /**
     * SP Page Builder Guard: refuses requests to SP Page Builder that use the attack routes behind its reported holes
     * (see MuruguardHelper::sppbGuardMatch()). Reads the request as sent (Joomla's input filter would hide encoded
     * values) and a JSON body up to 1 MB. Returns true when the request was refused.
     */
    private function runSppbGuard($params, string $ip, string $uri, string $userAgent): bool
    {
        if (!(bool) $params->get('sppb_guard_endpoints', 1)) return false;
        $get  = is_array($_GET ?? null) ? $_GET : [];
        $post = is_array($_POST ?? null) ? $_POST : [];
        $json = stripos((string) ($_SERVER['CONTENT_TYPE'] ?? ''), 'json') !== false;
        $option = (string) ($get['option'] ?? $post['option'] ?? '');
        if (strtolower($option) !== 'com_sppagebuilder' && !$json) return false;
        try {
            if ($json) {
                $raw = (string) @file_get_contents('php://input', false, null, 0, 1048576);
                $body = $raw !== '' ? json_decode($raw, true) : null;
                if (is_array($body)) $post['__json_body'] = $body;
            }
            $match = \MuruguardHelper::sppbGuardMatch($get, $post);
        } catch (\Throwable $e) {
            return false;
        }
        if ($match === null) return false;
        \MuruguardHelper::recordAttackLogEntry([
            'type'       => 'request',
            'ip'         => $ip,
            'time'       => time(),
            'blocked'    => true,
            'rule'       => $match['rule'],
            'severity'   => $match['severity'],
            'why'        => $match['why'],
            'matched'    => $match['matched_text'],
            'uri'        => mb_substr($uri, 0, 300),
            'user_agent' => mb_substr($userAgent, 0, 200),
        ]);
        $this->rejectRequest();
        return true;
    }

    private function checkAdminLockdownGate(): void
    {
        $app = Factory::getApplication();
        // isClient() is Joomla 4-only (Joomla 3: isAdmin()).
        if (!self::isAdminClient($app)) return;

        $params = ComponentHelper::getParams('com_muruguard');
        if (!$params->get('harden_lock_admin_actions', 0)) return;

        $input = $app->input;
        $option = $input->getCmd('option', '');

        // "controller=user&task=save" is the same request as "task=user.save".
        $task = strtolower($input->getCmd('task', ''));
        $controller = strtolower($input->getCmd('controller', ''));
        if ($task !== '' && strpos($task, '.') === false && $controller !== '') $task = $controller . '.' . $task;

        // Other ways to put code on the site without com_installer: a
        // Joomla Update package upload (normal core updates still work)
        // and the template file editor.
        $blockInstaller = ($option === 'com_installer')
            || ($option === 'com_joomlaupdate' && $task === 'update.upload')
            || ($option === 'com_templates' && (in_array($task, ['template.createfile', 'template.uploadfile', 'template.copyfile', 'template.renamefile', 'template.extractarchive'], true)
                || (in_array($task, ['template.save', 'template.apply'], true) && $input->getString('file', '') !== '')));

        $blockNewUser = false;
        if ($option === 'com_users') {
            if (in_array($task, ['user.save', 'user.apply', 'user.save2copy', 'user.save2new'], true)) {
                $blockNewUser = ($input->getInt('id', 0) === 0) || $task === 'user.save2copy';
            }
        }

        if (!$blockInstaller && !$blockNewUser) return;

        // Every other check in this file guards with loadShieldHelper()
        // before its first MuruguardHelper:: use -- this one didn't,
        // which is a real (if silent) bug: onAfterInitialise() wraps this
        // call in try/catch(\Throwable), so a "Class not found" here
        // fails open silently rather than fataling visibly, but it still
        // means Admin Lockdown never actually blocked anything on a
        // request where nothing else in the SAME page load happened to
        // load the helper first.
        if (!$this->loadShieldHelper()) return;

        $ip = \MuruguardHelper::resolveClientIp($input->server, (string) $params->get('shield_trusted_proxy_header', ''));
        \MuruguardHelper::recordAttackLogEntry([
            'type'       => 'admin_lockdown',
            'ip'         => $ip,
            'time'       => time(),
            'blocked'    => true,
            'rule'       => $blockInstaller ? 'installer_locked' : 'new_user_locked',
            'severity'   => 'medium',
            'why'        => $blockInstaller
                ? 'The Joomla extension installer is locked down (MuRu Guard Settings > Site Protection > Admin Lockdown).'
                : 'Creating a new backend user is locked down (MuRu Guard Settings > Site Protection > Admin Lockdown).',
            'matched'    => $option . ($task !== '' ? '&task=' . $task : ''),
            'uri'        => mb_substr((string) $input->server->get('REQUEST_URI', '', 'string'), 0, 300),
            'user_agent' => mb_substr((string) $input->server->get('HTTP_USER_AGENT', '', 'string'), 0, 200),
        ]);

        // A logged-in admin hitting this is far more likely to be the
        // site owner themselves (forgot the toggle was on) than an
        // actual attacker, since it only fires once inside an already-
        // authenticated backend session -- so this explains itself and
        // sends them back, rather than the bare 403 the public-facing
        // gates above use against real unauthenticated attack traffic.
        //
        // CMSPlugin does NOT auto-load a plugin's own language file --
        // these two Text::_() calls are the only user-facing strings this
        // whole plugin ever shows (everything else is a silent block or a
        // log entry), so this was never exercised before Admin Lockdown
        // existed. Without this, Text::_() has nothing loaded to resolve
        // the key against and just echoes the raw language key back
        // ("PLG_SYSTEM_MURUGUARDSHIELD_LOCKDOWN_INSTALLER_MSG") instead of
        // the actual message -- confirmed real, reported from a live site.
        $this->loadLanguage();

        $app->enqueueMessage(
            $blockInstaller
                ? Text::_('PLG_SYSTEM_MURUGUARDSHIELD_LOCKDOWN_INSTALLER_MSG')
                : Text::_('PLG_SYSTEM_MURUGUARDSHIELD_LOCKDOWN_NEWUSER_MSG'),
            'warning'
        );
        $app->redirect('index.php');
    }

    /**
     * True when a high-severity, block-eligible match should still block a
     * logged-in admin. On the backend the request is checked again without
     * its POST body, so an admin saving content that contains code is not
     * blocked; only a payload in the URL or query string counts there.
     */
    private function adminMatchStillBlocks(?array $match, callable $rescanWithoutPost): bool
    {
        if ($match === null || ($match['severity'] ?? '') !== 'high' || empty($match['block_eligible'])) return false;
        try {
            if (!self::isAdminClient(Factory::getApplication())) return true;
            $again = $rescanWithoutPost();
        } catch (\Throwable $e) {
            return false;
        }
        return is_array($again) && ($again['severity'] ?? '') === 'high' && !empty($again['block_eligible']);
    }

    /** Plain-text 403 and an immediate, unconditional stop -- deliberately not the site's own error template, which could itself trigger more application code to run. */
    private function rejectRequest(): void
    {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo "Forbidden\n";
        Factory::getApplication()->close();
    }
}

if (defined('JVERSION') && version_compare(JVERSION, '4.0', '>=')) {
    class plgSystemMuruguardshield extends plgSystemMuruguardshieldBase
    {
        /**
         * Scheduled-scan bridge (see runWebcronBridge()). A guest com_ajax call
         * in the administrator is only allowed for a handler Joomla registers
         * directly, which needs this exact typed $event parameter, and newer
         * Joomla versions also require the attribute below. A legacy
         * no-argument handler made that check fail with an empty response,
         * which nginx answered with a 502. To PHP 7 the attribute line is a
         * plain comment.
         */
        #[\Joomla\CMS\Plugin\Attribute\AllowUnauthorizedAdministratorAccess]
        public function onAjaxMuruguardshield(\Joomla\Event\EventInterface $event)
        {
            $this->runWebcronBridge();
        }
    }
} else {
    class plgSystemMuruguardshield extends plgSystemMuruguardshieldBase
    {
        /** Scheduled-scan bridge on Joomla 3, which calls event handlers without arguments. */
        public function onAjaxMuruguardshield()
        {
            $this->runWebcronBridge();
        }
    }
}
