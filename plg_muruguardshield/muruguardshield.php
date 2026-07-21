<?php
/**
 * @package     plg_system_muruguardshield
 * @author      ZKRANA <zkranao@gmail.com>
 * @license     MIT
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

use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Component\ComponentHelper;

class plgSystemMuruguardshield extends CMSPlugin
{
    /**
     * Fires on every request, before routing. Every code path below is
     * wrapped in a try/catch that swallows any Throwable -- this plugin
     * runs on EVERY page load of the entire site (frontend, backend,
     * API, everything), so a bug here must never be able to fatal the
     * whole site over a security feature meant to protect it.
     */
    public function onAfterInitialise()
    {
        try {
            $this->runShieldCheck();
        } catch (\Throwable $e) {
            // Fail open, silently -- see class docblock.
        }
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

            $ip = (string) Factory::getApplication()->input->server->get('REMOTE_ADDR', '', 'string');
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
                'user_agent' => (string) Factory::getApplication()->input->server->get('HTTP_USER_AGENT', '', 'string'),
            ]);
        } catch (\Throwable $e) {
            // Never let logging break the login flow itself.
        }
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
        $ip    = (string) $input->server->get('REMOTE_ADDR', '', 'string');

        // Brute-force IP block -- checked first and regardless of who's
        // asking, since an attacker hammering the login form is by
        // definition not an authenticated user yet.
        if ($params->get('shield_block_bruteforce', 0) && $ip !== '') {
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

        // Request-pattern checks are skipped for already-authenticated,
        // non-guest users. A genuine unauthenticated RCE/webshell
        // attacker is by definition not logged in -- exempting real
        // admin sessions avoids the actually-dangerous failure mode
        // here, which is an admin's own legitimate action tripping a
        // false block and locking THEM out of their own site.
        $user = $app->getIdentity();
        if ($user && !$user->guest) return;

        $uri       = (string) $input->server->get('REQUEST_URI', '', 'string');
        $userAgent = (string) $input->server->get('HTTP_USER_AGENT', '', 'string');
        $get       = $input->get->getArray();
        $post      = $input->post->getArray();

        $match = \MuruguardHelper::scanRequestForAttack($get, $post, $uri, $userAgent);
        if ($match === null) return;

        $shouldBlock = $match['block_eligible'] && (bool) $params->get('shield_block_patterns', 0);

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

    /** Plain-text 403 and an immediate, unconditional stop -- deliberately not the site's own error template, which could itself trigger more application code to run. */
    private function rejectRequest(): void
    {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo "Forbidden\n";
        Factory::getApplication()->close();
    }
}
