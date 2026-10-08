<?php
/**
 * JED-readiness static checks for MuRu Guard.
 *
 * Plain PHP, zero dependencies -- runs anywhere PHP exists:
 *   php tests/static-checks.php
 *
 * Guards the properties the Joomla Extension Directory cares about that a
 * syntax linter can't see: no remote assets in the admin page, the
 * vendored stylesheet covers every utility class the sources reference,
 * manifests declare update servers + media, the installer script handles
 * preflight/uninstall, and every shipped directory carries an index.html.
 * Exit code is 0 when everything passes, 1 otherwise.
 */

$root = dirname(__DIR__);
$failures = [];

$fail = function (string $message) use (&$failures) {
    $failures[] = $message;
    fwrite(STDERR, "FAIL: $message\n");
};

$read = function (string $path) use ($root, $fail) {
    $contents = @file_get_contents($root . '/' . $path);
    if ($contents === false) {
        $fail("cannot read $path");
        return null;
    }
    return $contents;
};

// --- 1. No remote assets in the admin template -------------------------------
$tmpl = $read('com_muruguard/admin/views/scanner/tmpl/default.php');
if ($tmpl !== null) {
    if (preg_match('/<script[^>]+src=["\']https?:\/\//i', $tmpl)) {
        $fail('admin template loads a remote <script> -- all JS must ship inside the package');
    }
    if (preg_match('/<link[^>]+href=["\']https?:\/\//i', $tmpl)) {
        $fail('admin template loads a remote <link> stylesheet -- all CSS must ship inside the package');
    }
    if (strpos($tmpl, 'cdn.tailwindcss.com') !== false) {
        $fail('admin template still references the Tailwind CDN');
    }
}

// --- 2. Vendored stylesheet exists and is scoped -------------------------------
$cssPath = $root . '/com_muruguard/media/css/muruguard.css';
$css = @file_get_contents($cssPath);
if ($css === false || strlen($css) < 10000) {
    $fail('com_muruguard/media/css/muruguard.css is missing or suspiciously small -- run scripts/build.sh');
    $css = '';
} elseif (strpos($css, '#muruguard-root') === false) {
    $fail('vendored stylesheet is not scoped to #muruguard-root');
}

// --- 3. Every referenced utility class has a rule in the stylesheet ------------
if ($css !== '') {
    // Custom (non-Tailwind) classes defined in the template's own <style>.
    $custom = ['active', 'anim-in', 'tbl-wrap', 'high', 'medium', 'shield-pulse', 'null', 'true', 'false', ':'];
    $sources = [
        'com_muruguard/admin/views/scanner/tmpl/default.php',
        'com_muruguard/admin/views/scanner/view.html.php',
        'com_muruguard/admin/helpers/muruguard.php',
        'com_muruguard/admin/helpers/hardening.php',
        'com_muruguard/admin/controllers/scanner.php',
        'com_muruguard/admin/models/scanner.php',
        'com_muruguard/admin/language/en-GB/en-GB.com_muruguard.ini',
        'plg_muruguardshield/muruguardshield.php',
    ];
    $tokens = [];
    foreach ($sources as $source) {
        $text = $read($source);
        if ($text === null) {
            continue;
        }
        preg_match_all('/class=\\\\?"([^"]+)\\\\?"/', $text, $m);
        $attrs = $m[1];
        preg_match_all("/className\\s*=\\s*'([^']+)'/", $text, $m2);
        preg_match_all("/classList\\.(?:add|remove|toggle)\\(\\s*'([^']+)'/", $text, $m3);
        foreach (array_merge($attrs, $m2[1], $m3[1]) as $attr) {
            foreach (preg_split('/\\s+/', $attr) as $token) {
                $token = trim($token);
                if ($token === '' || strpbrk($token, '$?<>"\'()') !== false) {
                    continue; // PHP fragment inside a dynamic class attribute.
                }
                if (!preg_match('/^[A-Za-z0-9!\\-_:\\/\\[\\].#]+$/', $token)) {
                    continue;
                }
                $tokens[$token] = true;
            }
        }
    }
    $missing = [];
    foreach (array_keys($tokens) as $token) {
        if (in_array($token, $custom, true) || strncmp($token, 'muru', 4) === 0) {
            continue;
        }
        $needle = '.' . preg_replace_callback(
            '/[^a-zA-Z0-9_-]/',
            function ($m) {
                return '\\' . $m[0];
            },
            $token
        );
        $found = false;
        $offset = 0;
        while (($pos = strpos($css, $needle, $offset)) !== false) {
            $next = $css[$pos + strlen($needle)] ?? '';
            if ($next === '' || strpos("{,.:# [>+~\n\r\t", $next) !== false) {
                $found = true;
                break;
            }
            $offset = $pos + 1;
        }
        if (!$found) {
            $missing[] = $token;
        }
    }
    if ($missing !== []) {
        $fail('stylesheet is missing rules for: ' . implode(', ', $missing) . ' -- rebuild with scripts/build.sh');
    }
}

// --- 4. Manifests ---------------------------------------------------------------
$comXml = $read('com_muruguard/muruguard.xml');
if ($comXml !== null) {
    foreach (['<media', '<updateservers>', '<scriptfile>script.php</scriptfile>'] as $required) {
        if (strpos($comXml, $required) === false) {
            $fail("com_muruguard/muruguard.xml is missing $required");
        }
    }
    if (strpos($comXml, '<description>COM_MURUGUARD_XML_DESCRIPTION</description>') === false) {
        $fail('component manifest <description> must be the COM_MURUGUARD_XML_DESCRIPTION language string');
    }
    if (!preg_match('/<version>\d+\.\d+\.\d+<\/version>/', $comXml, $comVer)) {
        $fail('component manifest <version> is not X.Y.Z');
        $comVer = null;
    }
}

$plgXml = $read('plg_muruguardshield/muruguardshield.xml');
if ($plgXml !== null && strpos($plgXml, '<updateservers>') === false) {
    $fail('plugin manifest is missing <updateservers> (JED requires update support)');
}

$pkgXml = $read('pkg_muruguard/pkg_muruguard.xml');
if ($pkgXml !== null) {
    foreach (['com_muruguard.zip', 'plg_muruguardshield.zip'] as $child) {
        if (strpos($pkgXml, $child) === false) {
            $fail("package manifest does not reference $child");
        }
    }
    if (isset($comVer) && $comVer !== null && strpos($pkgXml, $comVer[0]) === false) {
        $fail('package manifest <version> must track the component version ' . $comVer[0]);
    }
    // JED requires update-server support on every listing, the package
    // listing included -- and the bundle needs its own sys.ini so its
    // translated install name (not the pkg_-prefixed key) is what the
    // installer, the Manage list, and JED Checker all see.
    foreach (['<updateservers>', '<languages'] as $required) {
        if (strpos($pkgXml, $required) === false) {
            $fail("package manifest is missing $required");
        }
    }
}

// --- 4b. Package display name (what JED Checker validates) ----------------------
// Mirrors JED Checker's own top-level name rules: the translated install
// name must not start with a type prefix, must not contain a reserved
// whole word (module/plugin/component/template/extension/free -- even
// "(Free)" fails this), and stays within 40 characters to avoid even a
// warning. The JED listing name must match this string exactly.
$pkgSysIni = $read('pkg_muruguard/language/en-GB/en-GB.pkg_muruguard.sys.ini');
if ($pkgSysIni !== null) {
    foreach (['PKG_MURUGUARD=', 'PKG_MURUGUARD_XML_DESCRIPTION='] as $key) {
        if (strpos($pkgSysIni, $key) === false) {
            $fail("en-GB.pkg_muruguard.sys.ini is missing $key");
        }
    }
    if (preg_match('/^PKG_MURUGUARD="([^"]+)"$/m', $pkgSysIni, $pkgName)) {
        $displayName = $pkgName[1];
        if (preg_match('/^\s*(?:mod|com|plg|tpl|pkg)_/i', $displayName)) {
            $fail("package display name '$displayName' starts with a type prefix");
        }
        if (preg_match('/\b(?:module|plugin|component|template|extension|free)\b/i', $displayName)) {
            $fail("package display name '$displayName' contains a JED-reserved word");
        }
        if (preg_match('/[^\x20-\x7E]/', $displayName)) {
            $fail('package display name must be plain ASCII');
        }
        if (strlen($displayName) > 40) {
            $fail("package display name '$displayName' is over JED Checker's 40-character warning limit");
        }
    } else {
        $fail('en-GB.pkg_muruguard.sys.ini has no parseable PKG_MURUGUARD value');
    }
}

// --- 5. Installer script: preflight + uninstall ----------------------------------
$script = $read('com_muruguard/script.php');
if ($script !== null) {
    foreach (['function preflight', 'function uninstall'] as $required) {
        if (strpos($script, $required) === false) {
            $fail("com_muruguard/script.php is missing $required()");
        }
    }
}

// --- 6. Language keys --------------------------------------------------------------
$sysIni = $read('com_muruguard/admin/language/en-GB/en-GB.com_muruguard.sys.ini');
if ($sysIni !== null && strpos($sysIni, 'COM_MURUGUARD_XML_DESCRIPTION=') === false) {
    $fail('sys.ini is missing COM_MURUGUARD_XML_DESCRIPTION');
}
// JED Checker warns when the translated extension name differs from the
// admin menu label -- keep them identical so the install name, the menu,
// and the Manage list all show the same string.
if ($sysIni !== null && $comXml !== null) {
    $nameOk = preg_match('/^COM_MURUGUARD="([^"]+)"$/m', $sysIni, $sysName);
    $menuOk = preg_match('/<menu[^>]*>([^<]+)<\/menu>/', $comXml, $menuName);
    if (!$nameOk || !$menuOk) {
        $fail('cannot parse component display name or menu label for comparison');
    } elseif ($sysName[1] !== $menuName[1]) {
        $fail("component display name '{$sysName[1]}' differs from admin menu '{$menuName[1]}'");
    }
}
$ini = $read('com_muruguard/admin/language/en-GB/en-GB.com_muruguard.ini');
if ($ini !== null) {
    foreach ([
        'COM_MURUGUARD_ADVISORY_LINK=',
        'COM_MURUGUARD_UPDATE_TO_VERSION=',
        'COM_MURUGUARD_NO_FIXED_VERSION=',
        'COM_MURUGUARD_GO_TO_UPDATES=',
    ] as $key) {
        if (strpos($ini, $key) === false) {
            $fail("en-GB.com_muruguard.ini is missing $key");
        }
    }
}

// --- 7. index.html in every shipped directory --------------------------------------
foreach (['com_muruguard', 'plg_muruguardshield', 'pkg_muruguard'] as $tree) {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root . '/' . $tree, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    foreach ($iterator as $file) {
        if ($file->isDir() && !is_file($file->getPathname() . '/index.html')) {
            $fail('missing index.html in ' . substr($file->getPathname(), strlen($root) + 1));
        }
    }
}

// --- 8. No runtime data files tracked in helpers/data/ ------------------------------
// (.htaccess is an intentional shipped file -- defence in depth for the
// data dir -- not runtime data.)
$shippedData = ['index.html', 'joomla_core_checksums.php', '.htaccess'];
exec('git -C ' . escapeshellarg($root) . ' ls-files com_muruguard/admin/helpers/data', $tracked, $gitCode);
if ($gitCode === 0) {
    foreach ($tracked as $trackedFile) {
        if (!in_array(basename($trackedFile), $shippedData, true)) {
            $fail("runtime data file must not be tracked: $trackedFile");
        }
    }
}

// --- 9. Package element must match the manifest filename ---------------------------
// Joomla derives a package's #__extensions.element as 'pkg_' + cmd-filtered
// <packagename> (PackageAdapter::getElement), but copies + looks up the
// installed manifest by the manifest FILE's basename
// (administrator/manifests/packages/<basename>). If those two disagree,
// install succeeds and then uninstall can never find its manifest:
// "Package Uninstall: Missing manifest file." -- with no UI recovery.
// This guards that invariant. (Mirrors InputFilter::cleanCmd exactly:
// strip everything outside A-Z 0-9 _ . -, then ltrim leading dots.)
$pkgManifestPath = $root . '/pkg_muruguard/pkg_muruguard.xml';
$pkgManifestBasename = basename($pkgManifestPath);
if ($pkgXml !== null) {
    if (preg_match('/<packagename>([^<]+)<\/packagename>/', $pkgXml, $pkgName)) {
        $cmdCleaned = ltrim(preg_replace('/[^A-Z0-9_.-]/i', '', $pkgName[1]), '.');
        $expectedBasename = 'pkg_' . $cmdCleaned . '.xml';
        if ($expectedBasename !== $pkgManifestBasename) {
            $fail(
                "package <packagename>{$pkgName[1]}</packagename> derives element 'pkg_{$cmdCleaned}' "
                . "(Joomla looks for '{$expectedBasename}' at uninstall) but the manifest file is "
                . "'{$pkgManifestBasename}' -- uninstall would fail with 'Missing manifest file'"
            );
        }
    } else {
        $fail('package manifest is missing <packagename>');
    }
}

// --- 10. Joomla 3 compatibility guards ----------------------------------------
// Supported range is Joomla 3.10+ (PHP 7.4+) through 6.x (PHP 8.1+). Joomla
// 3 ships the legacy J-prefixed API instead of the Joomla\CMS namespaced
// one, so every J4-only class reference and method call must live behind
// the one version branch in helpers/compat.php (plus the Shield plugin's
// own self-contained fallback, since the plugin must also load -- inertly
// -- without the component installed). These guards fail the build if a
// J4-only API is ever used anywhere else, so "works on J4, fatals on J3"
// can never ship silently again.
$compat = $read('com_muruguard/admin/helpers/compat.php');
if ($compat !== null) {
    foreach (
        [
            'JControllerLegacy',
            'JModelLegacy',
            'JViewLegacy',
            'JPlugin',
            'JAccessExceptionNotallowed',
            'class MuruguardCompat',
            'function isJoomla4',
            'function getDatabase',
            'function getUser',
            'function getSession',
            'function isAdminClient',
        ] as $required
    ) {
        if (strpos($compat, $required) === false) {
            $fail("helpers/compat.php is missing $required");
        }
    }
}

// Code-only view of a PHP file: comments stripped, so documentation that
// NAMES a Joomla 4-only API ("getIdentity() is Joomla 4-only") never trips
// these gates -- only real calls do.
$codeOnly = function (string $text): string {
    $out = '';
    foreach (token_get_all($text) as $token) {
        if (is_array($token)) {
            if ($token[0] === T_COMMENT || $token[0] === T_DOC_COMMENT) {
                continue;
            }
            $out .= $token[1];
        } else {
            $out .= $token;
        }
    }
    return $out;
};

$phpFiles = [];
foreach (['com_muruguard', 'plg_muruguardshield'] as $tree) {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root . '/' . $tree, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($iterator as $file) {
        if ($file->isFile() && substr($file->getPathname(), -4) === '.php') {
            $phpFiles[] = substr($file->getPathname(), strlen($root) + 1);
        }
    }
}
sort($phpFiles);

// needle => relative paths where it is allowed to appear. (The plugin's
// single getIdentity() lives inside its guarded getCurrentUser() static,
// which is why the plugin file is allowed there.)
$j4OnlyGates = [
    'getIdentity()' => [
        'com_muruguard/admin/helpers/compat.php',
        'plg_muruguardshield/muruguardshield.php',
    ],
    '->getSession()' => ['com_muruguard/admin/helpers/compat.php'],
    '->isClient(' => [
        'com_muruguard/admin/helpers/compat.php',
        'plg_muruguardshield/muruguardshield.php',
    ],
];
foreach ($phpFiles as $phpFile) {
    $text = @file_get_contents($root . '/' . $phpFile);
    if ($text === false) {
        continue; // unreadable files already fail their own sections.
    }
    $code = $codeOnly($text);
    foreach ($j4OnlyGates as $needle => $allowedFiles) {
        if (strpos($code, $needle) !== false && !in_array($phpFile, $allowedFiles, true)) {
            $fail("$needle is Joomla 4-only and must only appear in " . implode(', ', $allowedFiles) . " (found in $phpFile)");
        }
    }
    // Table\Extension / Table\Asset only exist under Joomla\CMS on 4+; the
    // legitimate uses must sit next to the version branch that keeps them
    // off the Joomla 3 path.
    foreach (['Table\\Extension', 'Table\\Asset'] as $tableClass) {
        if (strpos($code, $tableClass) !== false && strpos($code, 'isJoomla4') === false) {
            $fail("$phpFile references $tableClass without a neighbouring isJoomla4() branch");
        }
    }
}

// Every alias loop must probe the alias, load the original, then probe the
// alias AGAIN before declaring: Joomla 3's own loader materialises its
// core-registered forward alias for the same modern name as a side effect
// of loading the legacy class, and re-declaring it emits "Cannot declare
// class" warnings that corrupt JSON responses and abort the scan (live
// bug, Joomla 3.10). Two no-autoload probes per file in CODE (comments
// stripped, so documenting the probe doesn't satisfy the count), all
// using the same $alias loop variable so this one count covers every copy.
foreach (
    [
        'com_muruguard/admin/helpers/compat.php',
        'plg_muruguardshield/muruguardshield.php',
        'com_muruguard/script.php',
    ] as $aliasFile
) {
    $aliasText = $read($aliasFile);
    if ($aliasText !== null && substr_count($codeOnly($aliasText), 'class_exists($alias, false)') < 2) {
        $fail("$aliasFile must re-check class_exists(\$alias, false) after loading the original (see section comment)");
    }
}

// Joomla 3 core files that generic heuristics must not flag: exact
// Joomla 3.10 core files that tripped them on a live 3.10 site (cli/ +
// bin/ loose-file allowlists, stray index.php, malicious-filename
// patterns). The Joomla 4+ lists stay tight; the version split itself is
// executed by tests, not just asserted as strings (see below).
$helperSrc = $read('com_muruguard/admin/helpers/muruguard.php');
if ($helperSrc !== null) {
    foreach (
        [
            'JOOMLA3_CORE_EXACT_PATHS',
            'function isJoomla3CoreExactPath',
            'finder_indexer.php',
            'sessionGc.php',
            'sessionMetadataGc.php',
            'keychain.php',
            'administrator/components/com_finder/controllers/index.php',
            'administrator/components/com_finder/models/index.php',
            'administrator/components/com_privacy/controllers/request.xml.php',
        ] as $required
    ) {
        if (strpos($helperSrc, $required) === false) {
            $fail("helpers/muruguard.php is missing $required");
        }
    }
    // The J3 loose-file map must be both DEFINED (signatures key) and
    // CONSULTED (checkCoreMasquerade branch) -- two occurrences.
    if (substr_count($helperSrc, 'CORE_LOOSE_FILE_ALLOWLIST_JOOMLA3') < 2) {
        $fail('helpers/muruguard.php must define and consult CORE_LOOSE_FILE_ALLOWLIST_JOOMLA3');
    }
}
$modelSrc = $read('com_muruguard/admin/models/scanner.php');
if ($modelSrc !== null && strpos($modelSrc, 'isJoomla3CoreExactPath') === false) {
    $fail('models/scanner.php must consult isJoomla3CoreExactPath() in the filename-pattern loop');
}

// The J4 radio switcher layout does not exist on Joomla 3 (verified: no
// layouts/joomla/form/field/radio/switcher.php on the 3.10 branch), so a
// config.xml using it breaks System > Global Configuration on J3.
$configXml = $read('com_muruguard/admin/config.xml');
if ($configXml !== null && strpos((string) preg_replace('/<!--.*?-->/s', '', $configXml), 'radio.switcher') !== false) {
    $fail('config.xml uses the Joomla 4 radio switcher layout, which does not exist on Joomla 3');
}

if ($script !== null) {
    if (strpos($script, "'3.10.0'") === false) {
        $fail('installer script must allow Joomla 3.10+ (MIN_JOOMLA_VERSION 3.10.0)');
    }
    if (strpos($script, "'7.4.0'") === false) {
        $fail('installer script must set a PHP 7.4 floor for Joomla 3');
    }
}

$shield = $read('plg_muruguardshield/muruguardshield.php');
if ($shield !== null) {
    foreach (['JPlugin', "version_compare(JVERSION, '4.0'"] as $required) {
        if (strpos($shield, $required) === false) {
            $fail("shield plugin is missing its Joomla 3 fallback ($required)");
        }
    }
}

foreach (
    [
        'com_muruguard/admin/muruguard.php',
        'com_muruguard/admin/helpers/muruguard.php',
    ] as $entryFile
) {
    $entryText = $read($entryFile);
    if ($entryText !== null && strpos($entryText, 'compat.php') === false) {
        $fail("$entryFile must load helpers/compat.php before any Joomla API use");
    }
}

// --- 11. PHP 7.4 syntax floor (Joomla 3 hosts) ---------------------------------
// CI lints on PHP 7.4 as well (see .github/workflows/ci.yml), but a local
// `php` is usually 8.x, which silently accepts 8-only syntax. Tripwire for
// the common cases -- not exhaustive, but catches the usual accidents.
$php8Needles = ['?->', 'str_contains(', 'str_starts_with(', 'str_ends_with(', '#[', 'readonly ', ': mixed'];
foreach ($phpFiles as $phpFile) {
    $text = @file_get_contents($root . '/' . $phpFile);
    if ($text === false) {
        continue;
    }
    // Same comment-stripping as section 10, so prose like "severity match
    // (tagged" in a docblock never trips the match() check below.
    $code = $codeOnly($text);
    foreach ($php8Needles as $needle) {
        if (strpos($code, $needle) !== false) {
            $fail("$phpFile uses PHP 8-only syntax ($needle) -- the Joomla 3 floor is PHP 7.4");
        }
    }
    // A standalone match() expression (PHP 8); the boundary guard excludes
    // preg_match()/fnmatch().
    if (preg_match('/(^|[^\w\x80-\xff])match\s*\(/m', $code)) {
        $fail("$phpFile uses a PHP 8 match() expression -- the Joomla 3 floor is PHP 7.4");
    }
}

if ($failures !== []) {
    fwrite(STDERR, count($failures) . ' static check(s) failed.' . "\n");
    exit(1);
}

echo "All JED-readiness static checks passed.\n";
