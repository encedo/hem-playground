
// ---- appended by hem-playground/test/run-tester.sh: a playground module instead of my.ence.do ----
$cfg_tester = getenv('TESTER') ?: "HEM Playground";
$cfg_ppa_domain = getenv('HEM_DOMAIN') ?: "test.localhost";
if (getenv('AUTHKEY')) $cfg_authkey = getenv('AUTHKEY');
if (getenv('DEBUG')) $cfg_debug = intval(getenv('DEBUG'));
