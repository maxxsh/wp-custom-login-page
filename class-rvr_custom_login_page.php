<?php defined('ABSPATH') or die();


if ( ! class_exists('RVR_WP_Custom_Login_Page')) {
    class RVR_WP_Custom_Login_Page
    {
        public function __construct()
        {
            if (get_option('rvr_main_options')['login_page']) {
                add_action('login_head', array( $this,'rvr_login_head'));
            }
            add_action('login_form_lostpassword', array( $this,'action_validate_password_reset'), 10);            
            // trim(esc_url(add_query_arg($wp->request))
            if (trim($_SERVER['REQUEST_URI'], " /.") == get_option('rvr_main_options')['login_page'] && ($_GET['redirect'] !== false)) {
                add_action('init', array( $this,'rvr_login_init'));
            }
            add_action('login_form', array( $this,'rvr_login_hidden_field'));
            add_action('lostpassword_form', array( $this,'rvr_login_hidden_field'), 10, 0);
            add_action('wp_logout', array( $this,'rvr_redirect_after_logout'));
            add_filter('logout_url', array( $this,'filter_logout_url'), 10, 2);
            add_filter('lostpassword_url', array( $this,'rvr_filter_lostpassword_url'), 10, 2);
            add_filter('lostpassword_redirect', array( $this,'rvr_login_lostpassword_redirect'), 100, 1);
            //block redirecting from /login
            add_action(
                'init',
                function () {
                    remove_action('template_redirect', 'wp_redirect_admin_locations', 1000);
                }
            );
        }

        public function rvr_login_head()
        {
            $nonce = $_REQUEST['_rvrnonce'];
            $nonce = (string) $nonce;
            $i = wp_nonce_tick();
            $expected = substr(wp_hash($i . '|rvr-login-nonce|0|', 'nonce'), -12, 10);
            if (hash_equals($expected, $nonce)) {
                return false;
            } elseif (($_GET['action'] == 'lostpassword') || ($_GET['action'] == 'rp')) {
                return false;
            } else {
                wp_safe_redirect(home_url(), 302);
                exit();
            }
        }

        // Define the validate_password_reset callback
        public function action_validate_password_reset()
        {
            list($rp_path) = explode('?', wp_unslash($_SERVER['REQUEST_URI']));
            $rp_cookie = 'wp-resetpass-' . COOKIEHASH;
    
            if (isset($_GET['key'])) {
                $value = sprintf('%s:%s', wp_unslash($_GET['login']), wp_unslash($_GET['key']));
                setcookie($rp_cookie, $value, 0, $rp_path, COOKIE_DOMAIN, is_ssl(), true);    
                wp_safe_redirect(remove_query_arg(array( 'key', 'login' )));
                exit;
            }
    
            if (isset($_COOKIE[ $rp_cookie ]) && 0 < strpos($_COOKIE[ $rp_cookie ], ':')) {
                list($rp_login, $rp_key) = explode(':', wp_unslash($_COOKIE[ $rp_cookie ]), 2);
    
                $user = check_password_reset_key($rp_key, $rp_login);
    
                if (isset($_POST['pass1']) && ! hash_equals($rp_key, $_POST['rp_key'])) {
                    $user = false;
                }
            } else {
                $user = false;
            }
    
            if (! $user || is_wp_error($user)) {
                setcookie($rp_cookie, ' ', time() - YEAR_IN_SECONDS, $rp_path, COOKIE_DOMAIN, is_ssl(), true);
                if ($user && $user->get_error_code() === 'expired_key') {
                    $i = wp_nonce_tick();
                    $nonce = substr(wp_hash($i . '|rvr-login-nonce|0|', 'nonce'), -12, 10);
                    wp_redirect(site_url('wp-login.php?action=lostpassword&error=expiredkey&_rvrnonce='.$nonce));
                } else {
                    login_header(__('Password Reset'), '<div id="login_error">' . __('Your password reset link appears to be invalid.') . '</div>');
                    login_footer();
                    exit;
                }    
                exit;
            }
        }

        // Lost password url
        public function rvr_filter_lostpassword_url()
        {
            $nonce = $_REQUEST['_rvrnonce'];
            return site_url("wp-login.php?action=lostpassword&saferedirect&_rvrnonce={$nonce}");
        }
    

        public function rvr_login_lostpassword_redirect($lostpassword_redirect)
        {
            $nonce = $_REQUEST['_rvrnonce'];
            return site_url("wp-login.php?checkemail=confirm&redirect=false&saferedirect&_rvrnonce={$nonce}");
        }
    
        public function rvr_login_init()
        {
            //generate our nonce for ~ 12 hours
            $i = wp_nonce_tick();
            $nonce = substr(wp_hash($i . '|rvr-login-nonce|0|', 'nonce'), -12, 10);
            wp_safe_redirect(home_url("wp-login.php?saferedirect&_rvrnonce={$nonce}"));
            exit();
        }
    // Add the hidden field for login and lostpassword forms
        public function rvr_login_hidden_field()
        {
            global $nonce
    ?>
    	<input type="hidden" id="rvrnonce-field" name="_rvrnonce" value=<?php echo $_REQUEST['_rvrnonce']; ?> />
  <?php
        }

        // Redirect after logout to login page
        public function rvr_redirect_after_logout()
        {
            wp_safe_redirect(home_url(get_option('rvr_main_options')['login_page']));
            exit();
        }

        public function filter_logout_url($logout_url, $redirect)
        {
            if (! is_user_logged_in()) {
                return home_url();
            }
            return $logout_url;
        }
    }
    new RVR_WP_Custom_Login_Page;
}
