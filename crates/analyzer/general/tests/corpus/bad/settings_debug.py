# EXPECT: gen_web_debug_enabled
# EXPECT: gen_web_insecure_cookie
# EXPECT: gen_web_cors_wildcard
DEBUG = True
SESSION_COOKIE_SECURE = False
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True
