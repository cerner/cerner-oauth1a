# v2.0.0
Added APIs for authenticating Access Tokens, so that service providers can be implemented
with this library.

Behavior changes:
* accessor_secret is no longer required to construct a Cerner::OAuth1a::AccessToken
* token_secret is no longer required to construct a Cerner::OAuth1a::AccessToken
* expires_at is no longer required to construct a Cerner::OAuth1a::AccessToken

# v1.0.1
Correct confusing functionality within AccessToken#expired?, so that it's
no longer surprising and backwards.

# v1.0.0
Initial release
