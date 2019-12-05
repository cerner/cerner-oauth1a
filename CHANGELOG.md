# v2.4.0
Handle nonce and timestamp as optional fields Per
https://tools.ietf.org/html/rfc5849#section-3.1, the oauth_timestamp and oauth_nonce
fields may be omitted when PLAINTEXT signatures are used. This commit make the APIs
related to those two fields treat the data as optional.

# v2.3.0
Added Protection Realm Equivalence feature to Cerner::OAuth1a::AccessTokenAgent,
which is used by Cerner::OAuth1a::AccessToken#authenticate when comparing realms.
This allows for realm aliases, so that the OAuth Service can transition hosts.

# v2.2.0
Renamed the cache key prefixes from 'cerner-oauth' cache prefixes to 'cerner-oauth1a'.

# v2.1.0
Added an attribute for the Protection Realm to Cerner::OAuth1a::AccessTokenAgent,
Cerner::OAuth1a::AccessToken, and Cerner::OAuth1a::OAuthError. This value will be
parsed as the canonical root URI of the agent's configured access_token_url. When
this value is available, it will be added to errors and generated authorization
headers.

# v2.0.1
Allow parsing authorization headers that do not include an oauth_version parameter as per
the spec:

```
oauth_version:
  OPTIONAL. If present, value MUST be 1.0 . Service Providers MUST assume the protocol
  version to be 1.0 if this parameter is not present. Service Providers' response to
  non-1.0 value is left undefined.
```

# v2.0.0
Added APIs for authenticating Access Tokens, so that service providers can be implemented
with this library. Additionally, caching mechanisms for AccessTokens and Keys has been
added.

Behavior changes:
* Caching of AccessTokens is on by default within Cerner::OAuth1a::AccessTokenAgent
* accessor_secret is no longer required to construct a Cerner::OAuth1a::AccessToken
* token_secret is no longer required to construct a Cerner::OAuth1a::AccessToken
* expires_at is no longer required to construct a Cerner::OAuth1a::AccessToken

# v1.0.1
Correct confusing functionality within AccessToken#expired?, so that it's
no longer surprising and backwards.

# v1.0.0
Initial release
