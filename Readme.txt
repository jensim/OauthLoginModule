===============================
== About this login provider ==
===============================

========================
== Expected knowledge ==
========================
* Jave SE, and a tad of EE
* Advanced OAuth client-server design pattern :: http://www.cloudidentity.com/blog/2013/01/02/oauth-2-0-and-sign-in-4/
* Module Installtion 
* Login Module configuration
* Security domain configuration


==================================
== MODULE Connection PARAMETERS ==
==================================
* db_url=jdbc:postgresql://127.0.0.1:5432/beardata
* db_user=postgres
* db_pass=password
* db_driver=org.postgresql.Driver
* query_get_user :: variables ${provider} and ${provider_user_id} are needed in the parameters
SELECT u.id FROM user u 
JOIN oauth_provider op ON u.oauth_provider_user_id = op.id 
WHERE u.oauth_provider_user_id = ${provider_user_id} 
AND op.name = ${provider};

* query_add_user :: variables ${provider} and ${provider_user_id} are needed in the parameters
INSERT INTO user(oauth_provider_id, oauth_provider_user_id) 
VALUES((SELECT id FROM oauth_provider WHERE name = ${provider}), ${provider_user_id});

* query_get_groups :: variables ${provider} and ${provider_user_id} are needed in the parameters
SELECT r.name 
FROM user_role r 
JOIN user u ON u.user_role_id = r.id 
JOIN oauth_provider op ON u.oauth_provider_id = op.id 
WHERE op.name = ${provider} 
AND u.oauth_provider_user_id = ${provider_user_id}

=============================
== MODULE OAuth PARAMETERS ==
=============================
Further more, i've taken the design decision to let the login module detect oauth providers dynamicly as they are added to the configuration.
How this works is that you add a set of parameters that end with '_provider', one for each oauth provider you want to implement for. For each provider you will need four to five extra parameters, and these are:
* _token
* _user
* _logout (optional)
* _client_id
* _secret

How this works is that when the login provider recognizes a parameter with the '_provider' ending, it will search for parameters starting with the same string as that parameter, only with additional endings and described in the past passage. The following example will show you how it might look:
* github_provider=github
* github_provider_token=https://github.com/login/oauth/access_token
* github_provider_user=https://api.github.com/user
* github_provider_client_id=2f292c6912e77
* github_provider_secret=e72e16c7e42f292c6912e7710c838347ae178b4a

*NOTE* that the VALUE (ie. 'github') of the '_provider'-parameter is will correspond to the ${provider} parameter in the Connection-PARAMETER section..
