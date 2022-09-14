# Quarkus MFA

## Overview

A [Quarkus](https://quarkus.io/) extension that provides enhanced form based authentication. It provides strong native authentication to supplement or replace the preferred [OIDC authentication mechanism](https://quarkus.io/guides/security-openid-connect-web-authentication). Setting up and administrating one or more external OIDC identity providers may not be practical for all applications and application administrators could get locked out of their Quarkus based application if they self manage their OIDC configuration with the Quarkus OIDC [multi-tenant](https://quarkus.io/guides/security-openid-connect-multitenancy) capability. 

## Features
The Quarkus MFA extension is similar to the built-in [form based authentication mechanism](https://quarkus.io/guides/security-built-in-authentication#form-auth) and it provides the following features:

* An encrypted cookie is used to track authentication state, similar to the form based authentication mechanism
* A [JWE](https://en.wikipedia.org/wiki/JSON_Web_Encryption) [JWT](https://en.wikipedia.org/wiki/JSON_Web_Token), similar to the OIDC ID Token except encrypted, is saved as a cookie and is used to track authentication state.
* As a user proceeds through the authentication flow the authentication context JWE is eventally upgraded to an authenticated session cookie, similar to the OIDC extension.
* Time Based One-Time Password ([TOTP](https://en.wikipedia.org/wiki/Time-based_one-time_password)) support
* Plugable [Identity Store](quarkus-mfa/src/main/java/io/github/aaronanderson/quarkus/mfa/runtime/MfaIdentityStore.java) implementations allow interactions with back-end Cloud database user stores
* Account Lock
* Password Reset
* TOTP QR Code Key Registration
* TOTP Passcode Validation
* Application provided login and log out presentation pages
* [MVC](https://en.wikipedia.org/wiki/Model%E2%80%93view%E2%80%93controller) presentation support allowing views to be rendered based on the login state
* Single Page Application ([SPA](https://en.wikipedia.org/wiki/Single-page_application)) Support
    * The authentication [action controller](https://github.com/aaronanderson/quarkus-mfa/blob/96b4b11c40491cb3f5e45b8223b404ca6f70f5ca/runtime/src/main/java/io/github/aaronanderson/quarkus/mfa/runtime/MfaAuthenticationMechanism.java#L116) supports both HTML form encoding and JSON
    * SPAs can perform a GET request to obtain details about the current authentication state
    * Based on authentication state SPAs can post login attempts, password resets, or TOTP passcode validation requests and respond accordingly based on the result. 
    * The authentication context cookie gets updated identically to the forms based login mechanism


## Installation

1. Add the extension to the Quarkus web application's Maven pom.xml
    ```
     <dependency>
	 	<groupId>io.github.aaronanderson</groupId>
  		<artifactId>quarkus-mfa</artifactId>
    	<version>1.0.0-SNAPSHOT</version>
     </dependency>
    ```

1. Create an [MFA Identity Store](quarkus-mfa/src/main/java/io/github/aaronanderson/quarkus/mfa/runtime/MfaIdentityStore.java) implementation. This [TestMfaIdentityStore.java](quarkus-mfa-integration-tests/src/main/java/io/github/aaronanderson/quarkus/mfa/it/TestMfaIdentityStore.java) example can be used as a reference.

1. Create login views or use SPA javascript to perform authentication actions like the ones performed in the [integration tests](quarkus-mfa-integration-tests/src/test/java/io/github/aaronanderson/quarkus/mfa/it/QuarkusMfaResourceTest.java)
