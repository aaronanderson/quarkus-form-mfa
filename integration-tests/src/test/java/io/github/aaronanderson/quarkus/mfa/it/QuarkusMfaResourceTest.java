package io.github.aaronanderson.quarkus.mfa.it;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

import java.security.GeneralSecurityException;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;

import io.github.aaronanderson.quarkus.mfa.runtime.MfaAuthConstants.FormFields;
import io.quarkus.arc.Arc;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.filter.cookie.CookieFilter;

@QuarkusTest
public class QuarkusMfaResourceTest {

	@Test
	public void testPublicAccess() {
		given().when().get("/public")
		.then()
		.statusCode(200)
	    .contentType("application/json")
	    .body("public", Matchers.equalTo(true));
	}

	@Test
    public void testLoginSuccess() throws GeneralSecurityException {
    	 CookieFilter cookieFilter = new CookieFilter();
    	 String location = assertMainRedirect(cookieFilter);
    	 assertLoginPage(location,"login", null,  cookieFilter);
         location = assertLoginAction("jdoe1", "trustno1", cookieFilter);
         assertLoginPage(location, "verify-totp", null, cookieFilter);
         location = assertVerifyAction("jdoe1", cookieFilter);
         assertMainAuthenticated(location, cookieFilter);
    }
    
  @Test
    public void testZeroPageLogin() throws GeneralSecurityException {
    	 CookieFilter cookieFilter = new CookieFilter();
    	 String location = assertLoginAction("jdoe1", "trustno1", cookieFilter);
         location = assertVerifyAction("jdoe1", cookieFilter);
         assertMainAuthenticated(location, cookieFilter);
    }
    
    @Test
    public void testLogout() throws GeneralSecurityException {
    	 CookieFilter cookieFilter = new CookieFilter();
    	 String location = assertMainRedirect(cookieFilter);
    	 assertLoginPage(location,"login", null,  cookieFilter);
         location = assertLoginAction("jdoe1", "trustno1", cookieFilter);
         assertLoginPage(location, "verify-totp", null, cookieFilter);
         location = assertVerifyAction("jdoe1", cookieFilter);
         assertMainAuthenticated(location, cookieFilter);
         assertLogoutPage(cookieFilter);
         //Logout is expiring the cookie but it is still being sent by RestAssured
         //assertMainRedirect(cookieFilter);
         
    }
	
	@Test
    public void testLoginFailed() throws GeneralSecurityException {
    	 CookieFilter cookieFilter = new CookieFilter();
    	 String location = assertMainRedirect(cookieFilter);
    	 assertLoginPage(location, "login", null, cookieFilter);
         location = assertLoginAction("jdoe1", "invalid", cookieFilter);
         assertLoginPage(location, "login", "failed", cookieFilter);
         
    }
    
	@Test
    public void testMfaExemptLoginSuccess() {
    	 CookieFilter cookieFilter = new CookieFilter();
    	 String location = assertMainRedirect(cookieFilter);
    	 assertLoginPage(location,"login", null,  cookieFilter);
         location = assertLoginAction("jdoe2", "trustno1", cookieFilter);
         assertMainAuthenticated(location, cookieFilter);
    }
    
    @Test
    public void testAccountLocked() throws GeneralSecurityException {
    	 CookieFilter cookieFilter = new CookieFilter();
    	 String location = assertMainRedirect(cookieFilter);
    	 assertLoginPage(location,"login", null,  cookieFilter);
         location = assertLoginAction("jdoe3", "trustno1", cookieFilter);
         assertLoginPage(location, "login", "account-locked", cookieFilter);
         
    }
    
    @Test
    public void testPasswordReset() throws GeneralSecurityException {
		 CookieFilter cookieFilter = new CookieFilter();
		 String location = assertMainRedirect(cookieFilter);
		 assertLoginPage(location,"login", null,  cookieFilter);
	     location = assertLoginAction("jdoe4", "trustno1", cookieFilter);
	     assertLoginPage(location, "password-reset", null, cookieFilter);
	     location = assertPasswordResetAction("invalid","trustno2", cookieFilter);
	     assertLoginPage(location, "password-reset", "failed-current", cookieFilter);
	     location = assertPasswordResetAction("trustno1","pw", cookieFilter);
	     assertLoginPage(location, "password-reset", "failed-policy", cookieFilter);
	     location = assertPasswordResetAction("trustno1","trustno2", cookieFilter);
	     assertLoginPage(location, "verify-totp", null, cookieFilter);
	     location = assertVerifyAction("jdoe4", cookieFilter);
         assertMainAuthenticated(location, cookieFilter);
         assertLogoutPage(cookieFilter);
         cookieFilter = new CookieFilter();//reset cookies just to be sure
         location = assertMainRedirect(cookieFilter);
    	 assertLoginPage(location,"login", null,  cookieFilter);
         location = assertLoginAction("jdoe4", "trustno2", cookieFilter);
         assertLoginPage(location, "verify-totp", null, cookieFilter);
         location = assertVerifyAction("jdoe4", cookieFilter);
         assertMainAuthenticated(location, cookieFilter);
         
    }
    
    @Test
    public void testRegister() throws GeneralSecurityException {
    	 CookieFilter cookieFilter = new CookieFilter();
    	 String location = assertMainRedirect(cookieFilter);
    	 assertLoginPage(location,"login", null,  cookieFilter);
         location = assertLoginAction("jdoe5", "trustno1", cookieFilter);
         assertLoginPage(location, "register-totp", null, cookieFilter);
         //should be able to bypass these two step
         //assertRegisterAction(cookieFilter);
         //assertLoginPage(location, "verify-totp", null, cookieFilter);
		 location = assertVerifyAction("jdoe5", cookieFilter);
         assertMainAuthenticated(location, cookieFilter);
         
         
    }
	

	
	private String assertMainRedirect(CookieFilter cookieFilter) {
		 String location = given()
 		.filter(cookieFilter)
 		.redirects().follow(false)
         .when().get("/")         
         .then()
         .statusCode(302)       
         .extract().header("Location");
		 Assertions.assertTrue(location.endsWith("/mfa_login"));
		 return location;
	}	
	private void assertMainAuthenticated(String location, CookieFilter cookieFilter) {

		 given()
			.filter(cookieFilter)
	       .when().get(location)
	       .then()
	       .statusCode(200)
	       .contentType("application/json")
	       .body("main", Matchers.equalTo(true));
	}
	
	private void assertLoginPage(String location, String action, String status, CookieFilter cookieFilter) {
		 assertLoginPage(location, action, status, false, cookieFilter);
	
	}
	
	private void assertLoginPage(String location, String action, String status, boolean totpURL, CookieFilter cookieFilter) {
		 given()
			.filter(cookieFilter)
	       .when().get(location)
	       .then()
	       .statusCode(200)
	       .contentType("application/json")
	       .body("action", Matchers.equalTo(action))
	       .body("status", status!=null? Matchers.equalTo(status): not(hasValue(nullValue())))
		   .body("totp-url", totpURL? hasValue(nullValue()) : not(hasValue(nullValue())));
	}
	
	private void assertLogoutPage(CookieFilter cookieFilter) {
		 given()
			.filter(cookieFilter)
	       .when().get("/mfa_logout")
	       .then()
	       .statusCode(200)
	       .contentType("application/json")
	       .body("action", Matchers.equalTo("logout"))
	       .body("status", not(hasValue(nullValue())));
	}
	
	
	private String assertLoginAction(String username, String password, CookieFilter cookieFilter) {
	      //RestAssure doesn't automatically follow POST 302 redirects and cookies are lost on 303 redirects https://github.com/rest-assured/rest-assured/issues/396
	      //Manually redirect.

		return given()
        .filter(cookieFilter)
        .contentType("application/x-www-form-urlencoded; charset=utf-8")
            .formParam(FormFields.USERNAME.toString(), username)
            .formParam(FormFields.PASSWORD.toString(), password)
        .when()
            .post("/mfa_action")
            .then()
            .statusCode(302)
            .extract().header("Location");
	}
	
	private String assertVerifyAction(String username, CookieFilter cookieFilter) throws GeneralSecurityException {
		TestMfaIdentityStore store = Arc.container().instance(TestMfaIdentityStore.class).get();
		//String totpKey, 
		String passcode = TimeBasedOneTimePasswordUtil.generateCurrentNumberString(store.totpKey(username));
		return given()
      .filter(cookieFilter)
       .contentType("application/x-www-form-urlencoded; charset=utf-8")
       .formParam(FormFields.PASSCODE.toString(), passcode)
      .when()
          .post("/mfa_action")
          .then()
          .statusCode(302)
          .extract().header("Location");
	}
	
	private String assertPasswordResetAction(String currentPassword, String newPassword, CookieFilter cookieFilter) throws GeneralSecurityException {
		
		return given()
      .filter(cookieFilter)
       .contentType("application/x-www-form-urlencoded; charset=utf-8")
       .formParam(FormFields.PASSWORD.toString(), currentPassword)
       .formParam(FormFields.NEW_PASSWORD.toString(), newPassword)
      .when()
          .post("/mfa_action")
          .then()
          .statusCode(302)
          .extract().header("Location");
	}
	
	private String assertRegisterAction(CookieFilter cookieFilter) throws GeneralSecurityException {		
		return given()
      .filter(cookieFilter)
       .contentType("application/x-www-form-urlencoded; charset=utf-8")       
      .when()
          .post("/mfa_action")
          .then()
          .statusCode(302)
          .extract().header("Location");
	}
	
	
}
