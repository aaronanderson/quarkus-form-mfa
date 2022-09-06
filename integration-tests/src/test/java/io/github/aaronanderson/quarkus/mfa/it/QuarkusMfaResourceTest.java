package io.github.aaronanderson.quarkus.mfa.it;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.filter.cookie.CookieFilter;

@QuarkusTest
public class QuarkusMfaResourceTest {

	@Test
    public void testPublicAccess() {
        given()
                .when().get("/public")
                .then()
                .statusCode(200)
                .body(is("Public"));
    }
	
    @Test
    public void testLoginSuccess() {
    	 CookieFilter cookieFilter = new CookieFilter();
    	 
        given()
        		.filter(cookieFilter)
                .when().get("/")
                .then()
                .statusCode(200)
                .body(is("Login"));
       
        
      //RestAssure doesn't automatically follow POST 302 redirects and cookies are lost on 303 redirects https://github.com/rest-assured/rest-assured/issues/396
      //Manually redirect.
       String location = given()
        .filter(cookieFilter)
        .contentType("application/x-www-form-urlencoded; charset=utf-8")
            .formParam("grant_type", "password")
            .formParam("username", "jdoe1")
            .formParam("password", "trustno1")
        .when()
            .post("/mfa_action")
            .then()
            .statusCode(302)
            .extract().header("Location");
        
       given()
		.filter(cookieFilter)
       .when().get(location)
       .then()
       .statusCode(200)
       .body(is("Main"));

    }
}
