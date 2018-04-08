package com.oauth.oauthserver;

import java.util.Arrays;

import javax.annotation.Resource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;


@Configuration
@EnableWebSecurity


public class DemoSecurityConfig extends WebSecurityConfigurerAdapter {
	 @Resource(name = "userService")
	    private UserDetailsService userDetailsService;
	
	 @Override
	    @Bean
	    public AuthenticationManager authenticationManagerBean() throws Exception {
	        return super.authenticationManagerBean();
	    }
/*
	    @Autowired
	    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
	        auth.userDetailsService(userDetailsService).passwordEncoder(encoder());
	    }*/
	
	@Autowired
    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(encoder());
    }
	
	
//@Override
protected void configure8(AuthenticationManagerBuilder auth) throws Exception {
// add our users for in memory authentication
 
auth.inMemoryAuthentication().withUser("user1").password("test123").roles("EMPLOYEE");
auth.inMemoryAuthentication().withUser("user2").password("test123").roles("MANAGER");
auth.inMemoryAuthentication().withUser("user3").password("test123").roles("ADMIN");
	//auth.jdbcAuthentication()
 
}

//@Override
protected void configure1(final HttpSecurity http) throws Exception {
	
	/* http
     .csrf().disable()
     .anonymous().disable()
     .authorizeRequests()
     .antMatchers("/api-docs/**").permitAll();
*/
	/*http.authorizeRequests()
    .anyRequest().authenticated()
    .and()
    .oauth2Login();*/
	
	http
	.requiresChannel()
		.antMatchers("/oauth/token", "/oauth/token_key", "/oauth/check_token")
			.requiresSecure();
}
@Override
protected void configure(HttpSecurity http) throws Exception {
	http.authorizeRequests().anyRequest().authenticated().and().oauth2Login();
	
}

//@Override
protected void configure3(HttpSecurity http) throws Exception {
/**
 * @Value("${logout.success.url}")
    private String logoutSuccessUrl;
https://stackoverflow.com/questions/45391264/spring-boot-2-and-oauth2-jwt-configuration
 */
    // @formatter:off
    http
        .cors()
    .and()
        .csrf().disable().authorizeRequests()
        
    .and()
        .authorizeRequests()

        .antMatchers("/oauth/authorize","/oauth/token").authenticated()
       /* //Anyone can access the urls
        .antMatchers("/images/**").permitAll()
        .antMatchers("/signin/**").permitAll()
        .antMatchers("/v1.0/**").permitAll()
        .antMatchers("/auth/**").permitAll()
        .antMatchers("/actuator/health").permitAll()
        .antMatchers("/actuator/**").hasAuthority(Permission.READ_ACTUATOR_DATA)*/
        .antMatchers("/login").permitAll()
        .anyRequest().authenticated();
   /* .and()
        .formLogin()
           
            .permitAll()
        .and()
            .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/logout")
                .permitAll();*/
    // @formatter:on
}





@Bean
public BCryptPasswordEncoder encoder(){
    return new BCryptPasswordEncoder();
}

@Bean
public CorsFilter corsFilter1() {
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowCredentials(true);
    config.addAllowedOrigin("*");
    config.addAllowedHeader("*");
    config.addAllowedMethod("*");
    source.registerCorsConfiguration("/**", config);
    return new CorsFilter(source);
}
}