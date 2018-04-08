package com.oauth.oauthserver;

import javax.annotation.Resource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;


//@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
//@Order(SecurityProperties.BASIC_AUTH_ORDER+2) 

//@Configuration
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
//@Order(-2)
public class AuthServerSecurityConfiguration extends WebSecurityConfigurerAdapter {
	 @Resource(name = "userService")
	    private UserDetailsService userDetailsService;
	@Autowired
	private AuthenticationManager authenticationManager;
	
	   @Override
	    @Bean
	    public AuthenticationManager authenticationManagerBean() throws Exception {
	        return super.authenticationManagerBean();
	    }

	    @Autowired
	    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
	        auth.userDetailsService(userDetailsService).passwordEncoder(encoder());
	    }

	
	/*@Override
	protected void configure(AuthenticationManagerBuilder auth)
			throws Exception {
		auth.inMemoryAuthentication()
			.withUser("user").password("userpwd").roles("USER")
			.and()
			.withUser("isa-client").password("isa-secret").roles("ADMIN")
			.and()
			.withUser("admin").password("adminpwd").roles("ADMIN")
			// FIXME : check_token api validates client credentials via basic authorization 
			.and()
			.withUser("soncrserv").password("soncrserv").roles("CLIENT");
		
		//auth.parentAuthenticationManager(authenticationManager);
	}*/
	
	@Override
	protected void configure(final HttpSecurity http) throws Exception {
		// @formatter:off
		/*http  .csrf().disable()
        .anonymous().disable()
			.formLogin().loginPage("/login").permitAll()
		.and()
			.requestMatchers().antMatchers("/login", "/oauth/authorize", "/oauth/token","/oauth/confirm_access")
		.and()
			.authorizeRequests().anyRequest().authenticated().and().authorizeRequests().antMatchers("/api-docs/**").permitAll();
*/

		
			 http
             .csrf().disable()
             .anonymous().disable()
             .authorizeRequests()
             .antMatchers("/api-docs/**").permitAll();
	/*http
		.csrf().disable()
		.anonymous().disable()
	  	.authorizeRequests()
	  	.antMatchers("/oauth/token").permitAll();*/
			
/*		
	http
		//.formLogin().loginPage("/login").permitAll()
	//.and()
		.requestMatchers().antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access")	
	
	.and().authorizeRequests().anyRequest().authenticated();*/

			// @formatter:on
	}
	
	 @Bean
	    public TokenStore tokenStore() {
	        return new InMemoryTokenStore();
	    }

	    @Bean
	    public BCryptPasswordEncoder encoder(){
	        return new BCryptPasswordEncoder();
	    }

	    @Bean
	    public FilterRegistrationBean corsFilter() {
	        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
	        CorsConfiguration config = new CorsConfiguration();
	        config.setAllowCredentials(true);
	        config.addAllowedOrigin("*");
	        config.addAllowedHeader("*");
	        config.addAllowedMethod("*");
	        source.registerCorsConfiguration("/**", config);
	        FilterRegistrationBean bean = new FilterRegistrationBean(new CorsFilter(source));
	        bean.setOrder(0);
	        return bean;
	    }
}
