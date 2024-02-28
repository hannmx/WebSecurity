package com.hannmx.WebSecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class WebSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(WebSecurityApplication.class, args);
	}

	@EnableWebSecurity
	public static class WebSecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests()
					.antMatchers("/private-data").hasRole("ADMIN")
					.antMatchers("/public-data").authenticated()
					.and()
					.formLogin()
					.and()
					.logout()
					.logoutSuccessUrl("/login");
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER")
					.and()
					.withUser("admin").password("password").roles("ADMIN");
		}

		@Bean
		public PasswordEncoder passwordEncoder() {
			// Используем NoOpPasswordEncoder для удобства, но в реальном приложении следует использовать более безопасный способ хеширования паролей
			return NoOpPasswordEncoder.getInstance();
		}
	}
}
