package com.springboot.bank.security.config;

import com.springboot.bank.security.JwtAuthenticationEntryPoint;
import com.springboot.bank.security.JwtAuthenticationTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * 安全配置类
 *
 * @author SONG
 */
@SuppressWarnings("SpringJavaAutowiringInspection")
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  private JwtAuthenticationEntryPoint unauthorizedHandler;

  @Autowired
  private UserDetailsService userDetailsService;

  @Autowired
  public void configureAuthentication(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
    authenticationManagerBuilder
        // 设置 UserDetailsService
        .userDetailsService(this.userDetailsService)
        // 使用 BCrypt 进行密码的 hash
        .passwordEncoder(passwordEncoder());
  }

  /**
   * 装载 BCrypt 密码编码器
   *
   * @return
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public JwtAuthenticationTokenFilter authenticationTokenFilterBean() throws Exception {
    return new JwtAuthenticationTokenFilter();
  }

  /**
   * token请求授权
   *
   * @param httpSecurity
   * @throws Exception
   */
  @Override
  protected void configure(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
        // we don't need CSRF because our token is invulnerable
        .csrf().disable()
        .cors().and() // 跨域

        .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()

        // don't create session
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()

        .authorizeRequests()
        //.antMatchers(HttpMethod.OPTIONS, "/**").permitAll()

        // allow anonymous resource requests
        .antMatchers(
            HttpMethod.GET,
            "/",
            "/*.html",
            "/favicon.ico",
            "/**/*.html",
            "/**/*.css",
            "/**/*.js"
        ).permitAll()

        // Un-secure 登录 验证码
        .antMatchers(
            "/api/auth/**",
            "/api/imagecode",
            "/api/global_json"
        ).permitAll()
        // secure other api
        .anyRequest().authenticated();

    // Custom JWT based security filter
    // 将token验证添加在密码验证前面
    httpSecurity
        .addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);

    // disable page caching
    httpSecurity
        .headers()
        .cacheControl();
  }
}
