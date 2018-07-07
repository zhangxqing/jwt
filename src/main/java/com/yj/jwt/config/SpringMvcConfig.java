package com.yj.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import com.yj.jwt.interceptor.JwtInterceptor;

@Configuration
@ComponentScan(basePackages = { "com.yj.jwt.interceptor" })
public class SpringMvcConfig extends WebMvcConfigurerAdapter {   
	
	@Bean
	public JwtInterceptor jwtInterceptor() {
		return new JwtInterceptor();
	}
	
    @Override    
    public void addInterceptors(InterceptorRegistry registry) {    
        registry.addInterceptor(jwtInterceptor()).addPathPatterns("/*").excludePathPatterns("/login").excludePathPatterns("/loginPage").excludePathPatterns("/pwdError").excludePathPatterns("/sysError");    
    }    
}   
