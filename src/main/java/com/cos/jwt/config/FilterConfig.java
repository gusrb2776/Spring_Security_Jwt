package com.cos.jwt.config;

import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<MyFilter1> filter1() {
        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
        bean.addUrlPatterns("/*");  // 모든 주소에 걸기
        bean.setOrder(0);           // 낮은 번호가 필터에서 가장 먼저 실행이 됨,.

        return bean;
    }

    /**
     * 필터를 하나 더 걸고싶으면 이렇게 하면 됨.
     */
    @Bean
    public FilterRegistrationBean<MyFilter2> filter2() {
        FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
        bean.addUrlPatterns("/*");  // 모든 주소에 걸기
        bean.setOrder(1);           // 낮은 번호가 필터에서 가장 먼저 실행이 됨,.

        return bean;
    }
}
