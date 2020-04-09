package com.jirath.shirojwt.conf.shiro;

import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Jirath
 * @date 2020/4/9
 * @description:
 */
@Configuration
public class ShiroConf {
    /**
     * <h1>FactoryBean</h1>
     * FactoryBean to be used in Spring-based web applications for defining the master Shiro Filter.
     * <h1>factoryBean.setFilters</h1>
     * <p>Sets the filterName-to-Filter map of filters available for reference when creating filter chain definitions.
     * Note: This property is optional: this FactoryBean implementation will discover all beans in the web application context that implement the Filter interface and automatically add them to this filter map under their bean name.
     * </p>
     * <code>
     *  Map<String, Filter> filterMap = new HashMap<>();
     *  filterMap.put("jwt", new JwtFilter());
     *  factoryBean.setFilters(filterMap);
     * </code></br>
     * <p><b>上述代码的目的是生成自定义的filter用来过滤请求</b></p>
     * @param securityManager
     * @return
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(DefaultWebSecurityManager securityManager){
        ShiroFilterFactoryBean shiroFilterFactoryBean=new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        //注册拦截方案
        Map<String, Filter> filterMap = new HashMap<>();
        filterMap.put("token", new JwtShiroFilter());
        shiroFilterFactoryBean.setFilters(filterMap);
        //定义拦截规则
        Map<String, String> filterRuleMap = new HashMap<>();
        //登陆相关api不需要被过滤器拦截
        filterRuleMap.put("/api/wx/user/login/**", "anon");
        filterRuleMap.put("/api/response/**", "anon");
        // 所有请求通过JWT Filter
        filterRuleMap.put("/**", "token");
        return shiroFilterFactoryBean;
    }

    /**
     * 因为本项目只用了一个Realm，所以使用了构造器进行初始化，该构造器只适合单Realm的情况
     * @param tokenRealm
     * @return
     */
    @Bean
    public DefaultWebSecurityManager securityManager(TokenRealm tokenRealm){
        DefaultWebSecurityManager defaultWebSecurityManager=new DefaultWebSecurityManager(tokenRealm);
        //设置realm
        defaultWebSecurityManager.setRealm(tokenRealm);
        //关闭session
        DefaultSubjectDAO subjectDAO = (DefaultSubjectDAO) defaultWebSecurityManager.getSubjectDAO();
        DefaultSessionStorageEvaluator evaluator = (DefaultSessionStorageEvaluator) subjectDAO.getSessionStorageEvaluator();
        evaluator.setSessionStorageEnabled(Boolean.FALSE);
        subjectDAO.setSessionStorageEvaluator(evaluator);
        return defaultWebSecurityManager;
    }

/**
 * ============================= Shiro注解设置  ===============================================
 */
    /**
     *  开启Shiro的注解(如@RequiresRoles,@RequiresPermissions),需借助SpringAOP扫描使用Shiro注解的类,并在必要时进行安全逻辑验证
     * 配置以下两个bean(DefaultAdvisorAutoProxyCreator和AuthorizationAttributeSourceAdvisor)即可实现此功能
     * @return
     */
    @Bean
    public DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator(){
        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        advisorAutoProxyCreator.setProxyTargetClass(true);
        return advisorAutoProxyCreator;
    }

    /**
     * 开启aop注解支持
     * @param securityManager
     * @return
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(DefaultWebSecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }
}
