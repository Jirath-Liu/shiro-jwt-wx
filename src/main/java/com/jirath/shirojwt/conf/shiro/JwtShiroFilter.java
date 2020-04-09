package com.jirath.shirojwt.conf.shiro;

import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * <h1>BasicHttpAuthenticationFilter</h1>
 * <p>shiro会扫描项目中所有的filter并加入manager中</p>
 * <p>所有的请求都会被拦截，在请求头前标了shiro定制的header的请求会被识别</p>
 * <h1>JwtFilter</h1>
 * <p>这里定制一个filter，使得我们可以识别出有token的请求</p>
 * <p><b>注意！登录是在这里进行的！isAccessAllowed方法，主要完成了登录</b></p>
 *  <p>因为小程序的访问不是同一次访问，所以对于系统来说，若把session替换为了token，就要每次登录
 * </p>
 * @author Jirath
 * @date 2020/4/9
 * @description: 定制一个使用jwt的filter
 */
public class JwtShiroFilter extends BasicHttpAuthenticationFilter {
    /**
     * 判断用户是否想要进行 需要验证的操作
     * 检测header里面是否包含Authorization字段即可
     */
    @Override
    protected boolean isLoginAttempt(ServletRequest request, ServletResponse response) {
        return !StringUtils.isEmpty(getAuthzHeader(request));
    }

    /**
     * 此方法调用登陆，验证逻辑
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        if (isLoginAttempt(request, response)) {
            JwtShiroToken token = new JwtShiroToken(getAuthzHeader(request));
            getSubject(request, response).login(token);
        }
        return true;
    }

    /**
     * 提供跨域支持
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        httpServletResponse.setHeader("Access-control-Allow-Origin", httpServletRequest.getHeader("Origin"));
        httpServletResponse.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
        httpServletResponse.setHeader("Access-Control-Allow-Headers", httpServletRequest.getHeader("Access-Control-Request-Headers"));
        // 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
        if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
            httpServletResponse.setStatus(HttpStatus.OK.value());
            return false;
        }
        return super.preHandle(request, response);
    }
}
