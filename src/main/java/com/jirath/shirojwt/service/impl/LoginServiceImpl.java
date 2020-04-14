package com.jirath.shirojwt.service.impl;

import com.alibaba.fastjson.JSONObject;
import com.jirath.shirojwt.conf.exceptionconfig.exception.WxApiException;
import com.jirath.shirojwt.conf.jwt.JwtUtil;
import com.jirath.shirojwt.dao.UserDao;
import com.jirath.shirojwt.pojo.User;
import com.jirath.shirojwt.service.LoginService;
import com.jirath.shirojwt.util.enums.WxApiEnum;
import com.jirath.shirojwt.vo.wxapi.WxLoginResponseVo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

/**
 * @author Jirath
 * @date 2020/4/9
 * @description:
 */
@Service
public class LoginServiceImpl implements LoginService {
    @Value("${app.id}")
    private String appid;
    @Value("${app.secret}")
    private String appSecret;
    @Autowired
    RestTemplate restTemplate;
    @Autowired
    UserDao userDao;
    @Autowired
    JwtUtil jwtUtil;

    /**
     * @param code
     * @return
     */
    @Override
    public String login(String code) throws WxApiException {
        String resultJson = analysisInfo(code);
        WxLoginResponseVo wxResponse = JSONObject.toJavaObject(JSONObject.parseObject(resultJson), WxLoginResponseVo.class);
        if (!wxResponse.getErrcode().equals("0")) {
            throw new WxApiException("请求微信api失败 : " + wxResponse.getErrmsg());
        } else {
            //3 . 先从本地数据库中查找用户是否存在
            User userInfo = userDao.findByWxOpenid(wxResponse.getOpenid());
            String sessionKey = wxResponse.getSession_key();
            //不存在就新建用户
            if (userInfo == null) {
                userInfo = new User(wxResponse.getOpenid(), "佚名", "0000-00-00", "未知", sessionKey);
                userDao.newUser(userInfo);
            } else {
                //4 . 更新sessionKey和 登陆时间
                userInfo.setSessionKey(sessionKey);
                userDao.fixSessionKeyById(userInfo);
            }
            //5 . JWT 返回自定义登陆态 Token
            String token = jwtUtil.createTokenByWxAccount(userInfo);
            return token;
        }

    }

    /**
     * 使用code获得微信api的用户json信息
     *
     * @param code
     * @return
     */
    private String analysisInfo(String code) {
        String code2SessionUrl = WxApiEnum.LOGIN_URL.getString();
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("appid", appid);
        params.add("secret", appSecret);
        params.add("js_code", code);
        params.add("grant_type", "authorization_code");
        URI code2Session = getURIwithParams(code2SessionUrl, params);
        return restTemplate.exchange(code2Session, HttpMethod.GET, new HttpEntity<String>(new HttpHeaders()), String.class).getBody();
    }

    /**
     * URI工具类
     *
     * @param url    url
     * @param params 参数
     * @return URI
     */
    private URI getURIwithParams(String url, MultiValueMap<String, String> params) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(url).queryParams(params);
        return builder.build().encode().toUri();
    }
}
