package com.jirath.shirojwt.controller;

import com.jirath.shirojwt.service.LoginService;
import com.jirath.shirojwt.vo.ResultVo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.constraints.NotNull;

/**
 * @author Jirath
 * @date 2020/4/9
 * @description:
 */
@RestController(value = "/api")
public class LoginController {
    @Autowired
    LoginService loginService;

    /**
     * 微信小程序用户登陆，完整流程可参考下面官方地址，本例中是按此流程开发
     * https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/login.html
     * 使用code与小程序信息获取用户信息
     * @param code 小程序使用 wx.login 获取到的code
     * @return
     */
    @RequestMapping(value = "/wx/user/sign_in")
    public ResultVo login(@NotNull String code){
        return ResultVo.builder()
                .code(200)
                .data(loginService.login(code))
                .msg("getToken")
                .build();
    }
}
