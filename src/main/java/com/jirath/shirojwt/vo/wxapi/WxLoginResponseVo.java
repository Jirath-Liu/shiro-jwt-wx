package com.jirath.shirojwt.vo.wxapi;

import lombok.Data;

/**
 * @author Jirath
 * @date 2020/4/9
 * @description:
 */
@Data
public class WxLoginResponseVo {
    private String openid;
    private String session_key;
    private String unionid;
    private String errcode = "0";
    private String errmsg;
    private int expires_in;
}
