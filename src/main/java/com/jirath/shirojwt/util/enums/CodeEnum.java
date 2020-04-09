package com.jirath.shirojwt.util.enums;

/**
 * @author Jirath
 * @date 2020/4/9
 * @description:
 */
public enum CodeEnum {
    // 数据操作错误定义
    SUCCESS(200, "成功!"),
    BODY_NOT_MATCH(400,"请求的数据格式不符!"),
    SIGNATURE_NOT_MATCH(401,"请求的数字签名不匹配!"),
    NOT_FOUND(404, "未找到该资源!"),
    INTERNAL_SERVER_ERROR(500, "服务器内部错误!"),
    ERROR_WX_CODE(508,"微信code异常"),
    ERROR_TOKEN(504,"token错误"),
    SERVER_BUSY(503,"服务器正忙，请稍后再试!")
    ;
    /** 错误码 */
    private Integer resultCode;

    /** 错误描述 */
    private String resultMsg;

    CodeEnum(Integer resultCode, String resultMsg) {
        this.resultCode = resultCode;
        this.resultMsg = resultMsg;
    }

    public Integer getResultCode() {
        return resultCode;
    }

    public String getResultMsg() {
        return resultMsg;
    }
}
