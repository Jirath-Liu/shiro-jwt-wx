package com.jirath.shirojwt.vo;

import lombok.Builder;
import lombok.Data;

/**
 * @author Jirath
 * @date 2020/4/9
 * @description:
 */
@Data
@Builder
public class ResultVo {
    Integer code;
    Object data;
    String msg;

    public ResultVo(Integer code, Object data, String msg) {
        this.code = code;
        this.data = data;
        this.msg = msg;
    }
}
