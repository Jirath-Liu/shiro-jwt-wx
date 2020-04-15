package com.jirath.shirojwt.vo;

/**
 * @author Jirath
 * @date 2020/4/9
 * @description:
 */

public class ResultVo {
    private Integer code;
    private Object data;
    private String msg;

    public ResultVo(Integer code, Object data, String msg) {
        this.code = code;
        this.data = data;
        this.msg = msg;
    }

    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }
    public static ResultVoBuilder builder(){
        return new ResultVoBuilder();
    }
    public static class ResultVoBuilder{
        Integer code;
        Object data;
        String msg;
        public ResultVoBuilder code(Integer code){
            this.code=code;
            return  this;
        }
        public ResultVoBuilder data(Object data){
            this.data=data;
            return this;
        }
        public ResultVoBuilder msg(String msg){
            this.msg=msg;
            return this;
        }
        public ResultVo build(){
            return new ResultVo(this.code,this.data,this.msg);
        }
    }
}
