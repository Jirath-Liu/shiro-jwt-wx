package com.jirath.shirojwt.pojo;

import lombok.*;

import java.util.Date;

/**
 * @author Jirath
 */
@Data
public class User {

  private Integer id;
  private String wxId;
  private String name;
  private String birthday;
  private String occupation;
  private java.util.Date gmtCreate;
  private java.util.Date gmtModified;
  private String sessionKey;

  public User(){}
  public User( String wxId, String name, String birthday, String occupation,  String sessionKey) {
    this.wxId = wxId;
    this.name = name;
    this.birthday = birthday;
    this.occupation = occupation;
    this.sessionKey = sessionKey;
  }
}
