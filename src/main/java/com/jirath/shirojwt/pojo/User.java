package com.jirath.shirojwt.pojo;

import java.util.Date;

/**
 * @author Jirath
 */
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

  public Integer getId() {
    return id;
  }

  public void setId(Integer id) {
    this.id = id;
  }

  public String getWxId() {
    return wxId;
  }

  public void setWxId(String wxId) {
    this.wxId = wxId;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getBirthday() {
    return birthday;
  }

  public void setBirthday(String birthday) {
    this.birthday = birthday;
  }

  public String getOccupation() {
    return occupation;
  }

  public void setOccupation(String occupation) {
    this.occupation = occupation;
  }

  public Date getGmtCreate() {
    return gmtCreate;
  }

  public void setGmtCreate(Date gmtCreate) {
    this.gmtCreate = gmtCreate;
  }

  public Date getGmtModified() {
    return gmtModified;
  }

  public void setGmtModified(Date gmtModified) {
    this.gmtModified = gmtModified;
  }

  public String getSessionKey() {
    return sessionKey;
  }

  public void setSessionKey(String sessionKey) {
    this.sessionKey = sessionKey;
  }
}
