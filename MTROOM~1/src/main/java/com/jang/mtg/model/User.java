package com.jang.mtg.model;

import javax.validation.constraints.NotEmpty;

public class User {

	private int no;
	@NotEmpty(message = "id�? ?��?��?���? ?��?��?��?��?��.!")
	private String id;
	@NotEmpty(message = "?��?��?��?���? ?��?��?���? ?��?��?��?��?��.!")
	private String pass;
	private String pass2;
	@NotEmpty(message="?��름이 ?��?��?���? ?��?��?��?��?��")
	private String name;
	@NotEmpty(message="?��?��번호�? ?��?��?���? ?��?��?��?��?��")
	private String zip;
	@NotEmpty(message="주소�?�? ?��?��?���? ?��?��?��?��?��")
	private String addr1;
	@NotEmpty(message="?��?��주소�? ?��?��?���? ?��?��?��?��?��")
	private String addr2;
	@NotEmpty(message="?��?��번호�? ?��?��?���? ?��?��?��?��?��")
	private String phone;
	@NotEmpty(message="email ?��?��?���? ?��?��?��?��?��")
	private String email;
	
	private String birthday;
	
	

	public String getPass2() {
		return pass2;
	}

	public void setPass2(String pass2) {
		this.pass2 = pass2;
	}

	public int getNo() {
		return no;
	}

	public void setNo(int no) {
		this.no = no;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getPass() {
		return pass;
	}

	public void setPass(String pass) {
		this.pass = pass;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getZip() {
		return zip;
	}

	public void setZip(String zip) {
		this.zip = zip;
	}

	public String getAddr1() {
		return addr1;
	}

	public void setAddr1(String addr1) {
		this.addr1 = addr1;
	}

	public String getAddr2() {
		return addr2;
	}

	public void setAddr2(String addr2) {
		this.addr2 = addr2;
	}

	public String getPhone() {
		return phone;
	}

	public void setPhone(String phone) {
		this.phone = phone;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getBirthday() {
		return birthday;
	}

	public void setBirthday(String birthday) {
		this.birthday = birthday;
	}

}
