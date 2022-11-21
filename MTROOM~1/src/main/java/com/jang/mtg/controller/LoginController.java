package com.jang.mtg.controller;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import org.apache.ibatis.annotations.Param;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.jang.doc.utils.AES256Util;
import com.jang.mtg.model.User;
import com.jang.mtg.service.UserService;





@Controller
public class LoginController {

	@Autowired // @Resource(name="userService")
	private UserService userService;

	@RequestMapping(value = "/login", method = RequestMethod.GET) 
	public String toLoginView(Model model) {

		model.addAttribute("user", new User());
		return "login";

	}

	@RequestMapping(value = "/login", method = RequestMethod.POST) 
	public String onSubmit(@Valid User user, BindingResult result, Model model,HttpSession session) {

		if (result.hasFieldErrors("id") || result.hasFieldErrors("pass")) {
			model.addAllAttributes(result.getModel());
			return "login";
		}
		try {

			BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

			
			User loginUser = this.userService.getUser(user.getId());
			
			if (loginUser==null) {
				model.addAllAttributes(result.getModel());
				return "login";
			}
			

			if (passwordEncoder.matches(user.getPass(), loginUser.getPass())) {

				session.setAttribute("userId",loginUser.getId());
				session.setAttribute("userName", loginUser.getName());
				model.addAttribute("loginUser", loginUser);
				return "redirect:/index";
			} else {
				result.rejectValue("pass", "error.password.user", "");
				model.addAllAttributes(result.getModel());
				return "login";
			}

		} catch (EmptyResultDataAccessException e) {
			result.rejectValue("id", "error.id.user", "���̵� �ٸ��ϴ�....");
			model.addAllAttributes(result.getModel());
			return "login";
		}
	}

	@RequestMapping(value = "/editUser", method = RequestMethod.GET)
	public String toUserEditView(Model model,HttpSession session) throws Exception {
		
		String userId = (String) session.getAttribute("userId");
		User loginUser = this.userService.getUser(userId);

		if (userService == null) {
			model.addAttribute("userId", "");
			model.addAttribute("msgCode", "?��록되�??��?? ?��?��?��?��?��?��"); 
			return "login";
		} else {

			

			

			Path filePath = Paths.get("C:/jj/key3.txt");
			String key = Files.readString(filePath);
			AES256Util aes256 = new AES256Util(key);

			String hashBirthday = loginUser.getBirthday();
			String decBrithday = aes256.aesDecode(hashBirthday);

			loginUser.setBirthday(decBrithday);

			model.addAttribute("user", loginUser);
			return "editForm";
		}
	}

	@RequestMapping(value = "/editUser", method = RequestMethod.POST)
	public String onEditSave(@ModelAttribute User user, Model model) throws Exception {

		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		String hashPass = passwordEncoder.encode(user.getPass());
		user.setPass(hashPass);

		

		Path filePath = Paths.get("C:/jj/key3.txt");
		String key = Files.readString(filePath);

		AES256Util aes256 = new AES256Util(key);

		String hashBrithday = aes256.aesEncode(user.getBirthday());
		user.setBirthday(hashBrithday);

		if (this.userService.updateUser(user) != 0) {
			user.setPass("");
			model.addAttribute("msgCode", "?��?��?�� ?��보수?���? ?��?��?��?��?��?��?��");
			model.addAttribute("user", user);
			return "login";
		} else {
			model.addAttribute("msgCode", "?��?��?�� ?��보수?��?�� ?��?��?��???��?��?��");
			return "editForm";
		}
	}

	@RequestMapping(value = "/logout", method = RequestMethod.GET) 

	public String logout(HttpSession session) {
		session.invalidate();
		return "redirect:/login";

	}

	@RequestMapping(value = "/findId", method = RequestMethod.GET) 

	public String toFIndIdForm(Model model) {
		System.out.println("get방식");
		model.addAttribute("user", new User());
		return "findIdForm";

	}

	@RequestMapping(value = "/findId", method = RequestMethod.POST)
	public String findIdSubmit(@Valid User user, BindingResult result, Model model) {

		if (result.hasFieldErrors("name") || result.hasFieldErrors("email")) {
			model.addAllAttributes(result.getModel());
			return "findIdForm";
		}

		try {

			User findUser = this.userService.findId(user.getName(), user.getEmail());
			System.out.println(findUser);
			System.out.println("3");
			if (findUser.getName().equals(user.getName()) && findUser.getEmail().equals(user.getEmail())) {

				System.out.println("1");
				model.addAttribute("findUser", findUser);
				return "findIdSuccess";
			} 
			else {
				System.out.println("2");
				result.rejectValue("email", "error.email.user", "?��메일?�� ?��치하�??��?��?��?��.");
				model.addAllAttributes(result.getModel());
				return "findIdForm";
			}

		} catch (NullPointerException e ) {
			System.out.println("4");
			result.rejectValue("name", "error.name.user", "?���? �? ?��메일?�� 존재?���??��?��?��?��.");
			model.addAllAttributes(result.getModel());
			return "findIdForm";
		}

	}

	@RequestMapping(value = "/findPass", method = RequestMethod.GET) // ?��무런값없?�� ?��?��?��?��?��

	public String toFIndPassForm(Model model) {
		System.out.println("get방식");
		model.addAttribute("user", new User());
		return "findPassForm";

	}

	@RequestMapping(value = "/findPass", method = RequestMethod.POST)

	public String findPassSubmit(@Valid User user, BindingResult result, Model model, RedirectAttributes redirect) {

		System.out.println("post방식");
		if (result.hasFieldErrors("id") || result.hasFieldErrors("email")) {

			model.addAllAttributes(result.getModel());
			return "findPassForm";
		}
		try {

			User findUser = this.userService.findPass(user.getId(), user.getEmail());
			if(findUser.getId().equals(user.getId()) &&findUser.getEmail().equals(user.getEmail())) {
				
				model.addAttribute("findUser", findUser);
				return "updatePassForm";
			}
			else {
			
				result.rejectValue("email", "error.email.user", "?��?��?�� �? ?��메일 ?��보�??��치하�??��?��?��?��.");
				model.addAllAttributes(result.getModel());
				return "findPassForm";
			}
			

		} catch (NullPointerException e) {

			result.rejectValue("id", "error.id.user", "?��?��?�� �? ?��메일 ?��보�??��치하�??��?��?��?��.");
			return "findPassForm";
		}
	}

	@RequestMapping(value = "/updatePass", method = RequestMethod.GET) // ?��무런값없?�� ?��?��?��?��?��

	public String toFIndupdateForm(User user, Model model) {
		System.out.println("get방식");
		model.addAttribute("userId", user.getId());

		model.addAttribute("user", new User());
		return "updatePassForm";

	}

	@RequestMapping(value = "updatePass", method = RequestMethod.POST)
	public String updatePass(@Valid User user, BindingResult result, Model model) throws Exception {

		if (result.hasFieldErrors("id") || result.hasFieldErrors("pass")) {
			model.addAllAttributes(result.getModel());
			return "updatePassForm";
		}
		// passwd ?��?��?�� ?��방향 ?��?��?��

		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		String hashPass = passwordEncoder.encode(user.getPass());
		user.setPass(hashPass);

		if (this.userService.updatePass(user) == 1) {
			model.addAttribute("userId", user.getId());
			return "updatePassSuccess";
		} else {
			result.rejectValue("id", "error.password.user", "?��?��?��?�� �?경에 ?��?��?��???��?��?��. ?��?��?��?��?��주셈...");
			return "updatePassForm";
		}
	}
	
	@RequestMapping(value = "/test", method = RequestMethod.GET) // ?��무런값없?�� ?��?��?��?��?��

	public String test() {
	
		return "test";

	}

}
