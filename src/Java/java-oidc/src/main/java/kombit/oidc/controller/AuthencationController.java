package kombit.oidc.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthencationController {

    @GetMapping("/")
    public String index(Model model) {

        return "login";
    }
}
