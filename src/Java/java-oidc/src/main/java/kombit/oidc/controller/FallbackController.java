package kombit.oidc.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class FallbackController {
    @RequestMapping("/{path:[^\\.]*}")
    public String redirectToHome() {
        return "redirect:/home";
    }
}
