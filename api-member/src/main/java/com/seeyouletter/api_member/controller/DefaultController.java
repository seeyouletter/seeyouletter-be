package com.seeyouletter.api_member.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DefaultController {

    @GetMapping(value = "/authorized")
    public String authorized() {
        return "authorized";
    }

    @GetMapping(value = "/")
    public String index() {
        return "";
    }

}
